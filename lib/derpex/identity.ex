defmodule Derpex.Identity do
  @moduledoc "Persistent, atomically created DERP server identity."

  alias Derpex.Crypto

  @key_length 32
  @file_mode 0o600
  @lock_attempts 100

  @doc "Loads a raw 32-byte private key or atomically creates one with mode 0600."
  @spec load_or_create(Path.t()) :: {:ok, binary()} | {:error, term()}
  def load_or_create(path) when is_binary(path) do
    path = Path.expand(path)

    case read_key(path) do
      {:ok, private_key} ->
        with :ok <- File.chmod(path, @file_mode), do: {:ok, private_key}

      {:error, :enoent} ->
        create_with_lock(path, @lock_attempts)

      {:error, _reason} = error ->
        error
    end
  end

  @doc "Loads or creates an identity and derives its public key."
  @spec load_or_create_keypair(Path.t()) :: {:ok, {binary(), binary()}} | {:error, term()}
  def load_or_create_keypair(path) do
    with {:ok, private_key} <- load_or_create(path),
         {:ok, public_key} <- Crypto.public_key(private_key) do
      {:ok, {public_key, private_key}}
    end
  end

  defp read_key(path) do
    case File.read(path) do
      {:ok, <<private_key::binary-size(@key_length)>>} -> {:ok, private_key}
      {:ok, contents} -> {:error, {:invalid_identity_size, byte_size(contents)}}
      {:error, reason} -> {:error, reason}
    end
  end

  defp create_with_lock(_path, 0), do: {:error, :identity_lock_timeout}

  defp create_with_lock(path, attempts) do
    :ok = File.mkdir_p(Path.dirname(path))
    lock_path = path <> ".lock"

    case open_exclusive(lock_path) do
      {:ok, lock} ->
        try do
          create_while_locked(path)
        after
          :ok = :file.close(lock)
          _result = File.rm(lock_path)
        end

      {:error, :eexist} ->
        retry_after_race(path, attempts)

      {:error, reason} ->
        {:error, {:identity_lock, reason}}
    end
  end

  defp retry_after_race(path, attempts) do
    case read_key(path) do
      {:ok, private_key} ->
        {:ok, private_key}

      {:error, :enoent} ->
        Process.sleep(5)
        create_with_lock(path, attempts - 1)

      {:error, _reason} = error ->
        error
    end
  end

  defp create_while_locked(path) do
    case read_key(path) do
      {:ok, private_key} -> {:ok, private_key}
      {:error, :enoent} -> write_new_identity(path)
      {:error, _reason} = error -> error
    end
  end

  defp write_new_identity(path) do
    private_key = :crypto.strong_rand_bytes(@key_length)
    temporary_path = path <> ".tmp.#{:erlang.unique_integer([:positive, :monotonic])}"

    case open_exclusive(temporary_path) do
      {:ok, file} -> write_and_rename(file, temporary_path, path, private_key)
      {:error, reason} -> {:error, {:identity_temporary_file, reason}}
    end
  end

  defp write_and_rename(file, temporary_path, path, private_key) do
    result =
      with :ok <- File.chmod(temporary_path, @file_mode),
           :ok <- :file.write(file, private_key),
           :ok <- :file.sync(file),
           :ok <- :file.close(file),
           :ok <- File.rename(temporary_path, path),
           :ok <- File.chmod(path, @file_mode) do
        {:ok, private_key}
      end

    case result do
      {:ok, _private_key} = ok ->
        ok

      {:error, reason} ->
        _close_result = :file.close(file)
        _remove_result = File.rm(temporary_path)
        {:error, {:identity_write, reason}}
    end
  end

  defp open_exclusive(path) do
    :file.open(String.to_charlist(path), [:write, :binary, :raw, :exclusive])
  end
end
