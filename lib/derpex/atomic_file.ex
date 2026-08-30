defmodule Derpex.AtomicFile do
  @moduledoc """
  Atomic, private-by-construction writes for secret material.

  A write lands in a uniquely named temporary file opened `:exclusive`, chmod-ed
  before a single byte is written, fsynced, closed and finally renamed over the
  destination. The rename inherits the temporary file's mode, so the destination
  is never observable with a permissive one.

  Missing parent directories are created `0700`. Directories that already exist
  are left exactly as the operator configured them: a relay may legitimately keep
  its keys in a directory it shares with something else, and silently tightening
  another owner's directory is not this module's call. In a pre-existing
  world-readable directory the temporary file is therefore observable, at its
  default mode, for the few microseconds between `open` and `chmod` — the BEAM's
  file driver has no `open(2)` mode argument, so that window cannot be closed
  from Elixir. Directories this module creates have no such window.

  `sync_directory/1` is a no-op on every current OTP release: durability of the
  rename itself would need an fsync on a directory handle, and the BEAM's file
  driver refuses to open a directory (`:eisdir`). The payload is always fsynced
  before the rename, so a crash can never expose a partially written key — only,
  on an unclean host crash, the pre-rename name.
  """

  @default_mode 0o600
  @directory_mode 0o700
  @temporary_attempts 8

  @type option :: {:mode, non_neg_integer()} | {:directory_mode, non_neg_integer()}

  @doc """
  Creates `directory` and any missing ancestors with `mode` (`0700` by default).

  Directories that already exist keep their current mode.
  """
  @spec ensure_directory(Path.t(), non_neg_integer()) :: :ok | {:error, term()}
  def ensure_directory(directory, mode \\ @directory_mode) when is_binary(directory) do
    directory
    |> Path.expand()
    |> ancestors()
    |> Enum.reduce_while(:ok, fn path, :ok -> create_directory(path, mode) end)
  end

  @spec write(Path.t(), iodata(), [option()]) :: :ok | {:error, term()}
  def write(path, data, options \\ []) when is_binary(path) and is_list(options) do
    path = Path.expand(path)
    directory = Path.dirname(path)
    mode = Keyword.get(options, :mode, @default_mode)
    directory_mode = Keyword.get(options, :directory_mode, @directory_mode)

    case ensure_directory(directory, directory_mode) do
      :ok -> create_and_write(path, directory, data, mode, @temporary_attempts)
      {:error, reason} -> {:error, {:mkdir, reason}}
    end
  end

  @spec write_or_noop(nil | Path.t(), iodata(), [option()]) :: :ok | {:error, term()}
  def write_or_noop(path, data, options \\ [])
  def write_or_noop(nil, _data, _options), do: :ok
  def write_or_noop(path, data, options), do: write(path, data, options)

  defp ancestors(directory) do
    [_root | components] = Path.split(directory)
    Enum.scan(components, "/", &Path.join(&2, &1))
  end

  defp create_directory(path, mode) do
    case File.mkdir(path) do
      :ok -> chmod_created_directory(path, mode)
      {:error, :eexist} -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp chmod_created_directory(path, mode) do
    case File.chmod(path, mode) do
      :ok -> {:cont, :ok}
      {:error, reason} -> {:halt, {:error, reason}}
    end
  end

  defp create_and_write(_path, _directory, _data, _mode, 0), do: {:error, {:open, :eexist}}

  defp create_and_write(path, directory, data, mode, attempts) do
    temporary = temporary_path(path)

    case :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
      {:ok, file} ->
        write_and_rename(file, temporary, path, data, mode, directory)

      {:error, :eexist} ->
        create_and_write(path, directory, data, mode, attempts - 1)

      {:error, reason} ->
        {:error, {:open, reason}}
    end
  end

  # Unpredictable so a hostile co-tenant in a shared directory cannot pre-create
  # the name we are about to use, and unique so concurrent writers never collide.
  defp temporary_path(path) do
    unique = Integer.to_string(:erlang.unique_integer([:positive, :monotonic]))
    random = 8 |> :crypto.strong_rand_bytes() |> Base.url_encode64(padding: false)
    path <> ".tmp." <> unique <> "." <> random
  end

  defp write_and_rename(file, temporary, path, data, mode, directory) do
    result =
      with :ok <- File.chmod(temporary, mode),
           :ok <- :file.write(file, data),
           :ok <- :file.sync(file),
           :ok <- :file.close(file),
           :ok <- File.rename(temporary, path) do
        sync_directory(directory)
      end

    case result do
      :ok ->
        :ok

      {:error, reason} ->
        _close_result = :file.close(file)
        _remove_result = File.rm(temporary)
        {:error, {:write, reason}}
    end
  end

  defp sync_directory(directory) do
    case :file.open(String.to_charlist(directory), [:read, :raw]) do
      {:ok, handle} ->
        _sync_result = :file.sync(handle)
        :file.close(handle)

      {:error, _unsupported} ->
        :ok
    end
  end
end
