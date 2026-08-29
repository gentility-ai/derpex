defmodule Derpex.AtomicFile do
  @moduledoc """
  Atomic, private-by-construction writes for secret material.

  Every write creates the parent directory `0700` *first*, then lands the payload
  in a uniquely named temporary file opened `:exclusive` and chmod-ed before a
  single byte is written. The temporary file is fsynced, closed, renamed over the
  destination and chmod-ed again. Because the directory is `0700` before the
  temporary file exists, no other user can observe the file in its default mode.
  """

  @default_mode 0o600
  @directory_mode 0o700

  @type option :: {:mode, non_neg_integer()} | {:directory_mode, non_neg_integer()}

  @doc "Ensures `directory` exists with a private (`0700` by default) mode."
  @spec ensure_directory(Path.t(), non_neg_integer()) :: :ok | {:error, term()}
  def ensure_directory(directory, mode \\ @directory_mode) when is_binary(directory) do
    with :ok <- File.mkdir_p(directory), do: File.chmod(directory, mode)
  end

  @spec write(Path.t(), iodata(), [option()]) :: :ok | {:error, term()}
  def write(path, data, options \\ []) when is_binary(path) and is_list(options) do
    path = Path.expand(path)
    directory = Path.dirname(path)
    mode = Keyword.get(options, :mode, @default_mode)
    directory_mode = Keyword.get(options, :directory_mode, @directory_mode)

    case ensure_directory(directory, directory_mode) do
      :ok -> create_and_write(path, directory, data, mode)
      {:error, reason} -> {:error, {:open, reason}}
    end
  end

  @spec write_or_noop(nil | Path.t(), iodata(), [option()]) :: :ok | {:error, term()}
  def write_or_noop(path, data, options \\ [])
  def write_or_noop(nil, _data, _options), do: :ok
  def write_or_noop(path, data, options), do: write(path, data, options)

  defp create_and_write(path, directory, data, mode) do
    temporary = path <> ".tmp.#{:erlang.unique_integer([:positive, :monotonic])}"

    case :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
      {:ok, file} -> write_and_rename(file, temporary, path, data, mode, directory)
      {:error, reason} -> {:error, {:open, reason}}
    end
  end

  defp write_and_rename(file, temporary, path, data, mode, directory) do
    result =
      with :ok <- File.chmod(temporary, mode),
           :ok <- :file.write(file, data),
           :ok <- :file.sync(file),
           :ok <- :file.close(file),
           :ok <- File.rename(temporary, path),
           :ok <- File.chmod(path, mode) do
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

  # POSIX durability additionally requires fsyncing the directory that holds the
  # renamed entry. The BEAM's file driver refuses to open a directory handle
  # (`:eisdir` on every current platform), so this is best effort: it syncs
  # wherever the runtime permits it and degrades to a no-op otherwise. The
  # payload itself is always fsynced before the rename, so a crash can never
  # expose a partially written key — only, on an unclean host crash, the
  # pre-rename name.
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
