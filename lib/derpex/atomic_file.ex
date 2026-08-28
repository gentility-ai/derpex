defmodule Derpex.AtomicFile do
  @moduledoc false

  @file_mode 0o600

  @spec write(Path.t(), iodata()) :: :ok | {:error, term()}
  def write(path, data) when is_binary(path) do
    path = Path.expand(path)

    with :ok <- File.mkdir_p(Path.dirname(path)),
         temporary = path <> ".tmp.#{:erlang.unique_integer([:positive, :monotonic])}",
         {:ok, file} <-
           :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
      write_and_rename(file, temporary, path, data)
    else
      {:error, reason} -> {:error, {:open, reason}}
    end
  end

  @spec write_or_noop(nil | Path.t(), iodata()) :: :ok | {:error, term()}
  def write_or_noop(nil, _data), do: :ok
  def write_or_noop(path, data), do: write(path, data)

  defp write_and_rename(file, temporary, path, data) do
    result =
      with :ok <- File.chmod(temporary, @file_mode),
           :ok <- :file.write(file, data),
           :ok <- :file.sync(file),
           :ok <- :file.close(file),
           :ok <- File.rename(temporary, path) do
        File.chmod(path, @file_mode)
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
end
