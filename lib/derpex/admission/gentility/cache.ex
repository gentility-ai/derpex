defmodule Derpex.Admission.Gentility.Cache do
  @moduledoc false

  @magic "DXAC"
  @version 1
  @file_mode 0o600
  @max_record_size 4_096

  @spec load(nil | Path.t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, {[binary()], [binary()]}} | {:error, term()}
  def load(nil, _max_leases, _max_revocations), do: {:ok, {[], []}}

  def load(path, max_leases, max_revocations) when is_binary(path) do
    case File.read(path) do
      {:ok, data} -> decode(data, max_leases, max_revocations)
      {:error, :enoent} -> {:ok, {[], []}}
      {:error, reason} -> {:error, {:read, reason}}
    end
  end

  @spec store(nil | Path.t(), [binary()], [binary()]) :: :ok | {:error, term()}
  def store(nil, _leases, _revocations), do: :ok

  def store(path, leases, revocations) when is_binary(path) do
    data = [
      @magic,
      <<@version::16, length(leases)::32>>,
      records(leases),
      <<length(revocations)::32>>,
      records(revocations)
    ]

    write_atomic(Path.expand(path), data)
  end

  defp decode(
         <<@magic, @version::16, lease_count::32, rest::binary>>,
         max_leases,
         max_revocations
       )
       when lease_count <= max_leases do
    with {:ok, leases, <<revocation_count::32, rest::binary>>} <- take_records(rest, lease_count),
         true <- revocation_count <= max_revocations,
         {:ok, revocations, ""} <- take_records(rest, revocation_count) do
      {:ok, {leases, revocations}}
    else
      false -> {:error, :too_many_revocations}
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_cache}
    end
  end

  defp decode(
         <<@magic, @version::16, _lease_count::32, _rest::binary>>,
         _max_leases,
         _max_revocations
       ),
       do: {:error, :too_many_leases}

  defp decode(<<@magic, version::16, _rest::binary>>, _max_leases, _max_revocations),
    do: {:error, {:unsupported_cache_version, version}}

  defp decode(_data, _max_leases, _max_revocations), do: {:error, :invalid_cache}

  defp take_records(rest, 0), do: {:ok, [], rest}

  defp take_records(<<size::32, rest::binary>>, count)
       when size <= @max_record_size and byte_size(rest) >= size do
    <<record::binary-size(^size), rest::binary>> = rest

    with {:ok, records, rest} <- take_records(rest, count - 1) do
      {:ok, [record | records], rest}
    end
  end

  defp take_records(_data, _count), do: {:error, :invalid_cache_record}

  defp records(records) do
    Enum.map(records, fn record -> [<<byte_size(record)::32>>, record] end)
  end

  defp write_atomic(path, data) do
    with :ok <- File.mkdir_p(Path.dirname(path)),
         temporary = path <> ".tmp.#{:erlang.unique_integer([:positive, :monotonic])}",
         {:ok, file} <-
           :file.open(String.to_charlist(temporary), [:write, :binary, :raw, :exclusive]) do
      write_and_rename(file, temporary, path, data)
    else
      {:error, reason} -> {:error, {:open, reason}}
    end
  end

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
