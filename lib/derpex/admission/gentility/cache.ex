defmodule Derpex.Admission.Gentility.Cache do
  @moduledoc false

  alias Derpex.Admission.Gentility.Contract

  @magic "DXAC"
  @version 1
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
    write(path, encode(leases, revocations))
  end

  @doc "Encodes the durable snapshot. Callers build this before handing off the write."
  @spec encode([binary()], [binary()]) :: iodata()
  def encode(leases, revocations) do
    [
      @magic,
      <<@version::16, length(leases)::32>>,
      records(leases),
      <<length(revocations)::32>>,
      records(revocations)
    ]
  end

  @doc "Writes an encoded snapshot atomically."
  @spec write(Path.t(), iodata()) :: :ok | {:error, term()}
  def write(path, data) when is_binary(path), do: Derpex.AtomicFile.write(path, data)

  defp decode(
         <<@magic, @version::16, lease_count::32, rest::binary>>,
         max_leases,
         max_revocations
       )
       when lease_count <= max_leases do
    with {:ok, leases, <<revocation_count::32, rest::binary>>} <- take_records(rest, lease_count),
         true <- revocation_count <= max_revocations,
         {:ok, revocations, ""} <- take_records(rest, revocation_count) do
      {:ok, {dedupe_leases(leases), revocations}}
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

  # A file written before this rule, or by a future writer, may carry two records
  # for one node key. Loading both would leave the cache with one entry and two
  # expiry-index keys, so the later expiry wins here and the other is discarded.
  defp dedupe_leases(wires) do
    wires
    |> Enum.reduce(%{}, &keep_later_lease/2)
    |> Enum.sort_by(fn {node_key, _held} -> node_key end)
    |> Enum.map(fn {_node_key, {_expires_at_ms, wire}} -> wire end)
  end

  defp keep_later_lease(wire, leases) do
    case Contract.decode_lease(wire) do
      {:ok, lease} ->
        case leases[lease.node_key] do
          {expires_at_ms, _wire} when expires_at_ms >= lease.expires_at_ms ->
            leases

          _older_or_missing ->
            Map.put(leases, lease.node_key, {lease.expires_at_ms, wire})
        end

      {:error, _undecodable} ->
        leases
    end
  end

  defp records(records) do
    Enum.map(records, fn record -> [<<byte_size(record)::32>>, record] end)
  end
end
