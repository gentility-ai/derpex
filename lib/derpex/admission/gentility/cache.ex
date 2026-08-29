defmodule Derpex.Admission.Gentility.Cache do
  @moduledoc false

  alias Derpex.Admission.Gentility.Contract

  @magic "DXAC"
  @journal_magic "DXAJ"
  @version 1
  @max_record_size 4_096

  @spec load(nil | Path.t(), non_neg_integer(), non_neg_integer()) ::
          {:ok, {[binary()], [binary()]}} | {:error, term()}
  def load(nil, _max_leases, _max_revocations), do: {:ok, {[], []}}

  def load(path, max_leases, max_revocations) when is_binary(path) do
    with {:ok, {leases, revocations}} <- load_snapshot(path, max_leases, max_revocations) do
      {:ok, {leases, revocations ++ load_journal(path, max_revocations)}}
    end
  end

  @doc "Returns the path of the revocation journal beside a snapshot."
  @spec journal_path(Path.t()) :: Path.t()
  def journal_path(path), do: path <> ".revocations"

  @doc """
  Opens the revocation journal for appending, creating it if needed.

  Revocations are the one record whose durability bounds a security window, so
  they are appended and flushed on their own rather than waiting for the next
  full snapshot. That keeps the cost of making a revocation durable independent
  of how many leases are cached.
  """
  @spec open_journal(Path.t()) :: {:ok, :file.io_device()} | {:error, term()}
  def open_journal(path) do
    journal = journal_path(path)

    with {:ok, io} <- :file.open(journal, [:append, :raw, :binary]),
         :ok <- write_journal_header(journal, io) do
      {:ok, io}
    end
  end

  @doc "Appends records to an open journal and flushes them to disk."
  @spec append_journal(:file.io_device(), [binary()]) :: :ok | {:error, term()}
  def append_journal(io, wires) do
    with :ok <- :file.write(io, records(wires)) do
      :file.sync(io)
    end
  end

  @doc "Replaces the journal with exactly the records given."
  @spec compact_journal(Path.t(), [binary()]) :: {:ok, :file.io_device()} | {:error, term()}
  def compact_journal(path, wires) do
    journal = journal_path(path)

    data = [@journal_magic, <<@version::16>>, records(wires)]

    with :ok <- Derpex.AtomicFile.write(journal, data) do
      :file.open(journal, [:append, :raw, :binary])
    end
  end

  @doc "Closes an open journal."
  @spec close_journal(nil | :file.io_device()) :: :ok
  def close_journal(nil), do: :ok
  def close_journal(io), do: :file.close(io)

  defp write_journal_header(journal, io) do
    case File.stat(journal) do
      {:ok, %File.Stat{size: 0}} -> :file.write(io, [@journal_magic, <<@version::16>>])
      _existing -> :ok
    end
  end

  # A journal is read best-effort: it is a tail of records appended one at a
  # time, so a torn final record after a crash costs that record and nothing
  # else. Every record is verified before it is trusted.
  defp load_journal(path, max_revocations) do
    journal = journal_path(path)
    maximum = max_revocations * (4 + @max_record_size) + 64

    with :ok <- readable(journal, maximum),
         {:ok, <<@journal_magic, @version::16, rest::binary>>} <- File.read(journal) do
      journal_records(rest, max_revocations, [])
    else
      _unreadable -> []
    end
  end

  defp journal_records(_data, 0, records), do: Enum.reverse(records)

  defp journal_records(<<size::32, rest::binary>>, remaining, records)
       when size <= @max_record_size and byte_size(rest) >= size do
    <<record::binary-size(^size), rest::binary>> = rest
    journal_records(rest, remaining - 1, [record | records])
  end

  defp journal_records(_data, _remaining, records), do: Enum.reverse(records)

  defp load_snapshot(path, max_leases, max_revocations) do
    case readable(path, max_bytes(max_leases, max_revocations)) do
      :ok -> read_and_decode(path, max_leases, max_revocations)
      :missing -> {:ok, {[], []}}
      {:error, _reason} = error -> error
    end
  end

  defp read_and_decode(path, max_leases, max_revocations) do
    case File.read(path) do
      {:ok, data} -> decode(data, max_leases, max_revocations)
      {:error, :enoent} -> {:ok, {[], []}}
      {:error, reason} -> {:error, {:read, reason}}
    end
  end

  # The cache is written by this relay and read back with the same privileges.
  # A symlink or an oversized file at that path is a sign the path is not what
  # it should be, and is refused before a byte is read into memory.
  defp readable(path, maximum) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= maximum -> :ok
      {:ok, %File.Stat{type: :regular}} -> {:error, :cache_too_large}
      {:ok, %File.Stat{}} -> {:error, :cache_not_a_regular_file}
      {:error, :enoent} -> :missing
      {:error, reason} -> {:error, {:read, reason}}
    end
  end

  defp max_bytes(max_leases, max_revocations) do
    (max_leases + max_revocations) * (4 + @max_record_size) + 64
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
