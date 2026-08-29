defmodule Derpex.Admission.Gentility.UsageContract do
  @moduledoc "Canonical, content-addressed Gentility usage-batch contract v1."

  alias Derpex.Admission.Gentility.UsageBatch
  alias Derpex.Admission.Gentility.UsageBatch.Entry

  @magic "DXUB"
  @version 1
  @max_identity_size 512
  @max_owner_kind_size 64
  @max_entries 10_000
  @max_wire_size 8 * 1_024 * 1_024
  @u32_max 0xFFFF_FFFF
  @u64_max 0xFFFF_FFFF_FFFF_FFFF

  @doc "Returns the largest number of sender-attribution entries one batch may carry."
  @spec max_entries() :: pos_integer()
  def max_entries, do: @max_entries

  @doc "Encodes a sorted canonical batch and returns its SHA-256 idempotency key."
  @spec encode(UsageBatch.t()) :: {:ok, {<<_::256>>, binary()}} | {:error, term()}
  def encode(%UsageBatch{} = batch) do
    with :ok <- validate_batch(batch),
         entries = Enum.sort_by(batch.entries, &entry_identity/1),
         {:ok, instance_id} <- text(batch.instance_id, @max_identity_size),
         {:ok, encoded_entries} <- encode_entries(entries) do
      wire =
        IO.iodata_to_binary([
          @magic,
          <<
            @version::16,
            instance_id::binary,
            batch.region_id::32,
            batch.window_start_ms::64,
            batch.window_end_ms::64,
            length(entries)::32
          >>,
          encoded_entries
        ])

      if byte_size(wire) <= @max_wire_size,
        do: {:ok, {:crypto.hash(:sha256, wire), wire}},
        else: {:error, :usage_batch_too_large}
    end
  end

  @doc "Validates a content-addressed record and decodes contract v1."
  @spec decode(binary(), <<_::256>>) :: {:ok, UsageBatch.t()} | {:error, term()}
  def decode(wire, <<id::binary-size(32)>>) when is_binary(wire) do
    with true <- byte_size(wire) <= @max_wire_size,
         true <- :crypto.hash(:sha256, wire) == id,
         {:ok, batch} <- decode_wire(wire) do
      {:ok, batch}
    else
      false -> {:error, :invalid_usage_batch}
      {:error, _reason} = error -> error
    end
  end

  defp decode_wire(<<@magic, @version::16, rest::binary>>) do
    with {:ok, instance_id, rest} <- take_text(rest, @max_identity_size),
         <<region_id::32, window_start_ms::64, window_end_ms::64, count::32, rest::binary>> <-
           rest,
         true <- count <= @max_entries,
         {:ok, entries, ""} <- take_entries(rest, count) do
      batch = %UsageBatch{
        instance_id: instance_id,
        region_id: region_id,
        window_start_ms: window_start_ms,
        window_end_ms: window_end_ms,
        entries: entries
      }

      with :ok <- validate_batch(batch), do: {:ok, batch}
    else
      false -> {:error, :too_many_usage_entries}
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_usage_batch_encoding}
    end
  end

  defp decode_wire(<<@magic, version::16, _rest::binary>>),
    do: {:error, {:unsupported_version, version}}

  defp decode_wire(_wire), do: {:error, :invalid_usage_batch_encoding}

  defp encode_entries(entries) do
    Enum.reduce_while(entries, {:ok, []}, fn entry, {:ok, encoded} ->
      case encode_entry(entry) do
        {:ok, wire} -> {:cont, {:ok, [encoded, wire]}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp encode_entry(entry) do
    with :ok <- validate_entry(entry),
         {:ok, node_id} <- text(entry.node_id, @max_identity_size),
         {:ok, organization_id} <- text(entry.organization_id, @max_identity_size),
         {:ok, owner_kind} <- text(entry.owner_kind, @max_owner_kind_size),
         {:ok, deployment_id} <- text(entry.deployment_id, @max_identity_size) do
      {:ok,
       <<
         node_id::binary,
         organization_id::binary,
         owner_kind::binary,
         deployment_id::binary,
         entry.accepted_packets::64,
         entry.accepted_bytes::64,
         entry.dropped_packets::64,
         entry.dropped_bytes::64
       >>}
    end
  end

  defp take_entries(rest, 0), do: {:ok, [], rest}

  defp take_entries(rest, count) do
    with {:ok, entry, rest} <- take_entry(rest),
         {:ok, entries, rest} <- take_entries(rest, count - 1) do
      {:ok, [entry | entries], rest}
    end
  end

  defp take_entry(rest) do
    with {:ok, node_id, rest} <- take_text(rest, @max_identity_size),
         {:ok, organization_id, rest} <- take_text(rest, @max_identity_size),
         {:ok, owner_kind, rest} <- take_text(rest, @max_owner_kind_size),
         {:ok, deployment_id, rest} <- take_text(rest, @max_identity_size),
         <<
           accepted_packets::64,
           accepted_bytes::64,
           dropped_packets::64,
           dropped_bytes::64,
           rest::binary
         >> <- rest do
      {:ok,
       %Entry{
         node_id: node_id,
         organization_id: organization_id,
         owner_kind: owner_kind,
         deployment_id: deployment_id,
         accepted_packets: accepted_packets,
         accepted_bytes: accepted_bytes,
         dropped_packets: dropped_packets,
         dropped_bytes: dropped_bytes
       }, rest}
    else
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_usage_entry_encoding}
    end
  end

  defp validate_batch(batch) do
    with :ok <- utf8(batch.instance_id, @max_identity_size, :instance_id),
         :ok <- uint(batch.region_id, @u32_max, :region_id),
         :ok <- uint(batch.window_start_ms, @u64_max, :window_start_ms),
         :ok <- uint(batch.window_end_ms, @u64_max, :window_end_ms),
         true <- batch.window_end_ms > batch.window_start_ms,
         true <- is_list(batch.entries) and length(batch.entries) in 1..@max_entries,
         true <- unique_entries?(batch.entries) do
      :ok
    else
      false -> {:error, :invalid_usage_batch}
      {:error, _reason} = error -> error
    end
  end

  defp validate_entry(%Entry{} = entry) do
    with :ok <- utf8(entry.node_id, @max_identity_size, :node_id),
         :ok <- utf8(entry.organization_id, @max_identity_size, :organization_id),
         :ok <- utf8(entry.owner_kind, @max_owner_kind_size, :owner_kind),
         :ok <- utf8(entry.deployment_id, @max_identity_size, :deployment_id),
         :ok <- uint(entry.accepted_packets, @u64_max, :accepted_packets),
         :ok <- uint(entry.accepted_bytes, @u64_max, :accepted_bytes),
         :ok <- uint(entry.dropped_packets, @u64_max, :dropped_packets) do
      uint(entry.dropped_bytes, @u64_max, :dropped_bytes)
    end
  end

  defp entry_identity(entry) do
    {entry.organization_id, entry.node_id, entry.owner_kind, entry.deployment_id}
  end

  defp unique_entries?(entries) do
    entries |> Enum.map(&entry_identity/1) |> MapSet.new() |> MapSet.size() == length(entries)
  end

  defp text(value, maximum) do
    with :ok <- utf8(value, maximum, :text), do: {:ok, <<byte_size(value)::16, value::binary>>}
  end

  defp take_text(<<size::16, rest::binary>>, maximum) when size > 0 and size <= maximum do
    case rest do
      <<value::binary-size(^size), rest::binary>> ->
        if String.valid?(value), do: {:ok, value, rest}, else: {:error, :invalid_utf8}

      _short ->
        {:error, :truncated_text}
    end
  end

  defp take_text(_data, _maximum), do: {:error, :invalid_text}

  defp utf8(value, maximum, _field)
       when is_binary(value) and byte_size(value) > 0 and byte_size(value) <= maximum do
    if String.valid?(value), do: :ok, else: {:error, :invalid_utf8}
  end

  defp utf8(_value, _maximum, field), do: {:error, {:invalid_field, field}}

  defp uint(value, maximum, _field)
       when is_integer(value) and value >= 0 and value <= maximum,
       do: :ok

  defp uint(_value, _maximum, field), do: {:error, {:invalid_field, field}}
end
