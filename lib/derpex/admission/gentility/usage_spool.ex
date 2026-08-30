defmodule Derpex.Admission.Gentility.UsageSpool do
  @moduledoc "A bounded, durable FIFO of idempotent usage-batch records."

  alias Derpex.Admission.Gentility.UsageContract
  alias Derpex.AtomicFile

  @magic "DXUS"
  @version 1
  @max_record_size 8 * 1_024 * 1_024

  @enforce_keys [:path, :max_batches, :max_bytes, :batches, :bytes]
  defstruct @enforce_keys

  @type batch :: {<<_::256>>, binary()}
  @type t :: %__MODULE__{
          path: nil | Path.t(),
          max_batches: pos_integer(),
          max_bytes: pos_integer(),
          batches: [batch()],
          bytes: non_neg_integer()
        }

  @doc "Loads a spool, rejecting corruption and records outside configured bounds."
  @spec load(nil | Path.t(), pos_integer(), pos_integer()) :: {:ok, t()} | {:error, term()}
  def load(path, max_batches, max_bytes) do
    spool = %__MODULE__{
      path: path,
      max_batches: max_batches,
      max_bytes: max_bytes,
      batches: [],
      bytes: 0
    }

    case path && readable(path, max_bytes + max_batches * 36 + 64) do
      nil -> {:ok, spool}
      :missing -> {:ok, spool}
      {:error, _reason} = error -> error
      :ok -> read_and_decode(spool, path)
    end
  end

  defp read_and_decode(spool, path) do
    case File.read(path) do
      {:ok, data} -> decode(spool, data)
      {:error, :enoent} -> {:ok, spool}
      {:error, reason} -> {:error, {:read, reason}}
    end
  end

  # A symlink or an oversized file where the spool belongs is refused before it
  # is read: the spool is this relay's own durable state, not shared input.
  defp readable(path, maximum) do
    case File.lstat(path) do
      {:ok, %File.Stat{type: :regular, size: size}} when size <= maximum -> :ok
      {:ok, %File.Stat{type: :regular}} -> {:error, :spool_too_large}
      {:ok, %File.Stat{}} -> {:error, :spool_not_a_regular_file}
      {:error, :enoent} -> :missing
      {:error, reason} -> {:error, {:read, reason}}
    end
  end

  @doc "Durably appends a batch. Replaying an existing id is a no-op."
  @spec put(t(), batch()) :: {:ok, t()} | {:error, term()}
  def put(%__MODULE__{} = spool, {<<id::binary-size(32)>>, wire} = batch)
      when is_binary(wire) do
    with {:ok, _decoded} <- UsageContract.decode(wire, id) do
      cond do
        Enum.any?(spool.batches, fn {existing, _wire} -> existing == id end) ->
          {:ok, spool}

        length(spool.batches) >= spool.max_batches ->
          {:error, :spool_batch_limit}

        spool.bytes + byte_size(wire) > spool.max_bytes ->
          {:error, :spool_byte_limit}

        true ->
          candidate = %{
            spool
            | batches: spool.batches ++ [batch],
              bytes: spool.bytes + byte_size(wire)
          }

          persist(candidate)
      end
    end
  end

  @doc "Returns the oldest unacknowledged batch."
  @spec peek(t()) :: nil | batch()
  def peek(%__MODULE__{batches: []}), do: nil
  def peek(%__MODULE__{batches: [batch | _rest]}), do: batch

  @doc "Durably acknowledges the oldest batch if its id matches."
  @spec ack(t(), <<_::256>>) :: {:ok, t()} | {:error, term()}
  def ack(%__MODULE__{batches: [{id, wire} | rest]} = spool, id) do
    candidate = %{spool | batches: rest, bytes: spool.bytes - byte_size(wire)}
    persist(candidate)
  end

  def ack(%__MODULE__{}, _id), do: {:error, :batch_not_at_head}

  @doc "Returns bounded spool counters without attribution labels."
  @spec stats(t()) :: %{batches: non_neg_integer(), bytes: non_neg_integer()}
  def stats(spool), do: %{batches: length(spool.batches), bytes: spool.bytes}

  defp decode(spool, <<@magic, @version::16, count::32, rest::binary>>)
       when count <= spool.max_batches do
    with {:ok, batches, ""} <- take_batches(rest, count, []),
         true <- unique_ids?(batches),
         bytes = Enum.sum(Enum.map(batches, fn {_id, wire} -> byte_size(wire) end)),
         true <- bytes <= spool.max_bytes do
      {:ok, %{spool | batches: batches, bytes: bytes}}
    else
      false -> {:error, :invalid_spool_bounds}
      {:error, _reason} = error -> error
    end
  end

  defp decode(spool, <<@magic, @version::16, _count::32, _rest::binary>>),
    do: {:error, {:spool_batch_limit, spool.max_batches}}

  defp decode(_spool, <<@magic, version::16, _rest::binary>>),
    do: {:error, {:unsupported_spool_version, version}}

  defp decode(_spool, _data), do: {:error, :invalid_spool}

  defp take_batches(rest, 0, batches), do: {:ok, Enum.reverse(batches), rest}

  defp take_batches(<<id::binary-size(32), size::32, rest::binary>>, count, batches)
       when size <= @max_record_size and byte_size(rest) >= size do
    <<wire::binary-size(^size), rest::binary>> = rest

    with {:ok, _batch} <- UsageContract.decode(wire, id) do
      take_batches(rest, count - 1, [{id, wire} | batches])
    end
  end

  defp take_batches(_data, _count, _batches), do: {:error, :invalid_spool_record}

  defp unique_ids?(batches) do
    batches |> Enum.map(&elem(&1, 0)) |> MapSet.new() |> MapSet.size() == length(batches)
  end

  defp persist(spool) do
    data = [
      @magic,
      <<@version::16, length(spool.batches)::32>>,
      Enum.map(spool.batches, fn {id, wire} -> [id, <<byte_size(wire)::32>>, wire] end)
    ]

    case AtomicFile.write_or_noop(spool.path, data) do
      :ok -> {:ok, spool}
      {:error, reason} -> {:error, {:persist, reason}}
    end
  end
end
