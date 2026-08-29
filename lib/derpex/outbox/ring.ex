defmodule Derpex.Outbox.Ring do
  @moduledoc """
  Fixed-capacity, non-blocking packet storage for one writer.

  A producer that meets a held lock retries inside a bounded wall-clock budget
  and then tail-drops, counting the drop. It keeps no shared waiting state, so
  it can be killed mid-attempt without wedging anyone. A full ring replaces its
  oldest item. Packet references live only in the preallocated ETS slots. The
  writer receives at most one coalesced atom wakeup and pulls values directly
  from the ring.

  Only the lock, the journal, the slots, and the atomics are touched inside the
  critical section. Clock reads and drop metrics happen outside it.

  A tiny ETS journal makes interrupted mutations recoverable by the next
  producer or consumer. It contains indices and counters, never the packet.
  """

  alias Derpex.Clock
  alias Derpex.Metrics
  alias Derpex.Outbox.Lock

  @head 1
  @size 2
  @wake_pending 3
  @head_drops 4
  @tail_drops 5
  @closed 6

  defstruct [
    :table,
    :state,
    :capacity,
    :full_policy,
    :notifier,
    :wake_message,
    :test_hook,
    :metrics,
    :metric_kind
  ]

  @opaque t :: %__MODULE__{
            table: :ets.tid(),
            state: :atomics.atomics_ref(),
            capacity: pos_integer(),
            full_policy: :replace | :reject,
            notifier: pid(),
            wake_message: atom(),
            test_hook: nil | (atom() -> term()),
            metrics: Metrics.handle() | nil,
            metric_kind: :disco | :other | :forward | nil
          }

  @type enqueue_result :: {:ok, :wake | :coalesced | :replaced} | {:dropped, atom()}

  @doc "Creates a ring owned by the calling process."
  @spec new(pos_integer(), keyword()) :: t()
  def new(capacity, options \\ []) when is_integer(capacity) and capacity > 0 do
    # Every read and write happens under the ring lock, so decorated
    # concurrency options would only buy per-scheduler structures that cost
    # tens of kilobytes per connection and are never contended.
    table =
      :ets.new(__MODULE__, [
        :set,
        :public,
        read_concurrency: false,
        write_concurrency: false
      ])

    true = :ets.insert(table, for(index <- 0..(capacity - 1), do: {index, 0, 0, nil}))

    %__MODULE__{
      table: table,
      state: :atomics.new(6, signed: false),
      capacity: capacity,
      full_policy: Keyword.get(options, :full, :replace),
      notifier: Keyword.get(options, :notifier, self()),
      wake_message: Keyword.get(options, :wake_message, :derpex_outbox_ready),
      test_hook: Keyword.get(options, :test_hook),
      metrics: Keyword.get(options, :metrics),
      metric_kind: Keyword.get(options, :metric_kind)
    }
  end

  @doc """
  Publishes an item. Full rings replace the oldest item.

  A held lock is retried inside a bounded wall-clock budget. `wait: false`
  keeps the retries free of naps, for callers such as the router that must
  never sleep on behalf of one destination.
  """
  @spec enqueue(t(), term(), keyword()) :: enqueue_result()
  def enqueue(%__MODULE__{} = ring, item, options \\ []) do
    if atomic_get(ring, @closed) == 1 do
      record_drop(ring, item, :gone_disconnected)
      {:dropped, :closed}
    else
      enqueue_open(ring, item, Keyword.get(options, :wait, true))
    end
  end

  defp enqueue_open(ring, item, wait?) do
    # Reading the clock costs more than the critical section itself, so the
    # queue timestamp is taken before the lock rather than inside it.
    enqueued_at = Clock.monotonic_time(:microsecond)

    case Lock.acquire_producer(ring.table, wait?, ring.metrics) do
      {:ok, lock_token} ->
        {result, pending_drop} =
          try do
            recover(ring)
            enqueue_locked(ring, item, enqueued_at, lock_token)
          after
            Lock.release(ring.table, lock_token)
          end

        record_pending_drop(ring, pending_drop)
        result

      :busy ->
        :atomics.add_get(ring.state, @tail_drops, 1)
        record_drop(ring, item, :queue_tail)
        {:dropped, :contention}
    end
  end

  defp record_pending_drop(_ring, nil), do: :ok

  defp record_pending_drop(ring, {item, reason}), do: record_drop(ring, item, reason)

  # Go records a head-dropped packet's residence time in the same moving average
  # as a delivered one, so a queue that is dropping still reports how long it is
  # making packets wait.
  defp record_pending_drop(ring, {item, reason, enqueued_at}) do
    :ok = record_drop(ring, item, reason)

    Metrics.observe_queue_duration(
      ring.metrics,
      max(Clock.monotonic_time(:microsecond) - enqueued_at, 0)
    )
  end

  @doc "Takes the next item for the single writer."
  @spec take(t()) :: {:ok, term()} | :empty | :closed | :busy
  def take(%__MODULE__{} = ring) do
    case take_with_age(ring) do
      {:ok, item, _age_microseconds} -> {:ok, item}
      other -> other
    end
  end

  @doc "Takes the next item with its non-negative queue residence time."
  @spec take_with_age(t()) :: {:ok, term(), non_neg_integer()} | :empty | :closed | :busy
  def take_with_age(%__MODULE__{} = ring) do
    case Lock.acquire_consumer(ring.table) do
      {:ok, lock_token} ->
        taken =
          try do
            recover(ring)
            take_locked(ring, lock_token)
          after
            Lock.release(ring.table, lock_token)
          end

        with {:ok, item, enqueued_at} <- taken do
          {:ok, item, max(Clock.monotonic_time(:microsecond) - enqueued_at, 0)}
        end

      :busy ->
        :busy
    end
  end

  @doc "Returns the ring table's memory footprint in machine words."
  @spec memory_words(t()) :: non_neg_integer()
  def memory_words(%__MODULE__{} = ring), do: :ets.info(ring.table, :memory)

  @doc "Closes the ring and releases every retained item. Idempotent."
  @spec close(t()) :: :ok | :busy
  def close(%__MODULE__{} = ring) do
    case Lock.acquire(ring.table) do
      {:ok, lock_token} ->
        try do
          recover(ring)
          record_retained_drops(ring)
          :atomics.put(ring.state, @closed, 1)
          clear_slots(ring)
          :atomics.put(ring.state, @size, 0)
          :atomics.put(ring.state, @wake_pending, 0)
          :ets.delete(ring.table, :journal)
          :ok
        after
          Lock.release(ring.table, lock_token)
        end

      :busy ->
        :busy
    end
  end

  @doc "Returns consistent queue and drop counters, or `:busy` under mutation."
  @spec stats(t()) :: map() | :busy
  def stats(%__MODULE__{} = ring) do
    case Lock.acquire(ring.table) do
      {:ok, lock_token} ->
        try do
          recover(ring)

          %{
            capacity: ring.capacity,
            full_policy: ring.full_policy,
            size: atomic_get(ring, @size),
            wake_pending: atomic_get(ring, @wake_pending) == 1,
            head_drops: atomic_get(ring, @head_drops),
            tail_drops: atomic_get(ring, @tail_drops),
            closed: atomic_get(ring, @closed) == 1,
            packet_slots: packet_slot_count(ring)
          }
        after
          Lock.release(ring.table, lock_token)
        end

      :busy ->
        :busy
    end
  end

  @doc """
  Closes the ring and drops its ETS table. Idempotent.

  A ring whose owner outlives it — the mesh client rebuilds one per reconnect —
  must be deleted rather than merely closed, because the table is reclaimed
  only when its owner dies. Call it from the process that owns the table.

  The closed flag is raised before `close/1` rather than by it: `close/1`
  reports `:busy` and leaves the flag alone when a producer holds the lock, and
  the table is dropped either way. Without the flag first, a stale `%Ring{}`
  still held by a producer would take the open path into a table identifier the
  runtime is free to have handed to somebody else. With it, every later
  `enqueue/2` answers `{:dropped, :closed}` off the atomics without touching
  ETS at all.
  """
  @spec delete(t()) :: :ok
  def delete(%__MODULE__{} = ring) do
    :atomics.put(ring.state, @closed, 1)
    _closed = close(ring)
    true = :ets.delete(ring.table)
    :ok
  rescue
    ArgumentError -> :ok
  end

  defp enqueue_locked(ring, item, enqueued_at, lock_token) do
    if atomic_get(ring, @closed) == 1 do
      {{:dropped, :closed}, {item, :gone_disconnected}}
    else
      enqueue_open_locked(ring, item, enqueued_at, lock_token)
    end
  end

  defp enqueue_open_locked(%{full_policy: :reject} = ring, item, enqueued_at, lock_token) do
    if atomic_get(ring, @size) == ring.capacity do
      # Go's handleFramePing drops the ping that arrived last when a pong is
      # already waiting: the client is pinging faster than it is being answered,
      # and the answer it is owed is the older one.
      :atomics.add_get(ring.state, @tail_drops, 1)
      {{:dropped, :queue_full}, nil}
    else
      publish_locked(ring, item, enqueued_at, lock_token)
    end
  end

  defp enqueue_open_locked(ring, item, enqueued_at, lock_token) do
    publish_locked(ring, item, enqueued_at, lock_token)
  end

  defp publish_locked(ring, item, enqueued_at, lock_token) do
    wake = signal_writer(ring)
    {full?, index, head, size, head_drops} = slot_plan(ring)
    operation_token = unique_token()

    journal(ring, lock_token, operation_token, index, head, size, head_drops)
    run_hook(ring, :after_journal)
    replaced = if full?, do: replaced_item(ring, index)
    true = :ets.insert(ring.table, {index, operation_token, enqueued_at, item})
    run_hook(ring, :after_publish)
    commit(ring, head, size, head_drops)
    run_hook(ring, :after_commit)
    :ets.delete(ring.table, :journal)

    {enqueue_result(full?, wake), replaced}
  end

  # The slot to publish into, with the head, size and head-drop count that
  # publishing it commits.
  defp slot_plan(ring) do
    head = atomic_get(ring, @head)
    size = atomic_get(ring, @size)
    head_drops = atomic_get(ring, @head_drops)

    if size == ring.capacity do
      {true, head, rem(head + 1, ring.capacity), size, head_drops + 1}
    else
      {false, rem(head + size, ring.capacity), head, size + 1, head_drops}
    end
  end

  defp enqueue_result(true, _wake), do: {:ok, :replaced}
  defp enqueue_result(false, :wake), do: {:ok, :wake}
  defp enqueue_result(false, :coalesced), do: {:ok, :coalesced}

  defp take_locked(ring, lock_token) do
    cond do
      atomic_get(ring, @closed) == 1 ->
        clear_slots(ring)
        :closed

      atomic_get(ring, @size) == 0 ->
        :atomics.put(ring.state, @wake_pending, 0)
        :empty

      true ->
        take_item_locked(ring, lock_token)
    end
  end

  defp take_item_locked(ring, lock_token) do
    head = atomic_get(ring, @head)
    size = atomic_get(ring, @size)
    head_drops = atomic_get(ring, @head_drops)
    [{^head, _slot_token, enqueued_at, item}] = :ets.lookup(ring.table, head)
    operation_token = unique_token()
    new_head = rem(head + 1, ring.capacity)
    new_size = size - 1

    journal(ring, lock_token, operation_token, head, new_head, new_size, head_drops)
    run_hook(ring, :after_journal)
    true = :ets.insert(ring.table, {head, operation_token, 0, nil})
    run_hook(ring, :after_publish)
    commit(ring, new_head, new_size, head_drops)
    run_hook(ring, :after_commit)
    :ets.delete(ring.table, :journal)
    {:ok, item, enqueued_at}
  end

  defp signal_writer(ring) do
    if atomic_get(ring, @wake_pending) == 0 do
      send(ring.notifier, ring.wake_message)
      :atomics.put(ring.state, @wake_pending, 1)
      :wake
    else
      :coalesced
    end
  end

  defp journal(ring, lock_token, operation_token, index, head, size, head_drops) do
    true =
      :ets.insert(ring.table, {
        :journal,
        lock_token,
        operation_token,
        index,
        head,
        size,
        head_drops
      })
  end

  defp recover(ring) do
    case :ets.lookup(ring.table, :journal) do
      [{:journal, _old_lock, operation_token, index, head, size, head_drops}] ->
        case :ets.lookup(ring.table, index) do
          [{^index, ^operation_token, _enqueued_at, _item}] ->
            commit(ring, head, size, head_drops)

          _not_published ->
            :ok
        end

        :ets.delete(ring.table, :journal)

      [] ->
        :ok
    end

    if atomic_get(ring, @closed) == 1, do: clear_slots(ring)
  end

  defp commit(ring, head, size, head_drops) do
    :atomics.put(ring.state, @head, head)
    :atomics.put(ring.state, @size, size)
    :atomics.put(ring.state, @head_drops, head_drops)
  end

  defp clear_slots(ring) do
    operation_token = unique_token()

    for index <- 0..(ring.capacity - 1) do
      true = :ets.insert(ring.table, {index, operation_token, 0, nil})
    end

    :ok
  end

  defp packet_slot_count(ring) do
    :ets.foldl(
      fn
        {index, _token, _enqueued_at, item}, count when is_integer(index) and item != nil ->
          count + 1

        _record, count ->
          count
      end,
      0,
      ring.table
    )
  end

  # Only the lookup belongs under the lock; the drop is recorded after release.
  defp replaced_item(ring, index) do
    case :ets.lookup(ring.table, index) do
      [{^index, _slot_token, replaced_at, item}] -> {item, :queue_head, replaced_at}
      [] -> nil
    end
  end

  defp record_retained_drops(%{metric_kind: nil}), do: :ok

  defp record_retained_drops(ring) do
    Enum.each(0..(ring.capacity - 1), fn index ->
      case :ets.lookup(ring.table, index) do
        [{^index, _slot_token, _enqueued_at, nil}] ->
          :ok

        [{^index, _slot_token, _enqueued_at, item}] ->
          record_drop(ring, item, :gone_disconnected)

        [] ->
          :ok
      end
    end)
  end

  defp record_drop(%{metric_kind: nil}, _item, _reason), do: :ok

  defp record_drop(ring, item, reason) do
    Metrics.add_drop(ring.metrics, reason, ring.metric_kind, packet_size(item))
  end

  defp packet_size({:recv_packet, _source, packet}) when is_binary(packet), do: byte_size(packet)

  defp packet_size({:forward_packet, _source, _destination, packet}) when is_binary(packet),
    do: byte_size(packet)

  defp packet_size(_non_packet), do: 0

  defp atomic_get(ring, index), do: :atomics.get(ring.state, index)
  defp unique_token, do: :erlang.unique_integer([:positive, :monotonic])
  defp run_hook(%__MODULE__{test_hook: nil}, _phase), do: :ok
  defp run_hook(%__MODULE__{test_hook: hook}, phase), do: hook.(phase)
end
