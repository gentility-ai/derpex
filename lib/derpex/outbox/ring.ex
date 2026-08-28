defmodule Derpex.Outbox.Ring do
  @moduledoc """
  Fixed-capacity, non-blocking packet storage for one writer.

  Producers make one lock-acquisition attempt. Contention is a tail drop; a
  full ring replaces its oldest item. Packet references live only in the
  preallocated ETS slots. The writer receives at most one coalesced atom wakeup
  and pulls values directly from the ring.

  A tiny ETS journal makes interrupted mutations recoverable by the next
  producer or consumer. It contains indices and counters, never the packet.
  """

  @head 1
  @size 2
  @wake_pending 3
  @head_drops 4
  @tail_drops 5
  @closed 6

  defstruct [:table, :state, :capacity, :notifier, :wake_message, :test_hook]

  @opaque t :: %__MODULE__{
            table: :ets.tid(),
            state: :atomics.atomics_ref(),
            capacity: pos_integer(),
            notifier: pid(),
            wake_message: atom(),
            test_hook: nil | (atom() -> term())
          }

  @type enqueue_result :: {:ok, :wake | :coalesced | :replaced} | {:dropped, atom()}

  @doc "Creates a ring owned by the calling process."
  @spec new(pos_integer(), keyword()) :: t()
  def new(capacity, options \\ []) when is_integer(capacity) and capacity > 0 do
    table =
      :ets.new(__MODULE__, [
        :set,
        :public,
        read_concurrency: true,
        write_concurrency: true
      ])

    true = :ets.insert(table, for(index <- 0..(capacity - 1), do: {index, 0, nil}))

    %__MODULE__{
      table: table,
      state: :atomics.new(6, signed: false),
      capacity: capacity,
      notifier: Keyword.get(options, :notifier, self()),
      wake_message: Keyword.get(options, :wake_message, :derpex_outbox_ready),
      test_hook: Keyword.get(options, :test_hook)
    }
  end

  @doc "Publishes an item without waiting. Full rings replace the oldest item."
  @spec enqueue(t(), term()) :: enqueue_result()
  def enqueue(%__MODULE__{} = ring, item) do
    if atomic_get(ring, @closed) == 1 do
      {:dropped, :closed}
    else
      case acquire(ring) do
        {:ok, lock_token} ->
          try do
            recover(ring)
            enqueue_locked(ring, item, lock_token)
          after
            release(ring, lock_token)
          end

        :busy ->
          :atomics.add_get(ring.state, @tail_drops, 1)
          {:dropped, :contention}
      end
    end
  end

  @doc "Takes the next item for the single writer."
  @spec take(t()) :: {:ok, term()} | :empty | :closed | :busy
  def take(%__MODULE__{} = ring) do
    case acquire(ring) do
      {:ok, lock_token} ->
        try do
          recover(ring)
          take_locked(ring, lock_token)
        after
          release(ring, lock_token)
        end

      :busy ->
        :busy
    end
  end

  @doc "Closes the ring and releases every retained item. Idempotent."
  @spec close(t()) :: :ok | :busy
  def close(%__MODULE__{} = ring) do
    case acquire(ring) do
      {:ok, lock_token} ->
        try do
          recover(ring)
          :atomics.put(ring.state, @closed, 1)
          clear_slots(ring)
          :atomics.put(ring.state, @size, 0)
          :atomics.put(ring.state, @wake_pending, 0)
          :ets.delete(ring.table, :journal)
          :ok
        after
          release(ring, lock_token)
        end

      :busy ->
        :busy
    end
  end

  @doc "Returns consistent queue and drop counters, or `:busy` under mutation."
  @spec stats(t()) :: map() | :busy
  def stats(%__MODULE__{} = ring) do
    case acquire(ring) do
      {:ok, lock_token} ->
        try do
          recover(ring)

          %{
            capacity: ring.capacity,
            size: atomic_get(ring, @size),
            wake_pending: atomic_get(ring, @wake_pending) == 1,
            head_drops: atomic_get(ring, @head_drops),
            tail_drops: atomic_get(ring, @tail_drops),
            closed: atomic_get(ring, @closed) == 1,
            packet_slots: packet_slot_count(ring)
          }
        after
          release(ring, lock_token)
        end

      :busy ->
        :busy
    end
  end

  defp enqueue_locked(ring, item, lock_token) do
    if atomic_get(ring, @closed) == 1 do
      {:dropped, :closed}
    else
      enqueue_open_locked(ring, item, lock_token)
    end
  end

  defp enqueue_open_locked(ring, item, lock_token) do
    wake = signal_writer(ring)
    head = atomic_get(ring, @head)
    size = atomic_get(ring, @size)
    head_drops = atomic_get(ring, @head_drops)
    full? = size == ring.capacity
    index = if full?, do: head, else: rem(head + size, ring.capacity)
    new_head = if full?, do: rem(head + 1, ring.capacity), else: head
    new_size = if full?, do: size, else: size + 1
    new_head_drops = if full?, do: head_drops + 1, else: head_drops
    operation_token = unique_token()

    journal(ring, lock_token, operation_token, index, new_head, new_size, new_head_drops)
    run_hook(ring, :after_journal)
    true = :ets.insert(ring.table, {index, operation_token, item})
    run_hook(ring, :after_publish)
    commit(ring, new_head, new_size, new_head_drops)
    run_hook(ring, :after_commit)
    :ets.delete(ring.table, :journal)

    cond do
      full? -> {:ok, :replaced}
      wake == :wake -> {:ok, :wake}
      true -> {:ok, :coalesced}
    end
  end

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
    [{^head, _slot_token, item}] = :ets.lookup(ring.table, head)
    operation_token = unique_token()
    new_head = rem(head + 1, ring.capacity)
    new_size = size - 1

    journal(ring, lock_token, operation_token, head, new_head, new_size, head_drops)
    run_hook(ring, :after_journal)
    true = :ets.insert(ring.table, {head, operation_token, nil})
    run_hook(ring, :after_publish)
    commit(ring, new_head, new_size, head_drops)
    run_hook(ring, :after_commit)
    :ets.delete(ring.table, :journal)
    {:ok, item}
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
          [{^index, ^operation_token, _item}] -> commit(ring, head, size, head_drops)
          _not_published -> :ok
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

  defp acquire(ring) do
    token = unique_token()

    if :ets.insert_new(ring.table, {:lock, token, self()}) do
      {:ok, token}
    else
      reclaim_stale_lock(ring, token)
    end
  end

  defp reclaim_stale_lock(ring, token) do
    case :ets.lookup(ring.table, :lock) do
      [{:lock, old_token, owner}] ->
        if Process.alive?(owner) do
          :busy
        else
          :ets.delete_object(ring.table, {:lock, old_token, owner})
          try_insert_lock(ring, token)
        end

      [] ->
        try_insert_lock(ring, token)
    end
  end

  defp try_insert_lock(ring, token) do
    if :ets.insert_new(ring.table, {:lock, token, self()}), do: {:ok, token}, else: :busy
  end

  defp release(ring, token), do: :ets.delete_object(ring.table, {:lock, token, self()})

  defp clear_slots(ring) do
    operation_token = unique_token()

    for index <- 0..(ring.capacity - 1) do
      true = :ets.insert(ring.table, {index, operation_token, nil})
    end

    :ok
  end

  defp packet_slot_count(ring) do
    :ets.foldl(
      fn
        {index, _token, item}, count when is_integer(index) and item != nil -> count + 1
        _record, count -> count
      end,
      0,
      ring.table
    )
  end

  defp atomic_get(ring, index), do: :atomics.get(ring.state, index)
  defp unique_token, do: :erlang.unique_integer([:positive, :monotonic])
  defp run_hook(%__MODULE__{test_hook: nil}, _phase), do: :ok
  defp run_hook(%__MODULE__{test_hook: hook}, phase), do: hook.(phase)
end
