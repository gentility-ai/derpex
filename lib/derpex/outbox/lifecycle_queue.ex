defmodule Derpex.Outbox.LifecycleQueue do
  @moduledoc """
  Unbounded, ordered storage for one connection's lifecycle frames.

  Peer-present and peer-gone frames are state changes, not traffic: dropping
  one leaves a watcher believing something about the region that is no longer
  true, and no later frame corrects it. Go keeps them in a slice that grows,
  and so does this queue. Packets keep their fixed rings; only lifecycle frames
  live here.

  The structure is an ETS `ordered_set` keyed by `{:item, sequence}`, with the
  lock, wake flag and counters of `Derpex.Outbox.Ring` — the same protocol, so
  a writer drains both the same way. Item keys are tuples and the lock key is
  an atom, which sorts before every tuple, so the oldest item is always
  `:ets.next(table, :lock)`.

  There is no capacity cap, but there is a soft cap: a watcher that has fallen
  more than `#{65_536}` frames behind is not going to catch up, and its queue is
  the only thing keeping those frames alive. Beyond that the queue tells its
  owner to close the connection, which is documented as an exception in
  PLAN section 2.3 and in ADR 0003.

  A mutation here is a single ETS insert or delete, so there is no journal: a
  producer killed mid-enqueue either inserted its item or did not, and the
  consumer reads the table rather than a separate size, so neither outcome can
  strand a frame.
  """

  alias Derpex.Clock
  alias Derpex.Metrics
  alias Derpex.Outbox.Lock

  @sequence 1
  @wake_pending 2
  @closed 3
  @overflow_drops 4
  @overflow_notified 5
  @default_soft_cap 65_536

  defstruct [
    :table,
    :state,
    :notifier,
    :owner,
    :wake_message,
    :soft_cap,
    :metrics
  ]

  @opaque t :: %__MODULE__{
            table: :ets.tid(),
            state: :atomics.atomics_ref(),
            notifier: pid(),
            owner: pid() | nil,
            wake_message: atom(),
            soft_cap: pos_integer(),
            metrics: Metrics.handle() | nil
          }

  @type enqueue_result :: {:ok, :wake | :coalesced} | {:dropped, atom()}

  @doc """
  Creates a queue owned by the calling process.

  `:owner` is the connection to close when the soft cap is passed; without one
  the queue only counts the overflow.
  """
  @spec new(keyword()) :: t()
  def new(options \\ []) do
    %__MODULE__{
      table: :ets.new(__MODULE__, [:ordered_set, :public]),
      state: :atomics.new(5, signed: false),
      notifier: Keyword.get(options, :notifier, self()),
      owner: Keyword.get(options, :owner),
      wake_message: Keyword.get(options, :wake_message, :derpex_outbox_ready),
      soft_cap: Keyword.get(options, :soft_cap, @default_soft_cap),
      metrics: Keyword.get(options, :metrics)
    }
  end

  @doc "The message a queue sends its owner when a watcher falls too far behind."
  @spec overflow_message(non_neg_integer()) :: {:derpex_lifecycle_overflow, non_neg_integer()}
  def overflow_message(size), do: {:derpex_lifecycle_overflow, size}

  @doc """
  Appends one lifecycle frame.

  `wait: false` keeps the acquisition free of naps, for the router and the
  drain coordinator, which must not sleep on behalf of one connection.
  """
  @spec enqueue(t(), term(), keyword()) :: enqueue_result()
  def enqueue(%__MODULE__{} = queue, item, options \\ []) do
    if atomic_get(queue, @closed) == 1 do
      {:dropped, :closed}
    else
      enqueue_open(queue, item, Keyword.get(options, :wait, true))
    end
  end

  defp enqueue_open(queue, item, wait?) do
    enqueued_at = Clock.monotonic_time(:microsecond)

    case Lock.acquire_producer(queue.table, wait?, queue.metrics) do
      {:ok, lock_token} ->
        result =
          try do
            enqueue_locked(queue, item, enqueued_at)
          after
            Lock.release(queue.table, lock_token)
          end

        report_overflow(queue, result)

      :busy ->
        {:dropped, :contention}
    end
  end

  defp enqueue_locked(queue, item, enqueued_at) do
    if atomic_get(queue, @closed) == 1 do
      {:dropped, :closed}
    else
      size = size_locked(queue)

      if size >= queue.soft_cap do
        :atomics.add_get(queue.state, @overflow_drops, 1)
        {:overflow, size}
      else
        wake = signal_writer(queue)
        sequence = :atomics.add_get(queue.state, @sequence, 1)
        true = :ets.insert(queue.table, {{:item, sequence}, enqueued_at, item})
        {:ok, wake}
      end
    end
  end

  # The queue cannot close a connection from inside its own critical section:
  # it tells the owner, outside the lock, and the owner closes itself. The
  # owner is told once - it is already closing, and every further frame the
  # watcher is owed would otherwise send another message to a dying process.
  defp report_overflow(queue, {:overflow, size}) do
    :ok = Metrics.add(queue.metrics, :lifecycle_queue_overflows, 1)

    if is_pid(queue.owner) and
         :atomics.compare_exchange(queue.state, @overflow_notified, 0, 1) ==
           :ok do
      send(queue.owner, overflow_message(size))
    end

    {:dropped, :overflow}
  end

  defp report_overflow(_queue, result), do: result

  @doc "Takes the oldest frame for the single writer."
  @spec take(t()) :: {:ok, term()} | :empty | :closed | :busy
  def take(%__MODULE__{} = queue) do
    case take_with_age(queue) do
      {:ok, item, _age_microseconds} -> {:ok, item}
      other -> other
    end
  end

  @doc "Takes the oldest frame with its queue residence time."
  @spec take_with_age(t()) :: {:ok, term(), non_neg_integer()} | :empty | :closed | :busy
  def take_with_age(%__MODULE__{} = queue) do
    case Lock.acquire_consumer(queue.table) do
      {:ok, lock_token} ->
        taken =
          try do
            take_locked(queue)
          after
            Lock.release(queue.table, lock_token)
          end

        with {:ok, item, enqueued_at} <- taken do
          {:ok, item, max(Clock.monotonic_time(:microsecond) - enqueued_at, 0)}
        end

      :busy ->
        :busy
    end
  end

  defp take_locked(queue) do
    if atomic_get(queue, @closed) == 1 do
      :closed
    else
      take_oldest(queue, :ets.next(queue.table, :lock))
    end
  end

  defp take_oldest(queue, :"$end_of_table") do
    :atomics.put(queue.state, @wake_pending, 0)
    :empty
  end

  defp take_oldest(queue, key) do
    [{^key, enqueued_at, item}] = :ets.lookup(queue.table, key)
    true = :ets.delete(queue.table, key)
    {:ok, item, enqueued_at}
  end

  @doc "Closes the queue and releases every retained frame. Idempotent."
  @spec close(t()) :: :ok | :busy
  def close(%__MODULE__{} = queue) do
    case Lock.acquire(queue.table) do
      {:ok, lock_token} ->
        try do
          :atomics.put(queue.state, @closed, 1)
          :atomics.put(queue.state, @wake_pending, 0)
          clear_items(queue)
          :ok
        after
          Lock.release(queue.table, lock_token)
        end

      :busy ->
        :busy
    end
  end

  @doc """
  Deletes the table outright.

  Closing first means a caller holding a stale struct sees `{:dropped, :closed}`
  rather than an `ArgumentError` from a table that is already gone.
  """
  @spec delete(t()) :: :ok
  def delete(%__MODULE__{} = queue) do
    # The flag first, and unconditionally: `close/1` needs the lock and may not
    # get it, and a producer that raced the delete must find the queue closed
    # rather than a table that is already gone.
    :atomics.put(queue.state, @closed, 1)
    _closed = close(queue)
    true = :ets.delete(queue.table)
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc "Returns the queue's depth, drop count and wake state."
  @spec stats(t()) :: map() | :busy
  def stats(%__MODULE__{} = queue) do
    case Lock.acquire(queue.table) do
      {:ok, lock_token} ->
        try do
          %{
            size: size_locked(queue),
            soft_cap: queue.soft_cap,
            overflow_drops: atomic_get(queue, @overflow_drops),
            wake_pending: atomic_get(queue, @wake_pending) == 1,
            closed: atomic_get(queue, @closed) == 1
          }
        after
          Lock.release(queue.table, lock_token)
        end

      :busy ->
        :busy
    end
  end

  @doc """
  True when `count` more frames fit under the soft cap.

  A producer that can wait asks first rather than overflowing a watcher that is
  merely behind.
  """
  @spec room_for?(t(), pos_integer()) :: boolean()
  def room_for?(%__MODULE__{} = queue, count), do: size(queue) + count <= queue.soft_cap

  @doc "Returns the queue table's memory footprint in machine words."
  @spec memory_words(t()) :: non_neg_integer()
  def memory_words(%__MODULE__{} = queue), do: :ets.info(queue.table, :memory)

  @doc "The queue's current depth, for a gauge. Lock-free, so a hint under load."
  @spec size(t()) :: non_neg_integer()
  def size(%__MODULE__{} = queue) do
    lock_rows = if :ets.member(queue.table, :lock), do: 1, else: 0
    max(:ets.info(queue.table, :size) - lock_rows, 0)
  end

  defp size_locked(queue), do: max(:ets.info(queue.table, :size) - 1, 0)

  defp clear_items(queue) do
    _deleted = :ets.select_delete(queue.table, [{{{:item, :"$1"}, :_, :_}, [], [true]}])
    :ok
  end

  defp signal_writer(queue) do
    if atomic_get(queue, @wake_pending) == 0 do
      send(queue.notifier, queue.wake_message)
      :atomics.put(queue.state, @wake_pending, 1)
      :wake
    else
      :coalesced
    end
  end

  defp atomic_get(queue, index), do: :atomics.get(queue.state, index)
end
