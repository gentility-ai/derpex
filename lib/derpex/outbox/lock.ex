defmodule Derpex.Outbox.Lock do
  @moduledoc """
  The lock every outbox structure shares: one ETS row naming its owner.

  A producer holds no shared "waiting" state. Every attempt is a plain lock
  attempt, so a producer killed between attempts leaves nothing behind for the
  next caller; the only thing a dead process can leave is the lock row itself,
  which the next caller reclaims by checking the recorded pid.

  Waiting is bounded by the wall clock rather than by an attempt count, because
  `:erlang.yield/0` returns in microseconds on an idle node and in tens of
  milliseconds behind a long run queue. Yields cover the common case, where the
  holder is running its few microseconds of ETS work; the naps cover the
  uncommon one, where the holder used up its reduction budget inside the
  critical section and has to be rescheduled. `wait: false` keeps the yields
  and drops the naps, for callers that must not sleep on behalf of one
  connection. See ADR 0001.
  """

  alias Derpex.Metrics

  @producer_yields 4
  @producer_nap_ms 1
  @acquire_budget_microseconds 4_000
  @lock_retries 1_024

  @type token :: integer()
  @type result :: {:ok, token()} | :busy

  @doc "The wall-clock budget an acquisition may spend, in microseconds."
  @spec budget_microseconds() :: pos_integer()
  def budget_microseconds, do: @acquire_budget_microseconds

  @doc "How many naps fit inside that budget."
  @spec nap_allowance() :: pos_integer()
  def nap_allowance, do: div(@acquire_budget_microseconds, @producer_nap_ms * 1_000)

  @doc """
  Acquires for a producer, yielding and then napping inside the budget.

  `metrics` counts the naps, so a relay that starts paying the budget says so.
  """
  @spec acquire_producer(:ets.tid(), boolean(), Metrics.handle() | nil) :: result()
  def acquire_producer(table, wait?, metrics) do
    acquire_producer(table, @producer_yields, wait?, metrics, deadline())
  end

  defp acquire_producer(table, yields_left, wait?, metrics, deadline) when yields_left > 0 do
    case try_acquire(table) do
      :busy ->
        :erlang.yield()

        if expired?(deadline),
          do: :busy,
          else: acquire_producer(table, yields_left - 1, wait?, metrics, deadline)

      result ->
        result
    end
  end

  # A caller that will not nap still makes the reclaiming attempt, so a lock
  # left by a dead producer cannot outlive it.
  defp acquire_producer(table, 0, false, _metrics, _deadline), do: try_acquire_or_reclaim(table)

  defp acquire_producer(table, 0, true, metrics, deadline) do
    case try_acquire_or_reclaim(table) do
      :busy ->
        if nap_fits?(deadline) do
          Metrics.add(metrics, :ring_producer_naps, 1)
          Process.sleep(@producer_nap_ms)
          acquire_producer(table, 0, true, metrics, deadline)
        else
          :busy
        end

      result ->
        result
    end
  end

  @doc "Acquires for the single consumer: one attempt, never a wait."
  @spec acquire_consumer(:ets.tid()) :: result()
  def acquire_consumer(table), do: try_acquire_or_reclaim(table)

  @doc "Acquires for an administrative caller: yields inside the same budget."
  @spec acquire(:ets.tid()) :: result()
  def acquire(table), do: acquire(table, @lock_retries, deadline())

  defp acquire(table, retries_left, deadline) do
    case try_acquire_or_reclaim(table) do
      :busy when retries_left > 0 ->
        :erlang.yield()

        if expired?(deadline), do: :busy, else: acquire(table, retries_left - 1, deadline)

      result ->
        result
    end
  end

  @doc "Releases a lock this process holds. Another holder's row is untouched."
  @spec release(:ets.tid(), token()) :: true
  def release(table, token), do: :ets.delete_object(table, {:lock, token, self()})

  defp deadline, do: :erlang.monotonic_time(:microsecond) + @acquire_budget_microseconds

  defp expired?(deadline), do: :erlang.monotonic_time(:microsecond) >= deadline

  defp nap_fits?(deadline) do
    :erlang.monotonic_time(:microsecond) + @producer_nap_ms * 1_000 <= deadline
  end

  # The stale-owner check costs a lookup and a liveness call, which is waste on
  # the common path where the owner is alive and about to release.
  defp try_acquire(table) do
    token = token()
    if :ets.insert_new(table, {:lock, token, self()}), do: {:ok, token}, else: :busy
  end

  defp try_acquire_or_reclaim(table) do
    token = token()

    if :ets.insert_new(table, {:lock, token, self()}) do
      {:ok, token}
    else
      reclaim_stale_lock(table, token)
    end
  end

  defp reclaim_stale_lock(table, token) do
    case :ets.lookup(table, :lock) do
      [{:lock, old_token, owner}] ->
        if Process.alive?(owner) do
          :busy
        else
          :ets.delete_object(table, {:lock, old_token, owner})
          try_insert_lock(table, token)
        end

      [] ->
        try_insert_lock(table, token)
    end
  end

  defp try_insert_lock(table, token) do
    if :ets.insert_new(table, {:lock, token, self()}), do: {:ok, token}, else: :busy
  end

  defp token, do: :erlang.unique_integer([:positive, :monotonic])
end
