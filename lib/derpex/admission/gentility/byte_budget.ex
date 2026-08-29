defmodule Derpex.Admission.Gentility.ByteBudget do
  @moduledoc false

  @type scope :: :node | :organization
  @type budget :: %{
          required(:identity) => binary(),
          required(:revision) => non_neg_integer(),
          required(:bytes_per_second) => non_neg_integer(),
          required(:byte_burst) => non_neg_integer()
        }

  @doc "Creates shared lock-free token-bucket storage owned by the controller."
  @spec new() :: :ets.tid()
  def new do
    :ets.new(__MODULE__, [
      :set,
      :public,
      read_concurrency: true,
      write_concurrency: :auto,
      decentralized_counters: true
    ])
  end

  @doc "Publishes a budget revision while preserving already-consumed capacity."
  @spec sync(:ets.tid(), scope(), budget(), integer()) :: :ok
  def sync(table, scope, budget, now_microsecond) do
    sync_row(table, {scope, budget.identity}, budget, now_microsecond)
  end

  @doc """
  Returns up to `limit` row keys and a continuation.

  Sweeping the table in bounded steps keeps reclamation off any single
  reduction budget; a continuation may miss or repeat rows changed while it is
  held, which the next sweep corrects.
  """
  @spec keys(:ets.tid(), pos_integer()) :: :done | {[{scope(), binary()}], term()}
  def keys(table, limit) when is_integer(limit) and limit > 0 do
    table
    |> :ets.select([{{:"$1", :_, :_, :_, :_, :_}, [], [:"$1"]}], limit)
    |> selected()
  end

  @doc "Continues a `keys/2` sweep."
  @spec next_keys(term()) :: :done | {[{scope(), binary()}], term()}
  def next_keys(continuation), do: continuation |> :ets.select() |> selected()

  @doc "Deletes one budget row no longer represented by a lease or live claim."
  @spec delete(:ets.tid(), {scope(), binary()}) :: :ok
  def delete(table, key) do
    true = :ets.delete(table, key)
    :ok
  end

  @doc "Atomically reserves bytes and returns aggregate pacing delay in microseconds."
  @spec reserve(:ets.tid(), scope(), binary(), non_neg_integer(), integer()) ::
          {:ok, non_neg_integer()} | {:error, term()}
  def reserve(table, scope, identity, bytes, now_microsecond)
      when is_integer(bytes) and bytes >= 0 do
    reserve_row(table, {scope, identity}, bytes, now_microsecond)
  catch
    :error, :badarg -> {:error, :byte_budget_unavailable}
  end

  defp selected({keys, continuation}), do: {keys, continuation}
  defp selected(:"$end_of_table"), do: :done

  defp sync_row(table, key, budget, now_microsecond) do
    case :ets.lookup(table, key) do
      [] ->
        row = new_row(key, budget, now_microsecond)

        if :ets.insert_new(table, row),
          do: :ok,
          else: sync_row(table, key, budget, now_microsecond)

      [old] ->
        sync_existing(table, old, budget, now_microsecond)
    end
  end

  defp sync_existing(_table, {_key, revision, _rate, _burst, _tokens, _last}, budget, _now)
       when revision > budget.revision,
       do: :ok

  defp sync_existing(table, {key, _revision, rate, burst, tokens, last} = old, budget, now) do
    available = refill(rate, burst, tokens, last, now)
    tokens = min(available, budget.byte_burst * 1.0)
    new = {key, budget.revision, budget.bytes_per_second, budget.byte_burst, tokens, now}

    if replace(table, old, new), do: :ok, else: sync_row(table, key, budget, now)
  end

  defp reserve_row(table, key, bytes, now_microsecond) do
    case :ets.lookup(table, key) do
      [{^key, _revision, 0, _burst, _tokens, _last}] ->
        {:ok, 0}

      [{^key, _revision, _rate, burst, _tokens, _last}] when bytes > burst ->
        {:error, :exceeds_byte_burst}

      [{^key, revision, rate, burst, tokens, last} = old] ->
        available = refill(rate, burst, tokens, last, now_microsecond)
        remaining = available - bytes
        delay = if remaining < 0, do: ceil(-remaining * 1_000_000 / rate), else: 0
        new = {key, revision, rate, burst, remaining, now_microsecond}

        if replace(table, old, new) do
          {:ok, delay}
        else
          reserve_row(table, key, bytes, now_microsecond)
        end

      [] ->
        {:error, :byte_budget_missing}
    end
  end

  defp new_row(key, budget, now) do
    {key, budget.revision, budget.bytes_per_second, budget.byte_burst, budget.byte_burst * 1.0,
     now}
  end

  defp refill(0, _burst, _tokens, _last, _now), do: 0.0

  defp refill(rate, burst, tokens, last, now) do
    elapsed = max(now - last, 0)
    min(burst * 1.0, tokens + elapsed * rate / 1_000_000)
  end

  defp replace(table, old, new) do
    :ets.select_replace(table, [{old, [], [{:const, new}]}]) == 1
  end
end
