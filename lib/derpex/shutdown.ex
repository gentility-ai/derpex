defmodule Derpex.Shutdown do
  @moduledoc "Coordinates a hard-bounded application drain before supervision stops."

  alias Derpex.Drain

  @default_deadline_ms 30_000
  @default_poll_ms 25
  @maximum_deadline_ms 86_400_000

  @type result :: %{
          outcome: :drained | :deadline | :unavailable,
          elapsed_ms: non_neg_integer(),
          forced_connections: non_neg_integer()
        }

  @doc "Begins drain, waits for homes to migrate, and closes leftovers at the wall deadline."
  @spec run(GenServer.server(), keyword()) :: result()
  def run(server \\ Drain, options \\ []) do
    deadline_ms = duration!(options, :deadline_ms, @default_deadline_ms, 0)
    poll_ms = duration!(options, :poll_ms, @default_poll_ms, 1)
    drain_options = Keyword.delete(options, :poll_ms)
    started_at = System.monotonic_time(:millisecond)
    initial_closes = initial_deadline_closes(server)

    case begin_drain(server, drain_options) do
      {:ok, _info} -> await(server, started_at, deadline_ms, poll_ms, initial_closes)
      {:error, :unavailable} -> result(:unavailable, started_at, 0)
    end
  end

  defp await(server, started_at, deadline_ms, poll_ms, initial_closes) do
    case drain_stats(server) do
      {:ok, %{targeted_connections: 0, deadline_closes: closes}} ->
        forced = max(closes - initial_closes, 0)
        outcome = if forced > 0, do: :deadline, else: :drained
        result(outcome, started_at, forced)

      {:ok, _stats} ->
        if elapsed(started_at) >= deadline_ms do
          forced = finish(server)
          forced = max(forced, deadline_closes_since(server, initial_closes))
          result(:deadline, started_at, forced)
        else
          Process.sleep(min(poll_ms, max(deadline_ms - elapsed(started_at), 1)))
          await(server, started_at, deadline_ms, poll_ms, initial_closes)
        end

      {:error, :unavailable} ->
        result(:unavailable, started_at, 0)
    end
  end

  defp initial_deadline_closes(server) do
    case drain_stats(server) do
      {:ok, %{deadline_closes: closes}} -> closes
      {:error, :unavailable} -> 0
    end
  end

  defp deadline_closes_since(server, initial_closes) do
    case drain_stats(server) do
      {:ok, %{deadline_closes: closes}} -> max(closes - initial_closes, 0)
      {:error, :unavailable} -> 0
    end
  end

  defp begin_drain(server, options) do
    Drain.begin_drain(server, options)
  catch
    :exit, _reason -> {:error, :unavailable}
  end

  defp drain_stats(server) do
    {:ok, Drain.stats(server)}
  catch
    :exit, _reason -> {:error, :unavailable}
  end

  defp finish(server) do
    case Drain.finish(server) do
      {:ok, closed} -> closed
    end
  catch
    :exit, _reason -> 0
  end

  defp result(outcome, started_at, forced) do
    %{outcome: outcome, elapsed_ms: elapsed(started_at), forced_connections: forced}
  end

  defp elapsed(started_at), do: max(System.monotonic_time(:millisecond) - started_at, 0)

  defp duration!(options, key, default, minimum) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value >= minimum and value <= @maximum_deadline_ms -> value
      _invalid -> raise ArgumentError, "#{key} is outside its supported range"
    end
  end
end
