defmodule Derpex.Admission.Gentility.Closer do
  @moduledoc """
  Runs mass peer closes outside the admission controller.

  A reconciliation, an expiry sweep, or a key rotation can close thousands of
  peers at once, and each close is a router operation. Doing that inside the
  controller's call would stall every admission decision behind it, so batches
  are handed here and run concurrently while the controller keeps answering.

  Each close is isolated: a router call that times out or crashes is counted and
  logged, and the rest of the batch still runs. One unreachable peer must not
  cost a batch, this process, or the controller behind it.
  """

  use GenServer

  require Logger

  @default_max_concurrency 32
  @default_close_timeout_ms 5_000

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc """
  Closes a batch of node keys without waiting for them.

  Returns `{:error, :no_closer}` when there is no closer to hand the batch to,
  so a caller reports peers it could not close rather than assuming it did.
  """
  @spec close(nil | pid(), [binary()]) :: :ok | {:error, :no_closer}
  def close(_server, []), do: :ok
  def close(nil, _keys), do: {:error, :no_closer}
  def close(server, keys), do: GenServer.cast(server, {:close, keys})

  @doc false
  @spec stop(nil | pid()) :: :ok
  def stop(nil), do: :ok

  def stop(server) do
    GenServer.stop(server, :shutdown, 500)
  catch
    :exit, _reason -> :ok
  end

  @impl GenServer
  def init(options) do
    close_peer = Keyword.fetch!(options, :close_peer)
    failures = Keyword.fetch!(options, :failures)

    max_concurrency =
      Keyword.get(options, :max_concurrency, @default_max_concurrency)

    close_timeout_ms =
      Keyword.get(options, :close_timeout_ms, @default_close_timeout_ms)

    if is_function(close_peer, 1) and is_integer(max_concurrency) and max_concurrency > 0 and
         is_integer(close_timeout_ms) and close_timeout_ms > 0 do
      {:ok,
       %{
         close_peer: close_peer,
         failures: failures,
         max_concurrency: max_concurrency,
         close_timeout_ms: close_timeout_ms
       }}
    else
      {:stop, :invalid_closer}
    end
  end

  @impl GenServer
  def handle_cast({:close, keys}, state) do
    # Every close is bounded: a router that stops answering costs one deadline
    # per peer, not a closer that never returns to the next batch.
    keys
    |> Task.async_stream(fn key -> close_one(state, key) end,
      max_concurrency: state.max_concurrency,
      ordered: false,
      timeout: state.close_timeout_ms,
      on_timeout: :kill_task
    )
    |> Enum.each(&record_result(state, &1))

    {:noreply, state}
  end

  defp record_result(_state, {:ok, _result}), do: :ok

  defp record_result(state, {:exit, reason}) do
    :atomics.add(state.failures, 1, 1)
    Logger.warning("gentility peer close did not finish: #{inspect(reason)}")
    :ok
  end

  defp close_one(state, key) do
    _connection_count = state.close_peer.(key)
    :ok
  catch
    kind, reason ->
      :atomics.add(state.failures, 1, 1)
      Logger.warning("gentility could not close a peer: #{inspect(kind)} #{inspect(reason)}")
      :error
  end
end
