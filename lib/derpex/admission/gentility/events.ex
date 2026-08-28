defmodule Derpex.Admission.Gentility.Events do
  @moduledoc "Bounded revocation consumption with reconciliation after every disconnect."

  use GenServer

  alias Derpex.Admission.Gentility
  alias Derpex.Clock

  @default_poll_timeout_ms 30_000
  @default_backoff_ms 1_000
  @default_max_backoff_ms 30_000
  @default_max_reconciliation_records 10_000
  @default_max_reconciliation_bytes 8 * 1_024 * 1_024
  @max_cursor_bytes 256
  @max_revocation_bytes 4_096

  @doc "Starts one reconnecting event consumer."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options) do
    {name, options} = Keyword.pop(options, :name)
    GenServer.start_link(__MODULE__, options, if(name, do: [name: name], else: []))
  end

  @doc "Returns bounded stream state without node attribution."
  @spec stats(GenServer.server()) :: map()
  def stats(server), do: GenServer.call(server, :stats)

  @impl GenServer
  def init(options) do
    state = %{
      controller: Keyword.get(options, :controller, Gentility),
      adapter: Keyword.fetch!(options, :adapter),
      clock: Keyword.get(options, :clock, Clock),
      poll_timeout_ms: positive_option!(options, :poll_timeout_ms, @default_poll_timeout_ms),
      backoff_ms: positive_option!(options, :backoff_ms, @default_backoff_ms),
      initial_backoff_ms: positive_option!(options, :backoff_ms, @default_backoff_ms),
      max_backoff_ms: positive_option!(options, :max_backoff_ms, @default_max_backoff_ms),
      max_reconciliation_records:
        positive_option!(
          options,
          :max_reconciliation_records,
          @default_max_reconciliation_records
        ),
      max_reconciliation_bytes:
        positive_option!(
          options,
          :max_reconciliation_bytes,
          @default_max_reconciliation_bytes
        ),
      cursor: "",
      mode: :reconcile,
      worker: nil,
      retry_timer: nil,
      last_error: nil,
      reconciliations: 0,
      revocations: 0
    }

    {:ok, start_worker(state)}
  end

  @impl GenServer
  def handle_call(:stats, _from, state) do
    reply = %{
      connected?: state.mode == :stream and not is_nil(state.worker),
      reconciling?: state.mode == :reconcile and not is_nil(state.worker),
      retrying?: not is_nil(state.retry_timer),
      last_error: state.last_error,
      reconciliations: state.reconciliations,
      revocations: state.revocations
    }

    {:reply, reply, state}
  end

  @impl GenServer
  def handle_info(
        {__MODULE__, :result, reference, result},
        %{worker: %{reference: reference}} = state
      ) do
    state = clear_worker(state)
    {:noreply, handle_result(state, result)}
  end

  def handle_info({__MODULE__, :result, _stale, _result}, state), do: {:noreply, state}

  def handle_info(
        {:DOWN, monitor, :process, _pid, _reason},
        %{worker: %{monitor: monitor}} = state
      ) do
    state = %{state | worker: nil, last_error: :adapter_exit, mode: :reconcile}
    {:noreply, schedule_retry(state)}
  end

  def handle_info({:DOWN, _monitor, :process, _pid, _reason}, state), do: {:noreply, state}

  def handle_info({__MODULE__, :retry, token}, %{retry_timer: {token, _timer}} = state) do
    {:noreply, start_worker(%{state | retry_timer: nil})}
  end

  def handle_info({__MODULE__, :retry, _stale}, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, state) do
    if state.worker, do: Process.exit(state.worker.pid, :kill)
    cancel_retry(state)
    :ok
  end

  defp start_worker(%{worker: nil, retry_timer: nil} = state) do
    parent = self()
    reference = make_ref()
    mode = state.mode
    adapter = state.adapter
    cursor = state.cursor
    timeout = state.poll_timeout_ms

    {pid, monitor} =
      spawn_monitor(fn ->
        result = invoke_adapter(adapter, mode, cursor, timeout)
        send(parent, {__MODULE__, :result, reference, result})
      end)

    %{state | worker: %{pid: pid, monitor: monitor, reference: reference}}
  end

  defp start_worker(state), do: state

  defp invoke_adapter({module, options}, :reconcile, _cursor, _timeout),
    do: module.reconcile(options)

  defp invoke_adapter(module, :reconcile, _cursor, _timeout), do: module.reconcile([])

  defp invoke_adapter({module, options}, :stream, cursor, timeout),
    do: module.next_revocation(cursor, timeout, options)

  defp invoke_adapter(module, :stream, cursor, timeout),
    do: module.next_revocation(cursor, timeout, [])

  defp handle_result(%{mode: :reconcile} = state, {:ok, wires, cursor}) do
    with :ok <- valid_cursor(cursor),
         :ok <- valid_reconciliation(wires, state),
         {:ok, _summary} <- Gentility.reconcile(state.controller, wires) do
      state = %{
        state
        | cursor: cursor,
          mode: :stream,
          last_error: nil,
          backoff_ms: state.initial_backoff_ms,
          reconciliations: state.reconciliations + 1
      }

      start_worker(state)
    else
      {:error, reason} -> fail_and_retry(state, normalize_error(reason))
    end
  end

  defp handle_result(%{mode: :stream} = state, {:ok, wire, cursor}) do
    with :ok <- valid_cursor(cursor),
         :ok <- valid_revocation(wire),
         {:ok, _result} <- Gentility.revoke(state.controller, wire) do
      state = %{
        state
        | cursor: cursor,
          last_error: nil,
          backoff_ms: state.initial_backoff_ms,
          revocations: state.revocations + 1
      }

      start_worker(state)
    else
      {:error, reason} -> fail_and_retry(state, normalize_error(reason))
    end
  end

  defp handle_result(%{mode: :stream} = state, {:timeout, cursor}) do
    case valid_cursor(cursor) do
      :ok -> start_worker(%{state | cursor: cursor, last_error: nil})
      {:error, reason} -> fail_and_retry(state, reason)
    end
  end

  defp handle_result(state, {:error, _reason}), do: fail_and_retry(state, :adapter_unavailable)
  defp handle_result(state, _invalid), do: fail_and_retry(state, :invalid_adapter_response)

  defp fail_and_retry(state, reason) do
    state = %{state | mode: :reconcile, last_error: reason}
    schedule_retry(state)
  end

  defp schedule_retry(state) do
    token = make_ref()
    timer = state.clock.send_after(self(), {__MODULE__, :retry, token}, state.backoff_ms)
    backoff_ms = min(state.backoff_ms * 2, state.max_backoff_ms)
    %{state | retry_timer: {token, timer}, backoff_ms: backoff_ms}
  end

  defp cancel_retry(%{retry_timer: nil}), do: :ok

  defp cancel_retry(%{retry_timer: {_token, timer}, clock: clock}) do
    _remaining = clock.cancel_timer(timer)
    :ok
  end

  defp clear_worker(state) do
    Process.demonitor(state.worker.monitor, [:flush])
    %{state | worker: nil}
  end

  defp valid_cursor(cursor) when is_binary(cursor) and byte_size(cursor) <= @max_cursor_bytes,
    do: :ok

  defp valid_cursor(_cursor), do: {:error, :invalid_cursor}

  defp valid_reconciliation(wires, state)
       when is_list(wires) and length(wires) <= state.max_reconciliation_records do
    if Enum.all?(wires, &valid_revocation?(&1, @max_revocation_bytes)) and
         Enum.sum(Enum.map(wires, &byte_size/1)) <= state.max_reconciliation_bytes do
      :ok
    else
      {:error, :invalid_reconciliation}
    end
  end

  defp valid_reconciliation(_wires, _state), do: {:error, :invalid_reconciliation}

  defp valid_revocation(wire) do
    if valid_revocation?(wire, @max_revocation_bytes),
      do: :ok,
      else: {:error, :invalid_revocation_record}
  end

  defp valid_revocation?(wire, maximum), do: is_binary(wire) and byte_size(wire) <= maximum

  defp normalize_error(reason)
       when reason in [
              :invalid_cursor,
              :invalid_reconciliation,
              :invalid_revocation_record,
              :invalid_signed_record,
              :invalid_signature,
              :record_too_large
            ],
       do: reason

  defp normalize_error(_reason), do: :reconciliation_failed

  defp positive_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{key} must be a positive integer"
    end
  end
end
