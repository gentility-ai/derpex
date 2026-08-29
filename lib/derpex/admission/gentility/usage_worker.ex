defmodule Derpex.Admission.Gentility.UsageWorker do
  @moduledoc """
  Owns durable Gentility usage rotation and export outside admission control.

  Packet accounting remains a direct ETS update. Spool persistence, batch
  encoding, retries, and exporter timeouts are isolated here so none of them
  can delay a lease decision or an active revocation.
  """

  use GenServer

  require Logger

  alias Derpex.Admission.Gentility.Usage
  alias Derpex.Admission.Gentility.UsageContract
  alias Derpex.Admission.Gentility.UsageSpool
  alias Derpex.Clock

  @default_window_ms 60_000
  @default_retry_ms 5_000
  @default_export_timeout_ms 5_000
  @default_max_batches 120
  @default_max_bytes 64 * 1_024 * 1_024

  defmodule Handle do
    @moduledoc false

    @enforce_keys [:server, :table, :metadata, :blocked, :window_ms]
    defstruct @enforce_keys

    @type t :: %__MODULE__{
            server: pid(),
            table: :ets.tid(),
            metadata: :ets.tid(),
            blocked: :atomics.atomics_ref(),
            window_ms: pos_integer()
          }
  end

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc false
  @spec handle(GenServer.server()) :: Handle.t()
  def handle(server), do: GenServer.call(server, :handle)

  @doc false
  @spec stop(nil | Handle.t()) :: :ok
  def stop(nil), do: :ok

  def stop(%Handle{server: server}) do
    Process.unlink(server)
    GenServer.stop(server, :shutdown)
  catch
    :exit, _reason -> :ok
  end

  @doc "Returns usage telemetry without entering either the usage or admission mailbox."
  @spec stats(nil | Handle.t()) :: map()
  def stats(nil), do: %{enabled: false}

  def stats(%Handle{} = handle) do
    aggregates = Usage.stats(handle.table)

    status =
      case :ets.lookup(handle.metadata, :status) do
        [{:status, status}] -> status
        [] -> unavailable_status(handle)
      end

    Map.merge(status, %{
      aggregate_entries: aggregates.entries,
      aggregate_windows: aggregates.windows,
      blocked?: :atomics.get(handle.blocked, 1) == 1
    })
  rescue
    ArgumentError ->
      unavailable_status(handle)
      |> Map.merge(%{aggregate_entries: 0, aggregate_windows: 0, blocked?: true})
  end

  @impl GenServer
  def init(options) do
    Process.flag(:trap_exit, true)

    with {:ok, state} <- initial_state(options) do
      state = state |> rotate_usage() |> schedule() |> start_export() |> publish()
      {:ok, state}
    end
  end

  @impl GenServer
  def handle_call(:handle, _from, state) do
    handle = %Handle{
      server: self(),
      table: state.table,
      metadata: state.metadata,
      blocked: state.blocked,
      window_ms: state.window_ms
    }

    {:reply, handle, state}
  end

  @impl GenServer
  def handle_info({__MODULE__, :tick, token}, %{timer_token: token} = state) do
    state = %{state | timer: nil, timer_token: nil, last_error: nil}
    {:noreply, state |> rotate_usage() |> schedule() |> start_export() |> publish()}
  end

  def handle_info({__MODULE__, :tick, _stale}, state), do: {:noreply, state}

  def handle_info(
        {__MODULE__, :export_result, reference, result},
        %{export: %{reference: reference}} = state
      ) do
    state = finish_export(state, result)

    state =
      if state.last_error do
        schedule(state)
      else
        state |> rotate_usage() |> schedule() |> start_export()
      end

    {:noreply, publish(state)}
  end

  def handle_info({__MODULE__, :export_result, _reference, _result}, state),
    do: {:noreply, state}

  def handle_info(
        {__MODULE__, :export_timeout, reference},
        %{export: %{reference: reference, pid: pid}} = state
      ) do
    Process.exit(pid, :kill)
    state = %{state | export: nil, last_error: :export_timeout}
    {:noreply, state |> schedule() |> publish()}
  end

  def handle_info({__MODULE__, :export_timeout, _stale}, state), do: {:noreply, state}

  def handle_info(
        {:DOWN, monitor, :process, _pid, _reason},
        %{export: %{monitor: monitor}} = state
      ) do
    state = cancel_export_timer(state)
    state = %{state | export: nil, last_error: :export_exit}
    {:noreply, state |> schedule() |> publish()}
  end

  def handle_info({:DOWN, _monitor, :process, _pid, _reason}, state), do: {:noreply, state}

  def handle_info({:EXIT, owner, reason}, %{owner: owner} = state), do: {:stop, reason, state}
  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

  @impl GenServer
  def terminate(_reason, state) do
    :atomics.put(state.blocked, 1, 1)
    _state = cancel_timer(state)

    if state.export do
      _state = cancel_export_timer(state)
      Process.exit(state.export.pid, :kill)
    end

    :ok
  end

  defp initial_state(options) do
    instance_id = Keyword.fetch!(options, :instance_id)
    region_id = Keyword.fetch!(options, :region_id)
    spool_path = Keyword.fetch!(options, :spool_path)
    exporter = Keyword.fetch!(options, :exporter)
    owner = Keyword.fetch!(options, :owner)
    clock = Keyword.get(options, :clock, Clock)
    window_ms = positive_option!(options, :window_ms, @default_window_ms)
    retry_ms = positive_option!(options, :retry_ms, @default_retry_ms)

    export_timeout_ms =
      positive_option!(options, :export_timeout_ms, @default_export_timeout_ms)

    max_batches = positive_option!(options, :max_batches, @default_max_batches)
    max_bytes = positive_option!(options, :max_bytes, @default_max_bytes)

    with :ok <- validate_identity(instance_id, region_id, spool_path, exporter, owner),
         {:ok, spool} <- UsageSpool.load(spool_path, max_batches, max_bytes) do
      blocked = :atomics.new(1, signed: false)
      if UsageSpool.stats(spool).batches >= max_batches, do: :atomics.put(blocked, 1, 1)

      {:ok,
       %{
         owner: owner,
         clock: clock,
         table: Usage.new(),
         metadata: metadata_table(),
         blocked: blocked,
         instance_id: instance_id,
         region_id: region_id,
         window_ms: window_ms,
         retry_ms: retry_ms,
         export_timeout_ms: export_timeout_ms,
         exporter: exporter,
         spool: spool,
         timer: nil,
         timer_token: nil,
         export: nil,
         last_error: nil,
         dropped_rows: 0
       }}
    end
  end

  defp metadata_table do
    :ets.new(__MODULE__, [:set, :public, read_concurrency: true])
  end

  defp rotate_usage(state) do
    now = state.clock.system_time(:millisecond)

    case Usage.oldest_closed(state.table, state.window_ms, now) do
      nil -> state
      {window_start, rows} -> drain_window(state, window_start, rows)
    end
  end

  # The window is snapshotted and ordered once; it is then cut into batches the
  # contract accepts. A cut that is still too large for the wire is bisected
  # rather than discarded, so a window of large identities is exported in full.
  defp drain_window(state, _window_start, []), do: state

  defp drain_window(state, window_start, rows) do
    {chunk, rest} = Enum.split(rows, UsageContract.max_entries())

    case commit_rows(state, window_start, chunk) do
      {:ok, state} when rest == [] -> rotate_usage(state)
      {:ok, state} -> drain_window(state, window_start, rest)
      {:blocked, state} -> state
    end
  end

  defp commit_rows(state, _window_start, []), do: {:ok, state}

  defp commit_rows(state, window_start, rows) do
    batch =
      Usage.batch(state.instance_id, state.region_id, window_start, state.window_ms, rows)

    case UsageContract.encode(batch) do
      {:ok, encoded} -> spool_batch(state, encoded, rows)
      {:error, reason} -> bisect_or_drop(state, window_start, rows, reason)
    end
  end

  defp spool_batch(state, encoded, rows) do
    case UsageSpool.put(state.spool, encoded) do
      {:ok, spool} ->
        :ok = Usage.delete_rows(state.table, rows)
        :atomics.put(state.blocked, 1, 0)
        {:ok, %{state | spool: spool, last_error: nil}}

      {:error, reason} ->
        :atomics.put(state.blocked, 1, 1)
        {:blocked, %{state | last_error: reason}}
    end
  end

  # Halving isolates whatever the contract rejects. Only a single row that still
  # cannot encode on its own is dropped: everything that shares the window with
  # it is exported normally.
  defp bisect_or_drop(state, window_start, [row], reason) do
    {:ok, drop_row(state, window_start, row, reason)}
  end

  defp bisect_or_drop(state, window_start, rows, _reason) do
    {left, right} = Enum.split(rows, div(length(rows), 2))

    case commit_rows(state, window_start, left) do
      {:ok, state} -> commit_rows(state, window_start, right)
      {:blocked, state} -> {:blocked, state}
    end
  end

  # A row the contract can never encode would otherwise be retried forever and
  # block every packet behind the billing ledger. Account for the loss, delete
  # it, and keep draining the window.
  defp drop_row(state, window_start, row, reason) do
    Logger.warning("gentility usage row dropped: #{inspect(reason)} (window #{window_start})")

    :ok = Usage.delete_rows(state.table, [row])
    :atomics.put(state.blocked, 1, 0)
    %{state | dropped_rows: state.dropped_rows + 1, last_error: nil}
  end

  defp start_export(%{export: export} = state) when not is_nil(export), do: state

  defp start_export(state) do
    case UsageSpool.peek(state.spool) do
      nil ->
        state

      {id, wire} ->
        parent = self()
        reference = make_ref()
        exporter = state.exporter

        {pid, monitor} =
          :erlang.spawn_opt(
            fn ->
              result = invoke_exporter(exporter, id, wire)
              send(parent, {__MODULE__, :export_result, reference, result})
            end,
            [:link, :monitor]
          )

        timer =
          state.clock.send_after(
            self(),
            {__MODULE__, :export_timeout, reference},
            state.export_timeout_ms
          )

        export = %{
          id: id,
          pid: pid,
          monitor: monitor,
          reference: reference,
          timer: timer
        }

        %{state | export: export}
    end
  end

  defp invoke_exporter(exporter, id, wire) when is_function(exporter, 2),
    do: exporter.(id, wire)

  defp invoke_exporter({module, options}, id, wire),
    do: module.export_usage(id, wire, options)

  defp invoke_exporter(module, id, wire), do: module.export_usage(id, wire, [])

  defp finish_export(state, result) do
    export = state.export
    Process.unlink(export.pid)
    Process.demonitor(export.monitor, [:flush])
    state = cancel_export_timer(state)
    state = %{state | export: nil}

    if successful_export?(result) do
      case UsageSpool.ack(state.spool, export.id) do
        {:ok, spool} ->
          :atomics.put(state.blocked, 1, 0)
          %{state | spool: spool, last_error: nil}

        {:error, reason} ->
          :atomics.put(state.blocked, 1, 1)
          %{state | last_error: {:spool_ack, reason}}
      end
    else
      %{state | last_error: :export_failed}
    end
  end

  defp successful_export?(:ok), do: true
  defp successful_export?({:ok, _result}), do: true
  defp successful_export?(_result), do: false

  defp schedule(state) do
    state = cancel_timer(state)
    now = state.clock.system_time(:millisecond)
    boundary_delay = state.window_ms - Integer.mod(now, state.window_ms)

    delay =
      if state.last_error || :atomics.get(state.blocked, 1) == 1,
        do: min(boundary_delay, state.retry_ms),
        else: boundary_delay

    token = make_ref()
    timer = state.clock.send_after(self(), {__MODULE__, :tick, token}, delay)
    %{state | timer: timer, timer_token: token}
  end

  defp cancel_timer(%{timer: nil} = state), do: state

  defp cancel_timer(state) do
    _remaining = cancel_clock_timer(state.clock, state.timer)
    %{state | timer: nil, timer_token: nil}
  end

  defp cancel_export_timer(%{export: %{timer: timer}} = state) do
    _remaining = cancel_clock_timer(state.clock, timer)
    state
  end

  defp cancel_export_timer(state), do: state

  defp cancel_clock_timer(clock, timer) do
    clock.cancel_timer(timer)
  catch
    :exit, _reason -> false
  end

  defp publish(state) do
    spool = UsageSpool.stats(state.spool)

    status = %{
      enabled: true,
      spool_batches: spool.batches,
      spool_bytes: spool.bytes,
      exporting?: not is_nil(state.export),
      dropped_rows: state.dropped_rows,
      last_error: state.last_error
    }

    true = :ets.insert(state.metadata, {:status, status})
    state
  end

  defp unavailable_status(_handle) do
    %{
      enabled: true,
      spool_batches: 0,
      spool_bytes: 0,
      exporting?: false,
      dropped_rows: 0,
      last_error: :usage_unavailable
    }
  end

  defp validate_identity(instance_id, region_id, spool_path, exporter, owner) do
    with :ok <- validate_instance_id(instance_id),
         :ok <- validate_region_id(region_id),
         :ok <- validate_spool_path(spool_path),
         :ok <- validate_exporter(exporter) do
      if is_pid(owner), do: :ok, else: {:error, :invalid_usage_owner}
    end
  end

  defp validate_instance_id(instance_id)
       when is_binary(instance_id) and byte_size(instance_id) in 1..512 do
    if String.valid?(instance_id), do: :ok, else: {:error, :invalid_usage_instance_id}
  end

  defp validate_instance_id(_instance_id), do: {:error, :invalid_usage_instance_id}

  defp validate_region_id(region_id) when is_integer(region_id) and region_id in 0..0xFFFF_FFFF,
    do: :ok

  defp validate_region_id(_region_id), do: {:error, :invalid_usage_region_id}

  defp validate_spool_path(spool_path) when is_binary(spool_path) and spool_path != "", do: :ok
  defp validate_spool_path(_spool_path), do: {:error, :invalid_usage_spool_path}

  defp validate_exporter(exporter) do
    if valid_exporter?(exporter), do: :ok, else: {:error, :invalid_usage_exporter}
  end

  defp valid_exporter?(exporter) when is_function(exporter, 2), do: true
  defp valid_exporter?({module, _options}) when is_atom(module), do: true
  defp valid_exporter?(module) when is_atom(module), do: true
  defp valid_exporter?(_exporter), do: false

  defp positive_option!(options, key, default) do
    case Keyword.get(options, key, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{key} must be a positive integer"
    end
  end
end
