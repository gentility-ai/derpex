defmodule Derpex.Clock.Manual do
  @moduledoc false

  use GenServer

  @behaviour Derpex.Clock

  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, name: __MODULE__)
  end

  def advance(milliseconds) when is_integer(milliseconds) and milliseconds >= 0 do
    GenServer.call(__MODULE__, {:advance, milliseconds})
  end

  def set_system_time(milliseconds) when is_integer(milliseconds) do
    GenServer.call(__MODULE__, {:set_system_time, milliseconds})
  end

  def pending_timer_count, do: GenServer.call(__MODULE__, :pending_timer_count)

  @impl Derpex.Clock
  def monotonic_time(unit) do
    __MODULE__
    |> GenServer.call(:monotonic_time)
    |> System.convert_time_unit(:millisecond, unit)
  end

  @impl Derpex.Clock
  def system_time(unit) do
    __MODULE__
    |> GenServer.call(:system_time)
    |> System.convert_time_unit(:millisecond, unit)
  end

  @impl Derpex.Clock
  def send_after(destination, message, milliseconds) do
    GenServer.call(__MODULE__, {:send_after, destination, message, milliseconds})
  end

  @impl Derpex.Clock
  def cancel_timer(reference) do
    GenServer.call(__MODULE__, {:cancel_timer, reference})
  end

  @impl GenServer
  def init(options) do
    monotonic = Keyword.get(options, :monotonic_time, 0)
    system = Keyword.get(options, :system_time, 0)
    {:ok, %{monotonic: monotonic, system: system, sequence: 0, timers: %{}}}
  end

  @impl GenServer
  def handle_call(:monotonic_time, _from, state), do: {:reply, state.monotonic, state}

  def handle_call(:system_time, _from, state), do: {:reply, state.system, state}

  def handle_call(:pending_timer_count, _from, state),
    do: {:reply, map_size(state.timers), state}

  def handle_call({:set_system_time, milliseconds}, _from, state) do
    {:reply, :ok, %{state | system: milliseconds}}
  end

  def handle_call({:send_after, destination, message, milliseconds}, _from, state) do
    reference = make_ref()
    sequence = state.sequence + 1
    timer = {state.monotonic + milliseconds, sequence, destination, message}
    timers = Map.put(state.timers, reference, timer)
    {:reply, reference, %{state | sequence: sequence, timers: timers}}
  end

  def handle_call({:cancel_timer, reference}, _from, state) do
    case Map.pop(state.timers, reference) do
      {nil, _timers} ->
        {:reply, false, state}

      {{deadline, _sequence, _destination, _message}, timers} ->
        remaining = max(deadline - state.monotonic, 0)
        {:reply, remaining, %{state | timers: timers}}
    end
  end

  def handle_call({:advance, milliseconds}, _from, state) do
    monotonic = state.monotonic + milliseconds
    system = state.system + milliseconds

    {due, future} =
      Enum.split_with(state.timers, fn {_ref, {deadline, _, _, _}} -> deadline <= monotonic end)

    due
    |> Enum.sort_by(fn {_ref, {deadline, sequence, _, _}} -> {deadline, sequence} end)
    |> Enum.each(fn {_ref, {_deadline, _sequence, destination, message}} ->
      send(destination, message)
    end)

    timers = Map.new(future)
    {:reply, :ok, %{state | monotonic: monotonic, system: system, timers: timers}}
  end
end
