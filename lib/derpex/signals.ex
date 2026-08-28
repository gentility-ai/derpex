defmodule Derpex.Signals do
  @moduledoc "Supervises OS signal integration that is not owned by the OTP release scripts."

  use GenServer

  require Logger

  alias Derpex.RateController
  alias Derpex.SignalHandler

  @signal_server :erl_signal_server

  @doc false
  def start_link(options) do
    {name, options} = Keyword.pop(options, :name, __MODULE__)
    GenServer.start_link(__MODULE__, options, if(name, do: [name: name], else: []))
  end

  @doc "Reloads the configured receive-rate file through the supervised controller."
  @spec reload(GenServer.server()) :: {:ok, Derpex.RateConfig.t()} | {:error, term()}
  def reload(server \\ __MODULE__), do: GenServer.call(server, :reload)

  @doc "Returns aggregate signal/reload state without exposing configuration contents."
  @spec stats(GenServer.server()) :: map()
  def stats(server \\ __MODULE__), do: GenServer.call(server, :stats)

  @impl GenServer
  def init(options) do
    state = %{
      path: Keyword.fetch!(options, :rate_config_path),
      rate_controller: Keyword.get(options, :rate_controller, RateController),
      handler: nil,
      reloads: 0,
      failures: 0,
      last_error: nil
    }

    if Keyword.get(options, :install, true) do
      case install_handler() do
        {:ok, handler} -> {:ok, %{state | handler: handler}}
        {:error, reason} -> {:stop, {:signal_handler, reason}}
      end
    else
      {:ok, state}
    end
  end

  @impl GenServer
  def handle_call(:reload, _from, state) do
    {result, state} = apply_reload(state)
    {:reply, result, state}
  end

  def handle_call(:stats, _from, state) do
    stats = %{
      installed?: not is_nil(state.handler),
      reloads: state.reloads,
      failures: state.failures,
      last_error: state.last_error
    }

    {:reply, stats, state}
  end

  @impl GenServer
  def handle_info({__MODULE__, :sighup}, state) do
    {_result, state} = apply_reload(state)
    {:noreply, state}
  end

  def handle_info({:gen_event_EXIT, handler, reason}, %{handler: handler} = state) do
    {:stop, {:signal_handler_exit, reason}, state}
  end

  def handle_info(_message, state), do: {:noreply, state}

  defp apply_reload(state) do
    Logger.info("SIGHUP received; reloading DERP rate configuration")

    case RateController.load_and_apply(state.rate_controller, state.path) do
      {:ok, _config} = result ->
        Logger.info("DERP rate configuration reloaded successfully")
        {result, %{state | reloads: state.reloads + 1, last_error: nil}}

      {:error, reason} = error ->
        Logger.warning("DERP rate configuration reload failed: #{inspect(reason)}")
        {error, %{state | failures: state.failures + 1, last_error: reason}}
    end
  catch
    :exit, reason ->
      Logger.warning("DERP rate configuration reload failed: #{inspect(reason)}")

      {{:error, :rate_controller_unavailable},
       %{state | failures: state.failures + 1, last_error: reason}}
  end

  defp install_handler do
    case :os.type() do
      {:unix, _name} ->
        :ok = :os.set_signal(:sighup, :handle)
        handler = {SignalHandler, self()}

        case :gen_event.add_sup_handler(@signal_server, handler, self()) do
          :ok -> {:ok, handler}
          {:error, reason} -> {:error, reason}
        end

      {:win32, _name} ->
        {:ok, nil}
    end
  catch
    :error, reason -> {:error, reason}
    :exit, reason -> {:error, reason}
  end
end
