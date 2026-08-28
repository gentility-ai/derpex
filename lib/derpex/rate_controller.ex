defmodule Derpex.RateController do
  @moduledoc "Owns live receive-rate configuration and updates every ordinary connection."

  use GenServer

  alias Derpex.RateConfig

  @update_message __MODULE__

  @doc false
  def start_link(options \\ []) do
    case Keyword.fetch(options, :name) do
      {:ok, nil} -> GenServer.start_link(__MODULE__, options)
      {:ok, name} -> GenServer.start_link(__MODULE__, options, name: name)
      :error -> GenServer.start_link(__MODULE__, options, name: __MODULE__)
    end
  end

  @doc "Subscribes an ordinary connection and returns the current applied configuration."
  @spec subscribe(GenServer.server(), pid(), boolean()) :: RateConfig.t()
  def subscribe(server, connection, mesh_peer?) do
    GenServer.call(server, {:subscribe, connection, mesh_peer?})
  end

  @spec subscribe(pid(), boolean()) :: RateConfig.t()
  def subscribe(connection \\ self(), mesh_peer? \\ false) do
    subscribe(__MODULE__, connection, mesh_peer?)
  end

  @doc "Normalizes and publishes a new configuration to all ordinary connections."
  @spec update(GenServer.server(), RateConfig.t()) :: RateConfig.t()
  def update(server, %RateConfig{} = config) do
    GenServer.call(server, {:update, config})
  end

  @spec update(RateConfig.t()) :: RateConfig.t()
  def update(%RateConfig{} = config), do: update(__MODULE__, config)

  @doc "Loads, normalizes, and publishes a JSON configuration file."
  @spec load_and_apply(GenServer.server(), binary()) :: {:ok, RateConfig.t()} | {:error, term()}
  def load_and_apply(server, path) do
    with {:ok, config} <- RateConfig.load(path) do
      {:ok, update(server, config)}
    end
  end

  @spec load_and_apply(binary()) :: {:ok, RateConfig.t()} | {:error, term()}
  def load_and_apply(path), do: load_and_apply(__MODULE__, path)

  @doc "Returns the message shape used for live connection updates."
  @spec update_message(RateConfig.t()) :: {module(), :updated, RateConfig.t()}
  def update_message(%RateConfig{} = config), do: {@update_message, :updated, config}

  @impl true
  def init(options) do
    case initial_config(options) do
      {:ok, config} -> {:ok, %{config: RateConfig.normalize(config), subscribers: %{}}}
      {:error, reason} -> {:stop, {:rate_config, reason}}
    end
  end

  @impl true
  def handle_call({:subscribe, _connection, true}, _from, state) do
    {:reply, %RateConfig{}, state}
  end

  def handle_call({:subscribe, connection, false}, _from, state) do
    subscribers = ensure_subscriber(state.subscribers, connection)
    {:reply, state.config, %{state | subscribers: subscribers}}
  end

  def handle_call({:update, config}, _from, state) do
    config = RateConfig.normalize(config)
    message = update_message(config)
    Enum.each(state.subscribers, fn {connection, _monitor} -> send(connection, message) end)
    {:reply, config, %{state | config: config}}
  end

  @impl true
  def handle_info({:DOWN, monitor, :process, connection, _reason}, state) do
    subscribers =
      case state.subscribers[connection] do
        ^monitor -> Map.delete(state.subscribers, connection)
        _other -> state.subscribers
      end

    {:noreply, %{state | subscribers: subscribers}}
  end

  defp ensure_subscriber(subscribers, connection) do
    Map.put_new_lazy(subscribers, connection, fn -> Process.monitor(connection) end)
  end

  defp initial_config(options) do
    case Keyword.get(options, :path) do
      nil -> {:ok, Keyword.get(options, :config, %RateConfig{})}
      path -> RateConfig.load(path)
    end
  end
end
