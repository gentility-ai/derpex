defmodule Derpex.Admission.Gentility.CacheWriter do
  @moduledoc """
  Serializes durable admission-cache writes off the controller process.

  The controller encodes its own snapshot, so what reaches disk is always a
  consistent view of one moment, but the write and its fsync happen here. At
  most one write is in flight; snapshots that arrive while it runs replace one
  another, so a burst of lease churn costs one write rather than a queue of
  them. Revocation writes are synchronous because their durability is what
  bounds a revoked node's reconnection window.
  """

  use GenServer

  alias Derpex.Admission.Gentility.Cache

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc "Queues a snapshot, replacing any snapshot still waiting to be written."
  @spec write(GenServer.server(), iodata()) :: :ok
  def write(server, data), do: GenServer.cast(server, {:write, data})

  @doc "Writes a snapshot and waits for it to reach disk."
  @spec write_sync(GenServer.server(), iodata(), timeout()) :: :ok | {:error, term()}
  def write_sync(server, data, timeout) do
    GenServer.call(server, {:write, data}, timeout)
  catch
    :exit, reason -> {:error, {:cache_writer, reason}}
  end

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
    path = Keyword.fetch!(options, :path)
    owner = Keyword.fetch!(options, :owner)

    if is_binary(path) and path != "" and is_pid(owner) do
      {:ok, %{path: path, owner: owner, pending: nil}}
    else
      {:stop, :invalid_cache_writer}
    end
  end

  @impl GenServer
  def handle_call({:write, data}, _from, state) do
    {:reply, Cache.write(state.path, data), %{state | pending: nil}}
  end

  @impl GenServer
  def handle_cast({:write, data}, state) do
    send(self(), :flush)
    {:noreply, %{state | pending: data}}
  end

  @impl GenServer
  def handle_info(:flush, %{pending: nil} = state), do: {:noreply, state}

  def handle_info(:flush, state) do
    result = Cache.write(state.path, state.pending)
    send(state.owner, {__MODULE__, :write_result, result})
    {:noreply, %{state | pending: nil}}
  end
end
