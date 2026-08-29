defmodule Derpex.Admission.Gentility.Closer do
  @moduledoc """
  Runs mass peer closes outside the admission controller.

  A reconciliation, an expiry sweep, or a key rotation can close thousands of
  peers at once, and each close is a router operation. Doing that inside the
  controller's call would stall every admission decision behind it, so batches
  are handed here and run concurrently while the controller keeps answering.
  """

  use GenServer

  @default_max_concurrency 32

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc "Closes a batch of node keys without waiting for them."
  @spec close(nil | pid(), [binary()]) :: :ok
  def close(nil, _keys), do: :ok
  def close(_server, []), do: :ok
  def close(server, keys), do: GenServer.cast(server, {:close, keys})

  @doc false
  @spec stop(nil | pid()) :: :ok
  def stop(nil), do: :ok

  def stop(server) do
    GenServer.stop(server, :shutdown, 1_000)
  catch
    :exit, _reason -> :ok
  end

  @impl GenServer
  def init(options) do
    close_peer = Keyword.fetch!(options, :close_peer)

    max_concurrency =
      Keyword.get(options, :max_concurrency, @default_max_concurrency)

    if is_function(close_peer, 1) and is_integer(max_concurrency) and max_concurrency > 0 do
      {:ok, %{close_peer: close_peer, max_concurrency: max_concurrency}}
    else
      {:stop, :invalid_closer}
    end
  end

  @impl GenServer
  def handle_cast({:close, keys}, state) do
    keys
    |> Task.async_stream(state.close_peer,
      max_concurrency: state.max_concurrency,
      ordered: false,
      timeout: :infinity
    )
    |> Stream.run()

    {:noreply, state}
  end
end
