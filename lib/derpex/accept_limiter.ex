defmodule Derpex.AcceptLimiter do
  @moduledoc "Shared token bucket checked before allocating per-connection DERP state."

  use GenServer

  alias Derpex.RateLimiter

  @doc false
  def start_link(options \\ []) do
    case Keyword.fetch(options, :name) do
      {:ok, nil} -> GenServer.start_link(__MODULE__, options)
      {:ok, name} -> GenServer.start_link(__MODULE__, options, name: name)
      :error -> GenServer.start_link(__MODULE__, options, name: __MODULE__)
    end
  end

  @doc "Consumes one shared accept token, or allows immediately when disabled."
  @spec allow?(GenServer.server() | nil) :: boolean()
  def allow?(server \\ __MODULE__)

  def allow?(nil), do: true
  def allow?(server), do: GenServer.call(server, :allow)

  @doc "Replaces the bucket live; nil disables limiting."
  @spec update(GenServer.server(), nil | {number(), pos_integer()}) :: :ok
  def update(server, config), do: GenServer.call(server, {:update, config})

  @spec update(nil | {number(), pos_integer()}) :: :ok
  def update(config), do: update(__MODULE__, config)

  @impl true
  def init(options) do
    {:ok, limiter(Keyword.get(options, :config))}
  end

  @impl true
  def handle_call(:allow, _from, nil), do: {:reply, true, nil}

  def handle_call(:allow, _from, limiter) do
    {allowed?, limiter} = RateLimiter.allow(limiter)
    {:reply, allowed?, limiter}
  end

  def handle_call({:update, config}, _from, _limiter), do: {:reply, :ok, limiter(config)}

  defp limiter(nil), do: nil
  defp limiter({rate, burst}), do: RateLimiter.new(rate, burst)
end
