defmodule Derpex.Admission.Gentility.UnknownLane do
  @moduledoc """
  The rate half of the unknown lane: a global token bucket and one bucket per
  source, for authorizations of keys that hold no cached lease here.

  A made-up key costs an attacker nothing, and every new connection is a call
  to Gentility, so keys this relay does not know are rationed apart from the
  ones it does. The controller holds the lane's in-flight bound; a call that
  has a slot then takes a token here. A call is admitted only when its source
  and the lane both have a token, and a source's token is spent only when the
  lane's is too, so a refused call costs the lane nothing.

  A source is keyed by its allocation, as `Derpex.AcceptLimiter.source_key/2`
  keys it. The per-source table is bounded: at the bound, sources whose bucket
  has refilled are dropped (they hold nothing a new bucket would not), and if
  none has, the one touched longest ago is.

  Rates are written `rate/burst`: `20/40` is twenty a second with a burst of
  forty.
  """

  use GenServer

  alias Derpex.AcceptLimiter
  alias Derpex.Clock
  alias Derpex.RateLimiter

  @default_max_sources 16_384
  @default_ipv6_prefix 64

  @type rate :: {number(), pos_integer()}

  @doc "Parses a `rate/burst` setting."
  @spec parse_rate(binary()) :: {:ok, rate()} | {:error, :invalid_rate}
  def parse_rate(text) when is_binary(text) do
    with [rate_text, burst_text] <- String.split(text, "/", parts: 2),
         {:ok, rate} <- number(rate_text),
         {burst, ""} when burst > 0 <- Integer.parse(burst_text) do
      {:ok, {rate, burst}}
    else
      _invalid -> {:error, :invalid_rate}
    end
  end

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc "Takes one token for a call from `source`, or refuses it."
  @spec take(pid(), nil | :inet.ip_address()) :: :ok | {:error, :admission_overloaded}
  def take(server, source) do
    GenServer.call(server, {:take, source})
  catch
    :exit, _reason -> {:error, :admission_overloaded}
  end

  @impl GenServer
  def init(options) do
    {rate, burst} = Keyword.fetch!(options, :rate)
    per_source = Keyword.fetch!(options, :per_source_rate)
    clock = Keyword.get(options, :clock, Clock)

    {:ok,
     %{
       clock: clock,
       global: RateLimiter.new(rate, burst),
       per_source: per_source,
       refill_ms: refill_ms(per_source),
       sources: %{},
       max_sources: Keyword.get(options, :max_sources, @default_max_sources),
       ipv6_prefix: Keyword.get(options, :ipv6_prefix, @default_ipv6_prefix)
     }}
  end

  @impl GenServer
  def handle_call({:take, source}, _from, state) do
    now = state.clock.monotonic_time(:millisecond)
    key = source_key(source, state.ipv6_prefix)
    {bucket, _touched} = Map.get_lazy(state.sources, key, fn -> {new_bucket(state), now} end)

    case RateLimiter.allow(bucket, now) do
      {false, bucket} ->
        {:reply, {:error, :admission_overloaded}, put_source(state, key, bucket, now)}

      {true, taken} ->
        case RateLimiter.allow(state.global, now) do
          {true, global} ->
            {:reply, :ok, %{put_source(state, key, taken, now) | global: global}}

          {false, global} ->
            {:reply, {:error, :admission_overloaded}, %{state | global: global}}
        end
    end
  end

  defp new_bucket(%{per_source: {rate, burst}}), do: RateLimiter.new(rate, burst)

  defp put_source(state, key, bucket, now) do
    state =
      if Map.has_key?(state.sources, key) or map_size(state.sources) < state.max_sources,
        do: state,
        else: make_room(state, now)

    %{state | sources: Map.put(state.sources, key, {bucket, now})}
  end

  defp make_room(state, now) do
    sources =
      Map.reject(state.sources, fn {_key, {_bucket, touched}} ->
        now - touched >= state.refill_ms
      end)

    sources =
      if map_size(sources) < state.max_sources do
        sources
      else
        {oldest, _entry} = Enum.min_by(sources, fn {_key, {_bucket, touched}} -> touched end)
        Map.delete(sources, oldest)
      end

    %{state | sources: sources}
  end

  # The time an emptied bucket takes to fill again, after which it holds
  # nothing a fresh one would not.
  defp refill_ms({rate, burst}) when rate > 0, do: ceil(burst * 1_000 / rate)

  defp source_key(nil, _prefix), do: :no_source

  defp source_key(source, prefix) when tuple_size(source) in [4, 8],
    do: AcceptLimiter.source_key(source, prefix)

  defp source_key(_source, _prefix), do: :no_source

  defp number(text) do
    case Float.parse(text) do
      {rate, ""} when rate > 0 -> {:ok, rate}
      _invalid -> :error
    end
  end
end
