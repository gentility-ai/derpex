# This module implements behavior from Tailscale's cmd/derper bootstrap DNS cache.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.BootstrapDNS do
  @moduledoc "Published and selectively unpublished bootstrap DNS responses."

  import Bitwise
  use GenServer

  @mask64 0xFFFF_FFFF_FFFF_FFFF
  @mul_hi 2_549_297_995_355_413_924
  @mul_lo 4_865_540_595_714_422_341
  @inc_hi 6_364_136_223_846_793_005
  @inc_lo 1_442_695_040_888_963_407
  @cheap_mul 0xDA94_2042_E4DD_58B5
  @low53_mask (1 <<< 53) - 1
  @float53 1 <<< 53

  @type ip_map :: %{optional(binary()) => [binary()]}
  @type metrics :: %{
          requests: non_neg_integer(),
          published_hits: non_neg_integer(),
          published_misses: non_neg_integer(),
          unpublished_hits: non_neg_integer(),
          unpublished_misses: non_neg_integer(),
          unpublished_percent_misses: non_neg_integer(),
          queried_domains: non_neg_integer()
        }

  def start_link(options \\ []) do
    server_options =
      case Keyword.get(options, :name, __MODULE__) do
        nil -> []
        name -> [name: name]
      end

    GenServer.start_link(__MODULE__, options, server_options)
  end

  @doc "Atomically replaces both DNS caches."
  @spec replace(GenServer.server(), ip_map(), ip_map(), %{optional(binary()) => float()}) :: :ok
  def replace(server \\ __MODULE__, published, unpublished, percentages) do
    GenServer.call(server, {:replace, published, unpublished, percentages})
  end

  @doc "Looks up one optional hidden name, falling back to the complete public map."
  @spec lookup(GenServer.server(), binary(), binary()) :: ip_map()
  def lookup(server \\ __MODULE__, query, remote_address) do
    GenServer.call(server, {:lookup, query, remote_address})
  end

  @doc "Returns the current request and cache metrics."
  @spec metrics(GenServer.server()) :: metrics()
  def metrics(server \\ __MODULE__), do: GenServer.call(server, :metrics)

  @doc "Resets counters and the bounded queried-domain set."
  @spec reset_metrics(GenServer.server()) :: :ok
  def reset_metrics(server \\ __MODULE__), do: GenServer.call(server, :reset_metrics)

  @doc "Matches Go's deterministic remote-IP percentage selection."
  @spec remote_address_matches_percent(binary(), float()) :: boolean()
  def remote_address_matches_percent(_remote_address, percent) when percent == 0, do: false
  def remote_address_matches_percent(_remote_address, percent) when percent == 1, do: true

  def remote_address_matches_percent(remote_address, percent)
      when is_binary(remote_address) and is_number(percent) and percent > 0 and percent < 1 do
    case remote_ip(remote_address) do
      {:ok, address} ->
        if loopback?(address) do
          :rand.uniform() < percent
        else
          <<seed1::unsigned-little-64, seed2::unsigned-little-64>> = address_bytes(address)
          percent > pcg_float64(seed1, seed2)
        end

      :error ->
        false
    end
  end

  @impl true
  def init(options) do
    {:ok,
     new_state(
       Keyword.get(options, :published, %{}),
       Keyword.get(options, :unpublished, %{}),
       Keyword.get(options, :percentages, %{})
     )}
  end

  @impl true
  def handle_call({:replace, published, unpublished, percentages}, _from, state) do
    {:reply, :ok,
     %{state | published: published, unpublished: unpublished, percentages: percentages}}
  end

  def handle_call({:lookup, query, remote_address}, _from, state) do
    state = %{state | requests: state.requests + 1}
    {response, state} = lookup_query(state, query, remote_address)
    {:reply, response, state}
  end

  def handle_call(:metrics, _from, state), do: {:reply, metrics_from(state), state}

  def handle_call(:reset_metrics, _from, state) do
    state =
      state
      |> Map.merge(zero_metrics())
      |> Map.put(:queried_domains, MapSet.new())

    {:reply, :ok, state}
  end

  defp lookup_query(state, "", _remote_address), do: {state.published, state}

  defp lookup_query(state, query, remote_address) do
    state = note_query(state, query)

    case Map.get(state.unpublished, query, []) do
      [_ip | _rest] = addresses ->
        state = %{state | unpublished_hits: state.unpublished_hits + 1}
        percentage = Map.get(state.percentages, query, 0.0)

        if remote_address_matches_percent(remote_address, percentage) do
          {%{query => addresses}, state}
        else
          state = %{
            state
            | unpublished_percent_misses: state.unpublished_percent_misses + 1
          }

          published_fallback(state, query)
        end

      [] ->
        published_fallback(state, query)
    end
  end

  defp published_fallback(state, query) do
    state =
      case Map.fetch(state.published, query) do
        {:ok, [_ip | _rest]} ->
          %{state | published_hits: state.published_hits + 1}

        {:ok, []} ->
          %{state | published_misses: state.published_misses + 1}

        :error ->
          %{state | unpublished_misses: state.unpublished_misses + 1}
      end

    {state.published, state}
  end

  defp note_query(state, query) do
    queried_domains = MapSet.put(state.queried_domains, query)

    queried_domains =
      if MapSet.size(queried_domains) > 500, do: MapSet.new(), else: queried_domains

    %{state | queried_domains: queried_domains}
  end

  defp new_state(published, unpublished, percentages) do
    zero_metrics()
    |> Map.merge(%{
      published: published,
      unpublished: unpublished,
      percentages: percentages,
      queried_domains: MapSet.new()
    })
  end

  defp zero_metrics do
    %{
      requests: 0,
      published_hits: 0,
      published_misses: 0,
      unpublished_hits: 0,
      unpublished_misses: 0,
      unpublished_percent_misses: 0
    }
  end

  defp metrics_from(state) do
    state
    |> Map.take(Map.keys(zero_metrics()))
    |> Map.put(:queried_domains, MapSet.size(state.queried_domains))
  end

  defp remote_ip(remote_address) do
    uri = URI.parse("tcp://" <> remote_address)

    with host when is_binary(host) <- uri.host,
         {:ok, address} <- :inet.parse_address(String.to_charlist(host)) do
      {:ok, address}
    else
      _invalid -> :error
    end
  end

  defp loopback?({127, _b, _c, _d}), do: true
  defp loopback?({0, 0, 0, 0, 0, 0, 0, 1}), do: true
  defp loopback?(_address), do: false

  defp address_bytes({a, b, c, d}), do: <<0::80, 0xFFFF::16, a, b, c, d>>

  defp address_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  defp pcg_float64(seed1, seed2) do
    {hi, lo} = pcg_next(seed1, seed2)
    value = dxsm(hi, lo)
    (value &&& @low53_mask) / @float53
  end

  defp pcg_next(hi, lo) do
    product = lo * @mul_lo
    next_lo = product &&& @mask64

    next_hi =
      ((product >>> 64) + hi * @mul_lo + lo * @mul_hi)
      |> band(@mask64)

    sum = next_lo + @inc_lo
    carry = if sum > @mask64, do: 1, else: 0
    next_lo = sum &&& @mask64
    next_hi = next_hi + @inc_hi + carry &&& @mask64
    {next_hi, next_lo}
  end

  defp dxsm(hi, lo) do
    hi
    |> bxor(hi >>> 32)
    |> multiply64(@cheap_mul)
    |> then(&bxor(&1, &1 >>> 48))
    |> multiply64(lo ||| 1)
  end

  defp multiply64(value, multiplier), do: value * multiplier &&& @mask64
end
