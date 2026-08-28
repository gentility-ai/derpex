# This module implements behavior from Tailscale's DERP prober packet builder.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Prober do
  @moduledoc "Helpers shared by DERP reachability and bandwidth probes."

  alias Derpex.Prober.PacketCache

  @max_packet_size 65_536

  @doc "Returns packet payloads whose combined length is exactly `size`."
  @spec packets_for_size(non_neg_integer()) :: [binary()]
  def packets_for_size(size) when is_integer(size) and size >= 0 and size <= @max_packet_size do
    [:crypto.strong_rand_bytes(size)]
  end

  def packets_for_size(size) when is_integer(size) and size > @max_packet_size do
    PacketCache.fetch(size)
  end
end

defmodule Derpex.Prober.PacketCache do
  @moduledoc false

  use GenServer

  @max_packet_size 65_536

  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, %{}, Keyword.put_new(options, :name, __MODULE__))
  end

  @spec fetch(pos_integer()) :: [binary()]
  def fetch(size), do: GenServer.call(__MODULE__, {:fetch, size}, :infinity)

  @impl true
  def init(cache), do: {:ok, cache}

  @impl true
  def handle_call({:fetch, size}, _from, cache) do
    case cache do
      %{^size => packets} ->
        {:reply, packets, cache}

      %{} ->
        packets = build_packets(size, [])
        {:reply, packets, Map.put(cache, size, packets)}
    end
  end

  defp build_packets(0, packets), do: Enum.reverse(packets)

  defp build_packets(remaining, packets) do
    size = min(remaining, @max_packet_size)
    build_packets(remaining - size, [:crypto.strong_rand_bytes(size) | packets])
  end
end
