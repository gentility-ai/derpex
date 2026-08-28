# This module implements behavior from Tailscale's dynamic DERP probe planner.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Prober.Plan do
  @moduledoc "Builds the probe inventory implied by a DERP map."

  @type probe :: %{
          optional(:address) => {binary(), integer()},
          optional(:from) => binary(),
          optional(:to) => binary(),
          kind: :tls | :udp4 | :udp6 | :mesh,
          labels: map()
        }

  @type t :: %{nodes: %{binary() => map()}, probes: %{binary() => probe()}}

  @doc "Builds nodes and named probes for the selected DERP regions."
  @spec build(map() | list(), keyword()) :: {:ok, t()} | {:error, {:duplicate_node, binary()}}
  def build(derp_map, options \\ []) do
    regions = regions(derp_map)
    region_filter = Keyword.get(options, :region, "")

    regions
    |> Enum.reject(&skip_region?(&1, region_filter))
    |> Enum.reduce_while({:ok, %{nodes: %{}, probes: %{}}}, fn region, {:ok, plan} ->
      case add_region(plan, region, options) do
        {:ok, plan} -> {:cont, {:ok, plan}}
        {:error, _reason} = error -> {:halt, error}
      end
    end)
  end

  @doc "Returns probe names added, retained, and removed by a new plan."
  @spec diff(t(), t()) :: %{added: MapSet.t(), retained: MapSet.t(), removed: MapSet.t()}
  def diff(previous, current) do
    previous_names = previous.probes |> Map.keys() |> MapSet.new()
    current_names = current.probes |> Map.keys() |> MapSet.new()

    %{
      added: MapSet.difference(current_names, previous_names),
      retained: MapSet.intersection(previous_names, current_names),
      removed: MapSet.difference(previous_names, current_names)
    }
  end

  defp add_region(plan, region, options) do
    nodes = field(region, :nodes, "Nodes", [])

    with {:ok, plan} <- add_nodes(plan, nodes) do
      {:ok,
       Enum.reduce(nodes, plan, fn node, plan ->
         plan
         |> add_node_probes(region, node, options)
         |> add_pair_probes(region, node, nodes, options)
       end)}
    end
  end

  defp add_nodes(plan, nodes) do
    Enum.reduce_while(nodes, {:ok, plan}, fn node, {:ok, plan} ->
      name = field(node, :name, "Name", "")

      if Map.has_key?(plan.nodes, name) do
        {:halt, {:error, {:duplicate_node, name}}}
      else
        {:cont, {:ok, put_in(plan, [:nodes, name], node)}}
      end
    end)
  end

  defp add_node_probes(plan, region, node, options) do
    plan
    |> maybe_add_tls(region, node, Keyword.get(options, :tls, false))
    |> maybe_add_udp(region, node, Keyword.get(options, :udp, false))
  end

  defp maybe_add_tls(plan, _region, _node, false), do: plan

  defp maybe_add_tls(plan, region, node, true) do
    region_code = field(region, :region_code, "RegionCode", "")
    node_name = field(node, :name, "Name", "")
    host_name = field(node, :host_name, "HostName", "")
    port = default_port(field(node, :derp_port, "DERPPort", 0), 443)
    name = "derp/#{region_code}/#{node_name}/tls"
    probe = %{kind: :tls, labels: labels(region, node), address: {host_name, port}}
    put_in(plan, [:probes, name], probe)
  end

  defp maybe_add_udp(plan, _region, _node, false), do: plan

  defp maybe_add_udp(plan, region, node, true) do
    stun_port = field(node, :stun_port, "STUNPort", 0)

    if stun_port == -1 do
      plan
    else
      plan
      |> maybe_add_udp_address(region, node, :udp6, field(node, :ipv6, "IPv6", ""), stun_port)
      |> maybe_add_udp_address(region, node, :udp4, field(node, :ipv4, "IPv4", ""), stun_port)
    end
  end

  defp maybe_add_udp_address(plan, _region, _node, _kind, "", _port), do: plan

  defp maybe_add_udp_address(plan, region, node, kind, address, port) do
    region_code = field(region, :region_code, "RegionCode", "")
    node_name = field(node, :name, "Name", "")
    suffix = if kind == :udp6, do: "udp6", else: "udp"
    name = "derp/#{region_code}/#{node_name}/#{suffix}"
    probe = %{kind: kind, labels: labels(region, node), address: {address, port}}
    put_in(plan, [:probes, name], probe)
  end

  defp add_pair_probes(plan, region, node, nodes, options) do
    if Keyword.get(options, :mesh, false) do
      Enum.reduce(nodes, plan, fn destination, plan ->
        region_code = field(region, :region_code, "RegionCode", "")
        from = field(node, :name, "Name", "")
        to = field(destination, :name, "Name", "")
        name = "derp/#{region_code}/#{from}/#{to}/mesh"
        probe = %{kind: :mesh, labels: labels(region, node), from: from, to: to}
        put_in(plan, [:probes, name], probe)
      end)
    else
      plan
    end
  end

  defp labels(region, node) do
    %{
      "region" => field(region, :region_code, "RegionCode", ""),
      "region_id" => region |> field(:region_id, "RegionID", 0) |> to_string(),
      "hostname" => field(node, :host_name, "HostName", "")
    }
  end

  defp skip_region?(_region, filter) when filter in [nil, ""], do: false

  defp skip_region?(region, filter) do
    code = field(region, :region_code, "RegionCode", "")
    id = region |> field(:region_id, "RegionID", 0) |> to_string()
    filter != code and filter != id
  end

  defp regions(%{regions: regions}), do: region_values(regions)
  defp regions(%{"Regions" => regions}), do: region_values(regions)
  defp regions(regions), do: region_values(regions)

  defp region_values(regions) when is_map(regions), do: Map.values(regions)
  defp region_values(regions) when is_list(regions), do: regions

  defp default_port(0, fallback), do: fallback
  defp default_port(port, _fallback), do: port

  defp field(map, atom_key, json_key, default) do
    cond do
      Map.has_key?(map, atom_key) -> Map.fetch!(map, atom_key)
      Map.has_key?(map, json_key) -> Map.fetch!(map, json_key)
      true -> default
    end
  end
end
