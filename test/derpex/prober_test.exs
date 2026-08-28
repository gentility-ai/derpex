defmodule Derpex.ProberTest do
  use ExUnit.Case, async: true

  alias Derpex.Prober
  alias Derpex.Prober.Plan

  test "matches upstream packet counts, total sizes, and cache behavior" do
    cases = [
      {8, 1, true},
      {8_192, 1, true},
      {65_536, 1, true},
      {65_537, 2, false},
      {500_000, 8, false}
    ]

    for {size, expected_count, expected_unique?} <- cases do
      results = Enum.map(1..5, fn _attempt -> Prober.packets_for_size(size) end)

      assert Enum.all?(results, &(length(&1) == expected_count))

      assert Enum.all?(
               results,
               &(Enum.sum(Enum.map(&1, fn packet -> byte_size(packet) end)) == size)
             )

      unique_hashes =
        results
        |> Enum.map(&:crypto.hash(:sha256, &1))
        |> Enum.uniq()
        |> length()

      assert unique_hashes > 1 == expected_unique?
    end
  end

  test "replans TLS, UDP, and ordered mesh probes as the DERP map changes" do
    first = node_map("n1")
    second = node_map("n2")
    third = node_map("n3")
    regions = %{0 => region(0, "zero", [first, second]), 1 => region(1, "one", [third])}
    options = [region: "zero", tls: true, udp: true, mesh: true]

    assert {:ok, initial} = Plan.build(%{regions: regions}, options)
    assert Map.keys(initial.nodes) |> Enum.sort() == ["n1", "n2"]
    assert map_size(initial.probes) == 10

    fourth = node_map("n4")
    expanded_regions = put_in(regions, [0, :nodes], [first, second, fourth])
    assert {:ok, expanded} = Plan.build(%{regions: expanded_regions}, options)
    assert map_size(expanded.nodes) == 3
    assert map_size(expanded.probes) == 18

    expansion = Plan.diff(initial, expanded)
    assert MapSet.size(expansion.added) == 8
    assert MapSet.size(expansion.retained) == 10
    assert MapSet.size(expansion.removed) == 0

    reduced_regions = put_in(expanded_regions, [0, :nodes], [first])
    assert {:ok, reduced} = Plan.build(%{regions: reduced_regions}, options)
    assert map_size(reduced.nodes) == 1
    assert map_size(reduced.probes) == 4

    reduction = Plan.diff(expanded, reduced)
    assert MapSet.size(reduction.removed) == 14
    assert MapSet.size(reduction.retained) == 4

    assert {:ok, unfiltered} =
             Plan.build(%{regions: reduced_regions},
               region: "",
               tls: true,
               udp: true,
               mesh: true
             )

    assert Map.keys(unfiltered.nodes) |> Enum.sort() == ["n1", "n3"]
    assert map_size(unfiltered.probes) == 8
    assert unfiltered.probes["derp/zero/n1/tls"].address == {"derpn1.tailscale.test", 443}
  end

  test "selects regions by numeric ID and rejects duplicate node names" do
    duplicate = node_map("same")
    regions = [region(17, "lax", [duplicate]), region(18, "sea", [duplicate])]

    assert {:ok, selected} = Plan.build(regions, region: "17", mesh: true)
    assert Map.keys(selected.nodes) == ["same"]

    assert Plan.build(regions, mesh: true) == {:error, {:duplicate_node, "same"}}
  end

  defp region(id, code, nodes), do: %{region_id: id, region_code: code, nodes: nodes}

  defp node_map(name) do
    %{
      name: name,
      region_id: 0,
      host_name: "derp#{name}.tailscale.test",
      ipv4: "1.1.1.1",
      ipv6: "::1"
    }
  end
end
