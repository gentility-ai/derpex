defmodule Derpex.ProberTest do
  use ExUnit.Case, async: true

  alias Derpex.Prober

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
end
