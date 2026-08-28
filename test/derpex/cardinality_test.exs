defmodule Derpex.CardinalityTest do
  use ExUnit.Case, async: true

  alias Derpex.Cardinality

  test "estimates small and medium sender sets while ignoring duplicates and zero" do
    cardinality = Cardinality.new()
    assert Cardinality.estimate(nil) == 0
    assert Cardinality.estimate(cardinality) == 0
    assert Cardinality.insert(cardinality, <<0::256>>) == :ok
    assert Cardinality.estimate(cardinality) == 0

    keys = Enum.map(1..100, &key/1)
    Enum.each(Enum.take(keys, 10), &Cardinality.insert(cardinality, &1))
    assert Cardinality.estimate(cardinality) in 8..12

    Enum.each(Enum.take(keys, 5), &Cardinality.insert(cardinality, &1))
    assert Cardinality.estimate(cardinality) in 8..12

    Enum.each(Enum.drop(keys, 10), &Cardinality.insert(cardinality, &1))
    assert Cardinality.estimate(cardinality) in 85..115
  end

  test "storage is fixed independently of observed key count" do
    assert Cardinality.dimensions() == %{buckets: 1_024, words: 16}
    cardinality = Cardinality.new()
    Enum.each(1..10_000, &Cardinality.insert(cardinality, key(&1)))
    assert Cardinality.dimensions() == %{buckets: 1_024, words: 16}
  end

  defp key(integer), do: :crypto.hash(:sha256, <<integer::unsigned-big-64>>)
end
