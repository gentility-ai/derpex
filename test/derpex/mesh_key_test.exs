defmodule Derpex.MeshKeyTest do
  use ExUnit.Case, async: true

  alias Derpex.MeshKey

  @hex "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

  test "matches the upstream mesh-key parser" do
    assert {:ok, key} = MeshKey.parse("  \n#{@hex}\t")
    assert key == Base.decode16!(@hex, case: :mixed)
    assert MeshKey.parse("badf00d") == {:error, :invalid_mesh_key}
    assert MeshKey.parse(String.duplicate("z", 64)) == {:error, :invalid_mesh_key}
  end

  test "trust requires two configured equal keys" do
    {:ok, key} = MeshKey.parse(@hex)
    other = :binary.copy(<<1>>, 32)

    assert MeshKey.trusted?(key, key)
    refute MeshKey.trusted?(key, other)
    refute MeshKey.trusted?(key, nil)
    refute MeshKey.trusted?(nil, key)
  end
end
