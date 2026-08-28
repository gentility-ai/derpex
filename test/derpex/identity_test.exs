defmodule Derpex.IdentityTest do
  use ExUnit.Case, async: true

  alias Derpex.Crypto
  alias Derpex.Identity

  @tag :tmp_dir
  test "atomically creates a restrictive identity and preserves it", %{tmp_dir: tmp_dir} do
    path = Path.join([tmp_dir, "nested", "derpex.key"])

    assert {:ok, {public_key, private_key}} = Identity.load_or_create_keypair(path)
    assert byte_size(public_key) == 32
    assert byte_size(private_key) == 32
    assert File.read!(path) == private_key
    assert {:ok, ^private_key} = Identity.load_or_create(path)
    assert Crypto.public_key(private_key) == {:ok, public_key}

    assert {:ok, stat} = File.stat(path)
    assert Bitwise.band(stat.mode, 0o777) == 0o600
  end

  @tag :tmp_dir
  test "concurrent creators converge on one persistent key", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "derpex.key")

    keys =
      1..20
      |> Task.async_stream(fn _index -> Identity.load_or_create(path) end,
        max_concurrency: 20,
        ordered: false
      )
      |> Enum.map(fn {:ok, {:ok, key}} -> key end)

    assert length(Enum.uniq(keys)) == 1
    assert File.read!(path) == hd(keys)
  end

  @tag :tmp_dir
  test "never replaces a corrupt identity", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "derpex.key")
    File.write!(path, "short")

    assert Identity.load_or_create(path) == {:error, {:invalid_identity_size, 5}}
    assert File.read!(path) == "short"
  end
end
