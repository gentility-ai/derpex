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

    directory = Path.dirname(path)
    assert {:ok, directory_stat} = File.stat(directory)
    assert Bitwise.band(directory_stat.mode, 0o777) == 0o700
    assert Enum.filter(File.ls!(directory), &String.contains?(&1, ".tmp.")) == []
    assert Enum.filter(File.ls!(directory), &String.ends_with?(&1, ".lock")) == []
  end

  @tag :tmp_dir
  test "loading an identity leaves its mtime the day it was made", %{tmp_dir: tmp_dir} do
    # `File.chmod/2` resets the mtime to now — Erlang's `write_file_info` fills
    # the times it is not given — so re-asserting 0600 on every boot made the
    # key look rewritten by each restart, which is the one thing an operator
    # checks when asking whether a relay's identity is stable.
    path = Path.join(tmp_dir, "derpex.key")
    assert {:ok, private_key} = Identity.load_or_create(path)

    made = 1_700_000_000
    File.touch!(path, made)

    assert {:ok, ^private_key} = Identity.load_or_create(path)
    assert File.stat!(path, time: :posix).mtime == made
  end

  @tag :tmp_dir
  test "an identity found loosened is tightened again", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "derpex.key")
    assert {:ok, private_key} = Identity.load_or_create(path)
    File.chmod!(path, 0o644)

    assert {:ok, ^private_key} = Identity.load_or_create(path)
    assert Bitwise.band(File.stat!(path).mode, 0o777) == 0o600
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
