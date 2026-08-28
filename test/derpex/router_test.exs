defmodule Derpex.RouterTest do
  use ExUnit.Case, async: false

  alias Derpex.Outbox.Ring
  alias Derpex.Router

  test "successful routing looks up ETS and publishes directly to a bounded ring" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    ring = Ring.new(2)

    assert Router.register(destination, self(), ring) == :ok
    assert Router.route(source, destination, "packet") == {:ok, :wake}
    assert Ring.take(ring) == {:ok, {:recv_packet, source, "packet"}}
    assert Router.unregister(destination, self()) == :ok
    assert Router.route(source, destination, "packet") == {:dropped, :unknown_destination}
  end

  test "ordinary and discovery packets use independent bounded rings" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    ordinary = Ring.new(1)
    disco = Ring.new(1)
    lifecycle = Ring.new(1)
    disco_packet = <<0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC>> <> :binary.copy(<<0>>, 56)

    assert Router.register(destination, self(), ordinary, disco, lifecycle) == :ok
    assert Router.route(source, destination, "ordinary") == {:ok, :wake}
    assert Router.route(source, destination, disco_packet) == {:ok, :wake}
    assert Ring.take(ordinary) == {:ok, {:recv_packet, source, "ordinary"}}
    assert Ring.take(disco) == {:ok, {:recv_packet, source, disco_packet}}
    assert Router.unregister(destination, self()) == :ok
  end

  test "an old duplicate disconnect cannot delete the newer active route" do
    key = :crypto.strong_rand_bytes(32)
    old = spawn(fn -> Process.sleep(:infinity) end)
    newer = spawn(fn -> Process.sleep(:infinity) end)
    old_ring = Ring.new(1)
    new_ring = Ring.new(1)

    assert Router.register(key, old, old_ring) == :ok
    assert Router.register(key, newer, new_ring) == :ok
    assert Router.unregister(key, old) == :ok
    assert Router.route(:crypto.strong_rand_bytes(32), key, "new") == {:ok, :wake}
    assert Ring.take(new_ring) |> elem(0) == :ok
    assert Ring.take(old_ring) == :empty

    assert Router.register(key, old, old_ring) == :ok
    assert Router.register(key, newer, new_ring) == :ok
    assert Router.unregister(key, newer) == :ok
    assert Router.route(:crypto.strong_rand_bytes(32), key, "promoted") == {:ok, :wake}
    assert {:ok, {:recv_packet, _source, "promoted"}} = Ring.take(old_ring)
    assert Ring.take(new_ring) == :empty

    Process.exit(old, :kill)
    Process.exit(newer, :kill)
  end

  test "the last source disconnect notifies destinations that received its packets" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    source_connection = spawn(fn -> Process.sleep(:infinity) end)
    destination_connection = spawn(fn -> Process.sleep(:infinity) end)
    source_ring = Ring.new(1)
    destination_ring = Ring.new(1)
    destination_control = Ring.new(1)

    assert Router.register(source, source_connection, source_ring) == :ok

    assert Router.register(
             destination,
             destination_connection,
             destination_ring,
             destination_control
           ) == :ok

    assert Router.note_send(source, destination_connection, destination_control) == :ok
    assert Router.unregister(source, source_connection) == :ok
    assert Ring.take(destination_control) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination, destination_connection) == :ok
    Process.exit(source_connection, :kill)
    Process.exit(destination_connection, :kill)
  end

  test "the most recently active duplicate receives packets" do
    key = :crypto.strong_rand_bytes(32)
    source = :crypto.strong_rand_bytes(32)
    first = spawn(fn -> Process.sleep(:infinity) end)
    second = spawn(fn -> Process.sleep(:infinity) end)
    first_ring = Ring.new(2)
    second_ring = Ring.new(2)

    assert Router.register(key, first, first_ring) == :ok
    assert Router.register(key, second, second_ring) == :ok
    assert Router.route(source, key, "newest") == {:ok, :wake}
    assert Ring.take(second_ring) == {:ok, {:recv_packet, source, "newest"}}
    assert Ring.take(first_ring) == :empty

    assert Router.note_activity(key, first) == :ok
    assert Router.route(source, key, "active") == {:ok, :wake}
    assert Ring.take(first_ring) == {:ok, {:recv_packet, source, "active"}}
    assert Ring.take(second_ring) == :empty

    assert Router.unregister(key, first) == :ok
    assert Router.unregister(key, second) == :ok
    Process.exit(first, :kill)
    Process.exit(second, :kill)
  end
end
