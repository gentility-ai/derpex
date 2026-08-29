defmodule Derpex.RouterTest do
  use ExUnit.Case, async: false

  alias Derpex.Outbox.Ring
  alias Derpex.Router
  alias Derpex.Router.ReversePaths

  test "successful routing looks up ETS and publishes directly to a bounded ring" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    ring = Ring.new(2)

    assert Router.register(destination, self(), ring) == :ok
    assert Router.consistency_check() == :ok
    assert %{current_connections: 1, clients_local: 1} = Router.stats()
    assert Router.route(source, destination, "packet") == {:ok, :wake}
    assert Ring.take(ring) == {:ok, {:recv_packet, source, "packet"}}
    assert Router.unregister(destination, self()) == :ok
    assert Router.consistency_check() == :ok
    assert Router.route(source, destination, "packet") == {:dropped, :unknown_destination}
  end

  test "exposes only live authenticated endpoint-to-key mappings for traffic diagnostics" do
    key = :crypto.strong_rand_bytes(32)
    ring = Ring.new(1)

    presence = %{
      ip: <<0::80, 0xFFFF::16, 192, 0, 2, 8>>,
      port: 58_145,
      flags: 0x01,
      app_name: ""
    }

    on_exit(fn -> Router.unregister(key, self()) end)

    assert :ok = Router.register(key, self(), ring, ring, ring, presence)
    assert Router.debug_client_keys()[{{192, 0, 2, 8}, 58_145}] == key

    assert :ok = Router.unregister(key, self())
    refute Map.has_key?(Router.debug_client_keys(), {{192, 0, 2, 8}, 58_145})
  end

  test "regional forwarders preserve first-seen priority and local routes win" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    first = Ring.new(8)
    second = Ring.new(8)
    local = Ring.new(2)

    assert Router.add_forwarder(destination, :first, first) == :ok
    assert Router.add_forwarder(destination, :second, second) == :ok
    assert Router.add_forwarder(destination, :second, second) == :ok

    assert_enqueued(Router.route(source, destination, "first"))

    assert Ring.take(first) ==
             {:ok, {:forward_packet, source, destination, "first"}}

    assert Ring.take(second) == :empty

    assert Router.remove_forwarder(destination, :not_registered) == :ok
    assert_enqueued(Router.route(source, destination, "still first"))

    assert Ring.take(first) ==
             {:ok, {:forward_packet, source, destination, "still first"}}

    assert Router.remove_forwarder(destination, :first) == :ok
    assert_enqueued(Router.route(source, destination, "second"))

    assert Ring.take(second) ==
             {:ok, {:forward_packet, source, destination, "second"}}

    assert Router.register(destination, self(), local) == :ok
    assert_enqueued(Router.route(source, destination, "local"))
    assert Ring.take(local) == {:ok, {:recv_packet, source, "local"}}
    assert Ring.take(second) == :empty

    assert Router.unregister(destination, self()) == :ok

    assert Router.route_local(source, destination, "do not loop") ==
             {:dropped, :unknown_destination}

    assert Ring.take(second) == :empty
    assert_enqueued(Router.route(source, destination, "remote again"))

    assert Ring.take(second) ==
             {:ok, {:forward_packet, source, destination, "remote again"}}

    assert Router.remove_forwarder(destination, :second) == :ok
    assert Router.route(source, destination, "gone") == {:dropped, :unknown_destination}
  end

  test "routing remains available while multiple forwarders change concurrently" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    first = Ring.new(5_000)
    second = Ring.new(5_000)
    third = Ring.new(5_000)

    assert Router.add_forwarder(destination, :first, first) == :ok

    mutator =
      Task.async(fn ->
        Enum.each(1..500, fn _iteration ->
          :ok = Router.add_forwarder(destination, :second, second)
          :ok = Router.add_forwarder(destination, :third, third)
          :ok = Router.remove_forwarder(destination, :second)
          :ok = Router.remove_forwarder(destination, :first)
          :ok = Router.add_forwarder(destination, :first, first)
          :ok = Router.remove_forwarder(destination, :third)
        end)
      end)

    Enum.each(1..5_000, fn sequence ->
      assert Router.route(source, destination, Integer.to_string(sequence)) in [
               {:ok, :wake},
               {:ok, :coalesced}
             ]
    end)

    Task.await(mutator, 5_000)

    assert count_ring(first) + count_ring(second) + count_ring(third) == 5_000

    assert Router.remove_forwarder(destination, :first) == :ok
    assert Router.remove_forwarder(destination, :second) == :ok
    assert Router.remove_forwarder(destination, :third) == :ok
  end

  test "a crashed forwarding process is evicted and the next path is promoted" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    first_process = spawn(fn -> Process.sleep(:infinity) end)
    second_process = spawn(fn -> Process.sleep(:infinity) end)
    first = Ring.new(1)
    second = Ring.new(1)

    assert Router.add_forwarder(destination, first_process, first) == :ok
    assert Router.add_forwarder(destination, second_process, second) == :ok
    Process.exit(first_process, :kill)

    assert_eventually(fn -> Router.forwarder_count(destination) == 1 end)
    assert_enqueued(Router.route(source, destination, "promoted"))

    assert Ring.take(second) ==
             {:ok, {:forward_packet, source, destination, "promoted"}}

    Process.exit(second_process, :kill)

    assert_eventually(fn -> Router.forwarder_count(destination) == 0 end)
    assert Router.route(source, destination, "gone") == {:dropped, :unknown_destination}
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

  test "forgetting a destination costs its own reverse paths, not the whole table" do
    sources = for _index <- 1..100, do: :crypto.strong_rand_bytes(32)
    connections = for _index <- 1..2_000, do: spawn(fn -> Process.sleep(:infinity) end)
    shared_ring = Ring.new(1)

    on_exit(fn ->
      Enum.each(connections, &ReversePaths.forget_connection/1)
      Enum.each(connections, &Process.exit(&1, :kill))
    end)

    for connection <- connections, source <- sources do
      assert Router.note_send(source, connection, shared_ring) == :ok
    end

    [target | _others] = connections
    target_key = :crypto.strong_rand_bytes(32)
    assert Router.register(target_key, target, shared_ring) == :ok

    {elapsed, :ok} = :timer.tc(fn -> Router.unregister(target_key, target) end)

    assert elapsed < 2_000,
           "unregister scanned the whole reverse table: #{elapsed} us"
  end

  test "clearing one destination's reverse paths leaves the others subscribed" do
    source = :crypto.strong_rand_bytes(32)
    first_key = :crypto.strong_rand_bytes(32)
    second_key = :crypto.strong_rand_bytes(32)
    source_connection = spawn(fn -> Process.sleep(:infinity) end)
    first = spawn(fn -> Process.sleep(:infinity) end)
    second = spawn(fn -> Process.sleep(:infinity) end)
    first_ring = Ring.new(1)
    second_ring = Ring.new(1)

    assert Router.register(source, source_connection, Ring.new(1)) == :ok
    assert Router.register(first_key, first, first_ring) == :ok
    assert Router.register(second_key, second, second_ring) == :ok
    assert Router.note_send(source, first, first_ring) == :ok
    assert Router.note_send(source, second, second_ring) == :ok

    assert Router.unregister(first_key, first) == :ok
    assert Router.unregister(source, source_connection) == :ok

    assert Ring.take(second_ring) == {:ok, {:peer_gone, source, 0x00}}
    assert Ring.take(first_ring) == :empty

    assert Router.unregister(second_key, second) == :ok
    Enum.each([source_connection, first, second], &Process.exit(&1, :kill))
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

  test "closing a peer asks every duplicate connection to stop" do
    key = :crypto.strong_rand_bytes(32)
    first = reporting_connection(self())
    second = reporting_connection(self())
    first_ring = Ring.new(1)
    second_ring = Ring.new(1)

    assert Router.register(key, first, first_ring) == :ok
    assert Router.register(key, second, second_ring) == :ok
    assert Router.close_peer(key) == 2
    assert_receive {:connection_message, ^first, {:derpex_close_peer, ^key}}
    assert_receive {:connection_message, ^second, {:derpex_close_peer, ^key}}
    assert Router.close_peer(:crypto.strong_rand_bytes(32)) == 0

    Process.exit(first, :kill)
    Process.exit(second, :kill)
  end

  test "trusted watchers receive an active snapshot and future presence changes" do
    first_key = :crypto.strong_rand_bytes(32)
    second_key = :crypto.strong_rand_bytes(32)
    first_connection = spawn(fn -> Process.sleep(:infinity) end)
    second_connection = spawn(fn -> Process.sleep(:infinity) end)
    watcher = spawn(fn -> Process.sleep(:infinity) end)
    first_ring = Ring.new(4)
    second_ring = Ring.new(4)
    watcher_ring = Ring.new(8)

    first_presence = %{
      ip: <<0::80, 0xFFFF::16, 127, 0, 0, 1>>,
      port: 12_345,
      flags: 0x01,
      app_name: "test-app"
    }

    second_presence = %{
      ip: <<0::128>>,
      port: 23_456,
      flags: 0x06,
      app_name: ""
    }

    assert Router.register(
             first_key,
             first_connection,
             first_ring,
             first_ring,
             first_ring,
             first_presence
           ) == :ok

    assert Router.watch(watcher, watcher_ring) == :ok

    assert Ring.take(watcher_ring) ==
             {:ok,
              {:peer_present, first_key, first_presence.ip, first_presence.port,
               first_presence.flags, first_presence.app_name}}

    assert Router.register(
             second_key,
             second_connection,
             second_ring,
             second_ring,
             second_ring,
             second_presence
           ) == :ok

    assert Ring.take(watcher_ring) ==
             {:ok,
              {:peer_present, second_key, second_presence.ip, second_presence.port,
               second_presence.flags, second_presence.app_name}}

    assert Router.unregister(second_key, second_connection) == :ok
    assert Ring.take(watcher_ring) == {:ok, {:peer_gone, second_key, 0x00}}

    assert Router.unregister(first_key, first_connection) == :ok
    Process.exit(first_connection, :kill)
    Process.exit(second_connection, :kill)
    Process.exit(watcher, :kill)
  end

  test "a vanished ring owner becomes a drop instead of crashing topology state" do
    parent = self()

    owner =
      spawn(fn ->
        send(parent, {:stale_ring, Ring.new(1)})
      end)

    monitor = Process.monitor(owner)
    assert_receive {:stale_ring, stale_ring}
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}

    source = :crypto.strong_rand_bytes(32)
    source_connection = spawn(fn -> Process.sleep(:infinity) end)
    source_ring = Ring.new(1)

    assert Router.register(source, source_connection, source_ring) == :ok
    assert Router.note_send(source, self(), stale_ring) == :ok
    assert Router.unregister(source, source_connection) == :ok
    assert Process.alive?(Process.whereis(Router))

    Process.exit(source_connection, :kill)
  end

  defp reporting_connection(parent) do
    spawn(fn ->
      receive do
        message ->
          send(parent, {:connection_message, self(), message})
          Process.sleep(:infinity)
      end
    end)
  end

  defp count_ring(ring, count \\ 0) do
    case Ring.take(ring) do
      {:ok, _message} -> count_ring(ring, count + 1)
      :empty -> count
    end
  end

  defp assert_enqueued(result) do
    assert result in [{:ok, :wake}, {:ok, :coalesced}]
  end

  defp assert_eventually(assertion, attempts \\ 100)

  defp assert_eventually(assertion, attempts) when attempts > 0 do
    if assertion.() do
      :ok
    else
      Process.sleep(2)
      assert_eventually(assertion, attempts - 1)
    end
  end

  defp assert_eventually(_assertion, 0), do: flunk("condition did not become true")
end
