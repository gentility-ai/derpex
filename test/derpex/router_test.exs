defmodule Derpex.RouterTest do
  use ExUnit.Case, async: false

  alias Derpex.Metrics
  alias Derpex.Outbox
  alias Derpex.Outbox.LifecycleQueue
  alias Derpex.Outbox.Lock
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

  test "the last local route leaving while a forwarder remains keeps the peer present" do
    source = :crypto.strong_rand_bytes(32)
    destination_key = :crypto.strong_rand_bytes(32)
    source_connection = spawn(fn -> Process.sleep(:infinity) end)
    destination = spawn(fn -> Process.sleep(:infinity) end)
    destination_ring = Ring.new(2)
    forwarder_ring = Ring.new(2)

    assert Router.register(source, source_connection, Ring.new(1)) == :ok
    assert Router.register(destination_key, destination, destination_ring) == :ok
    assert Router.add_forwarder(source, :peer_relay, forwarder_ring) == :ok
    assert Router.note_send(source, destination, destination_ring) == :ok

    assert Router.unregister(source, source_connection) == :ok
    assert Ring.take(destination_ring) == :empty

    assert Router.remove_forwarder(source, :peer_relay) == :ok
    assert Ring.take(destination_ring) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination_key, destination) == :ok
    Enum.each([source_connection, destination], &Process.exit(&1, :kill))
  end

  test "the last forwarder leaving with no local route announces the peer as gone" do
    source = :crypto.strong_rand_bytes(32)
    destination_key = :crypto.strong_rand_bytes(32)
    destination = spawn(fn -> Process.sleep(:infinity) end)
    destination_ring = Ring.new(2)
    forwarder_ring = Ring.new(2)

    assert Router.register(destination_key, destination, destination_ring) == :ok
    assert Router.add_forwarder(source, :peer_relay, forwarder_ring) == :ok
    assert Router.note_send(source, destination, destination_ring) == :ok

    assert Router.remove_forwarder(source, :peer_relay) == :ok
    assert Ring.take(destination_ring) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination_key, destination) == :ok
    Process.exit(destination, :kill)
  end

  test "the last forwarder leaving while a local route remains keeps the peer present" do
    source = :crypto.strong_rand_bytes(32)
    destination_key = :crypto.strong_rand_bytes(32)
    source_connection = spawn(fn -> Process.sleep(:infinity) end)
    destination = spawn(fn -> Process.sleep(:infinity) end)
    destination_ring = Ring.new(2)
    forwarder_ring = Ring.new(2)

    assert Router.register(source, source_connection, Ring.new(1)) == :ok
    assert Router.register(destination_key, destination, destination_ring) == :ok
    assert Router.add_forwarder(source, :peer_relay, forwarder_ring) == :ok
    assert Router.note_send(source, destination, destination_ring) == :ok

    assert Router.remove_forwarder(source, :peer_relay) == :ok
    assert Ring.take(destination_ring) == :empty

    assert Router.unregister(source, source_connection) == :ok
    assert Ring.take(destination_ring) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination_key, destination) == :ok
    Enum.each([source_connection, destination], &Process.exit(&1, :kill))
  end

  test "removing one of two forwarders keeps the peer present and still routed" do
    source = :crypto.strong_rand_bytes(32)
    sender = :crypto.strong_rand_bytes(32)
    destination_key = :crypto.strong_rand_bytes(32)
    destination = spawn(fn -> Process.sleep(:infinity) end)
    destination_ring = Ring.new(2)
    first = Ring.new(2)
    second = Ring.new(2)

    assert Router.register(destination_key, destination, destination_ring) == :ok
    assert Router.add_forwarder(source, :first, first) == :ok
    assert Router.add_forwarder(source, :second, second) == :ok
    assert Router.note_send(source, destination, destination_ring) == :ok

    before = Metrics.snapshot()[:remove_forwarder_other]
    assert Router.remove_forwarder(source, :first) == :ok

    assert Ring.take(destination_ring) == :empty
    assert Router.forwarder_count(source) == 1
    assert Metrics.snapshot()[:remove_forwarder_other] == before

    assert_enqueued(Router.route(sender, source, "still routed"))
    assert Ring.take(second) == {:ok, {:forward_packet, sender, source, "still routed"}}
    assert Ring.take(first) == :empty

    assert Router.remove_forwarder(source, :second) == :ok
    assert Ring.take(destination_ring) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination_key, destination) == :ok
    Process.exit(destination, :kill)
  end

  # Go's `handleFrameSendPacket` increments `packetsForwardedOut` before it calls
  # `ForwardPacket`, so the counter measures forwarding attempts, not deliveries.
  test "forwarding counts the attempt even when the forwarder ring refuses it" do
    source = :crypto.strong_rand_bytes(32)
    destination = :crypto.strong_rand_bytes(32)
    forwarder_ring = Ring.new(1)

    assert Router.add_forwarder(destination, :closed, forwarder_ring) == :ok
    Ring.close(forwarder_ring)

    before = Metrics.snapshot()[:packets_forwarded_out]

    assert {:dropped, _reason} = Router.route(source, destination, "refused")
    assert Metrics.snapshot()[:packets_forwarded_out] == before + 1

    assert Router.remove_forwarder(destination, :closed) == :ok
  end

  test "removing an unregistered forwarder identity leaves the registered path alone" do
    source = :crypto.strong_rand_bytes(32)
    sender = :crypto.strong_rand_bytes(32)
    destination_key = :crypto.strong_rand_bytes(32)
    destination = spawn(fn -> Process.sleep(:infinity) end)
    forwarder_process = spawn(fn -> Process.sleep(:infinity) end)
    destination_ring = Ring.new(2)
    forwarder_ring = Ring.new(2)

    assert Router.register(destination_key, destination, destination_ring) == :ok
    assert Router.add_forwarder(source, forwarder_process, forwarder_ring) == :ok
    assert Router.note_send(source, destination, destination_ring) == :ok

    before = Metrics.snapshot()[:remove_forwarder_other]
    assert Router.remove_forwarder(source, :never_registered) == :ok
    assert Router.remove_forwarder(:crypto.strong_rand_bytes(32), :never_registered) == :ok

    assert Ring.take(destination_ring) == :empty
    assert Router.forwarder_count(source) == 1
    assert Metrics.snapshot()[:remove_forwarder_other] == before + 2

    assert_enqueued(Router.route(sender, source, "still routed"))
    assert Ring.take(forwarder_ring) == {:ok, {:forward_packet, sender, source, "still routed"}}

    # The registered identity is still monitored, so its death still evicts it.
    Process.exit(forwarder_process, :kill)
    assert_eventually(fn -> Router.forwarder_count(source) == 0 end)
    assert Ring.take(destination_ring) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination_key, destination) == :ok
    Process.exit(destination, :kill)
  end

  test "a crashed last forwarder for a remote-only peer announces it as gone" do
    source = :crypto.strong_rand_bytes(32)
    destination_key = :crypto.strong_rand_bytes(32)
    destination = spawn(fn -> Process.sleep(:infinity) end)
    forwarder_process = spawn(fn -> Process.sleep(:infinity) end)
    destination_ring = Ring.new(2)
    forwarder_ring = Ring.new(2)

    assert Router.register(destination_key, destination, destination_ring) == :ok
    assert Router.add_forwarder(source, forwarder_process, forwarder_ring) == :ok
    assert Router.note_send(source, destination, destination_ring) == :ok

    Process.exit(forwarder_process, :kill)
    assert_eventually(fn -> Router.forwarder_count(source) == 0 end)
    assert Ring.take(destination_ring) == {:ok, {:peer_gone, source, 0x00}}

    assert Router.unregister(destination_key, destination) == :ok
    Process.exit(destination, :kill)
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

  test "a sole connection's activity notes never reach a table" do
    key = :crypto.strong_rand_bytes(32)
    ring = Ring.new(1)
    connection = activity_reporter(self(), key, ring)

    assert_receive {:registered, ^connection}
    on_exit(fn -> Process.exit(connection, :kill) end)

    assert measure_lookups(connection) == 0
    assert Router.unregister(key, connection) == :ok
  end

  test "a connection promoted to a duplicate resumes noting its activity" do
    key = :crypto.strong_rand_bytes(32)
    source = :crypto.strong_rand_bytes(32)
    first_ring = Ring.new(2)
    second_ring = Ring.new(2)
    first = activity_reporter(self(), key, first_ring)
    assert_receive {:registered, ^first}

    second = spawn(fn -> Process.sleep(:infinity) end)
    on_exit(fn -> Enum.each([first, second], &Process.exit(&1, :kill)) end)

    assert Router.register(key, second, second_ring) == :ok
    assert Router.route(source, key, "newest") == {:ok, :wake}
    assert Ring.take(second_ring) == {:ok, {:recv_packet, source, "newest"}}

    assert measure_lookups(first) > 0
    assert Router.route(source, key, "promoted") == {:ok, :wake}
    assert Ring.take(first_ring) == {:ok, {:recv_packet, source, "promoted"}}

    assert Router.unregister(key, first) == :ok
    assert Router.unregister(key, second) == :ok
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

    # The snapshot streams in chunks between everything else the router does,
    # so it arrives shortly after the call returns rather than inside it.
    assert take_when_ready(watcher_ring) ==
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

  @tag :performance
  @tag timeout: 120_000
  test "a region-sized snapshot reaches a new watcher without stalling the router" do
    parent = self()
    connection = spawn(fn -> Process.sleep(:infinity) end)
    ring = Ring.new(1)
    total = 70_000
    peers = for _index <- 1..total, do: :crypto.strong_rand_bytes(32)

    on_exit(fn ->
      Enum.each(peers, &Router.unregister(&1, connection))
      Process.exit(connection, :kill)
    end)

    Enum.each(peers, &(:ok = Router.register(&1, connection, ring)))

    # A real watcher drains as it reads, which is what lets the router stream a
    # region larger than the queue's soft cap.
    watcher = spawn_link(fn -> await_snapshot(parent, total) end)
    lifecycle = LifecycleQueue.new(notifier: watcher, owner: watcher)
    send(watcher, {:queue, lifecycle})
    assert Router.watch(watcher, lifecycle) == :ok

    # The router keeps answering while the snapshot streams: sending it from
    # inside the watch call held the router for all seventy thousand frames.
    source = :crypto.strong_rand_bytes(32)
    destination = hd(peers)

    latencies =
      for _probe <- 1..200 do
        {microseconds, _result} = :timer.tc(fn -> Router.route(source, destination, "probe") end)
        Process.sleep(1)
        microseconds
      end

    assert_receive {:snapshot_complete, ^total}, 60_000
    assert Enum.max(latencies) < 5_000
  end

  defp await_snapshot(parent, total) do
    receive do
      {:queue, queue} -> collect_present(queue, MapSet.new(), parent, total)
    end
  end

  defp collect_present(queue, seen, parent, total) do
    case LifecycleQueue.take(queue) do
      {:ok, {:peer_present, key, _ip, _port, _flags, _app}} ->
        seen = MapSet.put(seen, key)

        if MapSet.size(seen) == total do
          send(parent, {:snapshot_complete, total})
        else
          collect_present(queue, seen, parent, total)
        end

      {:ok, _other} ->
        collect_present(queue, seen, parent, total)

      :busy ->
        collect_present(queue, seen, parent, total)

      _empty_or_closed ->
        receive do
          :derpex_outbox_ready -> collect_present(queue, seen, parent, total)
        after
          30_000 -> send(parent, {:snapshot_complete, MapSet.size(seen)})
        end
    end
  end

  test "a presence change that loses the queue lock is delivered, not dropped" do
    watcher = spawn(fn -> Process.sleep(:infinity) end)
    connection = spawn(fn -> Process.sleep(:infinity) end)
    queue = LifecycleQueue.new(notifier: watcher, owner: watcher)
    key = :crypto.strong_rand_bytes(32)

    on_exit(fn ->
      Router.unregister(key, connection)
      Process.exit(connection, :kill)
      Process.exit(watcher, :kill)
    end)

    assert Router.watch(watcher, queue) == :ok

    # Hold the watcher's queue the way its own writer does mid-drain.
    {:ok, token} = Lock.acquire_producer(queue.table, false, nil)
    before = Metrics.snapshot()
    assert Router.register(key, connection, Ring.new(1)) == :ok

    assert_eventually(fn -> :ets.info(Derpex.Router.PendingLifecycle, :size) > 0 end, 200)
    assert LifecycleQueue.size(queue) == 0

    assert Metrics.snapshot()[:lifecycle_contention] > before[:lifecycle_contention]

    # ADR 0003 promises a watcher's view is complete or absent: the frame waited
    # for the lock rather than disappearing behind it.
    Lock.release(queue.table, token)
    assert_eventually(fn -> LifecycleQueue.size(queue) == 1 end, 200)

    assert {:ok, {:peer_present, ^key, _ip, _port, _flags, _app}} = LifecycleQueue.take(queue)
  end

  test "a stalled watcher still learns about every peer that arrived" do
    watcher = spawn(fn -> Process.sleep(:infinity) end)
    lifecycle = LifecycleQueue.new(notifier: watcher, owner: watcher)
    peers = for _index <- 1..100, do: :crypto.strong_rand_bytes(32)

    on_exit(fn ->
      Enum.each(peers, &Router.unregister(&1, watcher))
      Process.exit(watcher, :kill)
    end)

    assert Router.watch(watcher, lifecycle) == :ok

    # The watcher's writer never drains while the region fills up. A fixed ring
    # would have kept the last thirty-two arrivals and quietly lost the rest.
    Enum.each(peers, fn peer ->
      assert Router.register(peer, watcher, Ring.new(1), Ring.new(1), lifecycle) == :ok
    end)

    assert_eventually(fn -> LifecycleQueue.size(lifecycle) == 100 end, 200)

    present =
      Stream.repeatedly(fn -> LifecycleQueue.take(lifecycle) end)
      |> Enum.take_while(&match?({:ok, {:peer_present, _key, _ip, _port, _flags, _app}}, &1))
      |> Enum.map(fn {:ok, {:peer_present, key, _ip, _port, _flags, _app}} -> key end)

    assert length(present) == 100
    assert Enum.sort(present) == Enum.sort(peers)
  end

  test "a packet for a torn-down destination counts as a disconnect drop" do
    parent = self()
    key = :crypto.strong_rand_bytes(32)
    source = :crypto.strong_rand_bytes(32)

    connection = spawn(fn -> Process.sleep(:infinity) end)

    # A ring dies with the process that owns its table. The route survives until
    # the router reaps it, so a packet can still find a destination that is gone.
    owner = spawn(fn -> send(parent, {:ring, Ring.new(1)}) end)
    monitor = Process.monitor(owner)
    assert_receive {:ring, ring}
    assert_receive {:DOWN, ^monitor, :process, ^owner, _reason}
    assert Router.register(key, connection, ring) == :ok

    on_exit(fn ->
      Router.unregister(key, connection)
      Process.exit(connection, :kill)
    end)

    before = Metrics.snapshot()
    assert Router.route(source, key, "orphan") == {:dropped, :closed_destination}
    after_snapshot = Metrics.snapshot()

    assert delta(before, after_snapshot, {:packets_dropped, :gone_disconnected, :other}) == 1
    assert delta(before, after_snapshot, {:bytes_dropped, :gone_disconnected, :other}) == 6
  end

  defp delta(before, current, key), do: Map.fetch!(current, key) - Map.fetch!(before, key)

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

  # Registers from inside the spawned process, the way a listener handler does,
  # then notes activity 10_000 times on demand so the caller can measure it.
  defp activity_reporter(parent, key, ring) do
    spawn(fn ->
      :ok = Router.register(key, self(), ring)
      send(parent, {:registered, self()})

      receive do
        :note_activity -> :ok
      end

      Enum.each(1..10_000, fn _index ->
        :ok = Router.note_activity(key, self())
      end)

      send(parent, {:noted, self()})
      Process.sleep(:infinity)
    end)
  end

  defp measure_lookups(connection) do
    counter = spawn_link(fn -> count_lookups(0) end)
    :erlang.trace_pattern({:ets, :lookup, 2}, true, [])
    :erlang.trace(connection, true, [:call, {:tracer, counter}])

    try do
      send(connection, :note_activity)
      assert_receive {:noted, ^connection}, 10_000
      reference = :erlang.trace_delivered(connection)
      assert_receive {:trace_delivered, ^connection, ^reference}, 5_000
      send(counter, {:count, self()})
      assert_receive {:lookups, count}, 5_000
      count
    after
      :erlang.trace(connection, false, [:call])
      :erlang.trace_pattern({:ets, :lookup, 2}, false, [])
    end
  end

  defp count_lookups(count) do
    receive do
      {:trace, _pid, :call, {:ets, :lookup, _arguments}} -> count_lookups(count + 1)
      {:count, caller} -> send(caller, {:lookups, count})
    end
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

  test "a watcher whose ring lock is held cannot delay the router" do
    parent = self()
    key = :crypto.strong_rand_bytes(32)
    connection = spawn(fn -> Process.sleep(:infinity) end)
    ring = Ring.new(2)

    watchers =
      Enum.map(1..100, fn _index ->
        watcher_ring = Ring.new(2, test_hook: holding_hook(parent))
        watcher = spawn(fn -> Process.sleep(:infinity) end)
        assert Router.watch(watcher, watcher_ring) == :ok

        holder =
          spawn(fn ->
            Process.put(:hold_ring_lock, true)
            Ring.enqueue(watcher_ring, :held)
          end)

        assert_receive {:holding, ^holder}
        {watcher, holder}
      end)

    on_exit(fn ->
      Router.unregister(key, connection)
      Process.exit(connection, :kill)

      Enum.each(watchers, fn {watcher, holder} ->
        Process.exit(holder, :kill)
        Process.exit(watcher, :kill)
      end)
    end)

    {elapsed_microseconds, :ok} =
      :timer.tc(fn -> Router.register(key, connection, ring, ring, ring) end)

    # Napping on each held lock would cost milliseconds per watcher.
    assert elapsed_microseconds < 5_000

    # Held locks make every later broadcast slow, so this test hands the router
    # back clean rather than leaving the teardown to run beside the next test.
    Enum.each(watchers, fn {watcher, holder} ->
      send(holder, :release)
      Process.exit(watcher, :kill)
    end)

    assert Router.unregister(key, connection) == :ok
    assert_eventually(fn -> Router.stats().watchers == 0 end)
  end

  # Only the process that marked itself the holder parks inside the lock. The
  # router runs this same hook whenever it publishes into one of these rings,
  # and parking it there would wedge the singleton for every other test.
  # A snapshot frame arrives from the router's own stream, so the first take
  # after watch/2 waits for it.
  defp take_when_ready(outbox, attempts \\ 200)
  defp take_when_ready(outbox, 0), do: Outbox.take(outbox)

  defp take_when_ready(outbox, attempts) do
    case Outbox.take(outbox) do
      :empty ->
        Process.sleep(2)
        take_when_ready(outbox, attempts - 1)

      result ->
        result
    end
  end

  defp holding_hook(parent) do
    fn
      :after_journal ->
        if Process.get(:hold_ring_lock) do
          send(parent, {:holding, self()})

          receive do
            :release -> :ok
          end
        end

      _phase ->
        :ok
    end
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
