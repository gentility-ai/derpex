defmodule Derpex.System.SendFreezeTest do
  @moduledoc """
  A faithful port of `TestSendFreeze` from the pinned Go oracle
  (`../tailscale/derp/derp_test.go:464-540`).

  Two streams leave alice: `alice -> bob` and `alice -> cathy`. One recipient
  stops reading; the other must keep receiving. Upstream freezes cathy over an
  in-memory pipe; this suite freezes bob over a real TCP socket, so the roles
  are swapped and the assertions read `alice -> cathy` where the Go test reads
  `alice -> bob`. Everything else is assertion-for-assertion:

  * `drain` waits up to one second for at least one new packet, then discards
    whatever else arrived, exactly like the Go helper of the same name.
  * `assert_no_packets` is upstream's `isEmpty`: alice is a pure sender and
    must never receive a packet.
  * Upstream's `recv` treats any frame that is not a `ReceivedPacket` as fatal,
    so every client here also asserts it saw no `peer_gone` and no other frame.
    Nothing should produce one: a disconnect only reaches peers watching the
    departed key, and a client starts watching a key when a packet from it is
    written to that client, so a pure sender like alice watches nobody. The
    unknown-destination `peer_gone` that alice's post-close sends could earn is
    gated on disco packets, and neither payload here is one.

  * `TestSendRecv`'s `if m.Source.IsZero()` is checked for both recipients, so
    a packet written out of a stalled queue still has to name its sender.

  Three assertions go beyond upstream, because a real socket makes them
  observable where `memnet` did not: the frozen client is closed by the write
  timeout, at least ninety percent of the `alice -> cathy` stream is delivered
  across the whole flood, and the frame kinds bob has seen are compared before
  and after the thaw rather than only before, so the backlog a thawed socket
  drains cannot contain a frame upstream's `recv` would have failed on.
  """

  use ExUnit.Case, async: false

  @moduletag :system

  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Metrics
  alias Derpex.Secret
  alias Derpex.Test.DerpClient

  # Upstream sets `s.WriteTimeout = 100 * time.Millisecond`.
  @write_timeout_ms 100
  # Upstream ticks the sender every 2ms; the flood runs for two seconds.
  @tick_ms 2
  @flood_ms 2_000
  # Upstream's drain helper gives a recipient one second to produce a packet.
  @drain_window_ms 1_000
  # Upstream's payload is a 17-byte string across a 1024-byte `memnet` pipe. A
  # real socket needs volume before a write blocks, and a loaded machine can
  # drag the sender down to a few dozen ticks, so each packet to the frozen
  # client is large enough that even a starved sender fills any socket buffer
  # the kernel hands out. `alice -> cathy` keeps the upstream payload.
  @bob_payload :binary.copy("x", 32 * 1_024)
  @cathy_payload "hello alice->cathy\n"

  test "a frozen recipient cannot freeze an independent flow" do
    port = start_listener()

    alice = DerpClient.connect("alice", port)

    bob =
      DerpClient.connect("bob", port, socket_options: [recbuf: 1_024, buffer: 1_024])

    cathy = DerpClient.connect("cathy", port)

    alice_reader = DerpClient.start_reader(alice)
    bob_reader = DerpClient.start_reader(bob)
    cathy_reader = DerpClient.start_reader(cathy)

    write_errors_before = write_errors()
    {flood, flood_deadline} = start_flood(alice, bob.public_key, cathy.public_key)

    # t.Run("initial-send"): both recipients are reading, alice receives nothing.
    drain(bob_reader, "bob")
    drain(cathy_reader, "cathy")
    assert_no_packets(alice_reader, "alice")

    # t.Run("block-bob"): the frozen socket backs the server up.
    :ok = DerpClient.freeze(bob_reader)
    Process.sleep(2 * @write_timeout_ms)

    drain(cathy_reader, "cathy")
    assert_no_packets(alice_reader, "alice")

    # Now wait a little longer, and ensure packets still flow to cathy.
    drain(cathy_reader, "cathy", "connection alice->cathy frozen by alice->bob")

    # ... and keep ensuring it for the rest of the flood, window by window.
    assert_progress_while_flooding(cathy_reader, flood_deadline)

    {sent_to_bob, sent_to_cathy} = await_flood(flood)

    # `@tick_ms` is a floor on the sender's period, not a rate guarantee:
    # `Process.sleep/1` rounds up and a loaded machine has been seen at 25 ms
    # per tick. So this is not a throughput assertion, only the sanity floor
    # that keeps the delivery ratio below from being judged against a handful
    # of packets — two percent of the nominal tick count.
    minimum_ticks = div(@flood_ms, 50 * @tick_ms)
    assert sent_to_bob >= minimum_ticks
    assert sent_to_cathy >= minimum_ticks

    delivered = settle(cathy_reader)

    assert delivered >= div(sent_to_cathy * 9, 10),
           "alice->cathy delivered #{delivered} of #{sent_to_cathy} packets"

    # Everything bob saw, he saw before the freeze; snapshot him here so the
    # thaw below can be compared against it rather than only re-checked.
    bob_frames = frame_types(bob_reader)
    assert_only_packets(bob_reader, "bob")
    assert_only_packets(cathy_reader, "cathy")

    # The frozen client is the one the server gives up on, and it gives up
    # because a write timed out rather than because the peer went away.
    :ok = DerpClient.thaw(bob_reader)
    assert eventually(fn -> DerpClient.closed?(bob_reader) end, 5_000), "bob was not closed"

    # `send_timeout_close` closes the socket before the failing `send/2`
    # returns, so the client can see the FIN a moment before the writer counts
    # the error. Poll rather than read once.
    assert eventually(fn -> write_errors() > write_errors_before end, 5_000),
           "the frozen client was closed without a recorded write error"

    # The thaw drains whatever the writer still held for bob before the close.
    # Upstream's `recv` fails on any frame that is not a ReceivedPacket, so what
    # comes out of that backlog has to be packets and nothing else: the frame
    # types must be exactly what they were before the thaw.
    assert frame_types(bob_reader) == bob_frames
    assert_only_packets(bob_reader, "bob")

    # isEmpty(alice): alice is a pure sender and must never receive a packet.
    assert_no_packets(alice_reader, "alice")
    assert_only_packets(alice_reader, "alice")

    # TestSendRecv's `if m.Source.IsZero()`, for the frozen recipient as well as
    # the flowing one: a packet written out of a stalled queue still has to name
    # who sent it.
    assert DerpClient.zero_source_packets(bob_reader) == 0
    assert DerpClient.zero_source_packets(cathy_reader) == 0

    # Close bob before alice, as upstream does, to keep a peer-gone frame from
    # racing the teardown.
    DerpClient.close(bob)
    DerpClient.close(alice)
    DerpClient.close(cathy)
  end

  defp start_listener do
    {server_public_key, server_private_key} = Crypto.generate_keypair()

    server =
      start_supervised!({ThousandIsland,
       port: 0,
       num_acceptors: 3,
       transport_options: [
         ip: {127, 0, 0, 1},
         send_timeout: @write_timeout_ms,
         send_timeout_close: true,
         # A floor, not a cap: Linux doubles SO_SNDBUF and enforces its own
         # minimum, so the frozen socket may take a little longer to back up.
         sndbuf: 1_024
       ],
       handler_module: Handler,
       handler_options: [
         server_private_key: Secret.wrap(server_private_key),
         server_public_key: server_public_key
       ]})

    {:ok, {_address, port}} = ThousandIsland.listener_info(server)
    port
  end

  # The sender goroutine: one packet to each recipient every tick until the
  # deadline. Send errors to the frozen recipient are expected and ignored,
  # matching the upstream comment on `aliceClient.Send(cathyKey.Public(), msg2)`.
  defp start_flood(alice, bob_key, cathy_key) do
    parent = self()
    deadline = System.monotonic_time(:millisecond) + @flood_ms

    flood =
      spawn_link(fn ->
        {to_bob, to_cathy} = flood(alice, bob_key, cathy_key, deadline, 0, 0)
        send(parent, {:flood_finished, self(), to_bob, to_cathy})
      end)

    {flood, deadline}
  end

  defp flood(alice, bob_key, cathy_key, deadline, to_bob, to_cathy) do
    if System.monotonic_time(:millisecond) >= deadline do
      {to_bob, to_cathy}
    else
      Process.sleep(@tick_ms)
      _ignored = DerpClient.send_packet(alice, bob_key, @bob_payload)
      :ok = DerpClient.send_packet(alice, cathy_key, @cathy_payload)
      flood(alice, bob_key, cathy_key, deadline, to_bob + 1, to_cathy + 1)
    end
  end

  defp await_flood(flood) do
    receive do
      {:flood_finished, ^flood, to_bob, to_cathy} -> {to_bob, to_cathy}
    after
      2 * @flood_ms -> flunk("the alice sender never finished")
    end
  end

  # Upstream drains twice after the freeze; the flood runs for two seconds, so
  # keep drawing a fresh drain window for as long as one whole window still
  # fits inside the flood. Stopping a window early keeps the last check from
  # racing the sender's own deadline.
  defp assert_progress_while_flooding(reader, deadline) do
    if System.monotonic_time(:millisecond) + @drain_window_ms < deadline do
      drain(reader, "cathy", "alice->cathy stalled during the flood")
      assert_progress_while_flooding(reader, deadline)
    else
      :ok
    end
  end

  # Upstream's drain: require at least one new packet within a second, then
  # discard whatever else has queued up behind it.
  defp drain(reader, name, message \\ nil) do
    before = DerpClient.packets(reader)

    assert eventually(fn -> DerpClient.packets(reader) > before end, @drain_window_ms),
           message || "no packet received by #{name}"
  end

  # Upstream's isEmpty, which inspects only the ReceivedPacket channel.
  defp assert_no_packets(reader, name) do
    assert DerpClient.packets(reader) == 0, "packet received by #{name}, want none"
  end

  # Upstream's `recv` fails the test on any message that is not a
  # ReceivedPacket; no frame in this scenario should be anything else.
  defp assert_only_packets(reader, name) do
    assert DerpClient.peer_gone_frames(reader) == 0,
           "peer_gone frame received by #{name}, want none"

    assert DerpClient.other_frames(reader) == 0,
           "unexpected frame type received by #{name}, want none"
  end

  # The frame kinds a reader has seen, packet count excluded: after a thaw the
  # packet count is expected to move and the frame kinds are not.
  defp frame_types(reader) do
    %{
      peer_gone: DerpClient.peer_gone_frames(reader),
      other: DerpClient.other_frames(reader)
    }
  end

  # Delivery is asynchronous, so let the tail of the stream land before the
  # ratio is judged; stop as soon as the count stops moving.
  defp settle(reader, previous \\ -1, attempts \\ 20)
  defp settle(reader, _previous, 0), do: DerpClient.packets(reader)

  defp settle(reader, previous, attempts) do
    current = DerpClient.packets(reader)

    if current == previous do
      current
    else
      Process.sleep(25)
      settle(reader, current, attempts - 1)
    end
  end

  defp eventually(condition, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    poll(condition, deadline)
  end

  defp poll(condition, deadline) do
    cond do
      condition.() ->
        true

      System.monotonic_time(:millisecond) >= deadline ->
        false

      true ->
        Process.sleep(5)
        poll(condition, deadline)
    end
  end

  defp write_errors, do: Map.get(Metrics.snapshot(), :write_errors, 0)
end
