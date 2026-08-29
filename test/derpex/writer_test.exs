defmodule Derpex.WriterTest do
  use ExUnit.Case, async: true

  alias Derpex.Outbox.Ring
  alias Derpex.Router
  alias Derpex.Writer

  defmodule BlockingTransport do
    @behaviour Derpex.Transport
    import Kernel, except: [send: 2]

    @impl true
    def send(test_process, data) do
      Kernel.send(test_process, {:write_started, self(), IO.iodata_to_binary(data)})

      receive do
        :unblock_write -> :ok
      end
    end

    @impl true
    def close(_socket), do: :ok

    @impl true
    def peername(_socket), do: {:ok, :test}

    @impl true
    def secure?(_socket), do: false
  end

  defmodule ControlledTransport do
    @behaviour Derpex.Transport
    import Kernel, except: [send: 2]

    @impl true
    def send({test_process, name, :open}, data) do
      Kernel.send(test_process, {:write_finished, name, IO.iodata_to_binary(data)})
      :ok
    end

    def send({test_process, name, :blocked}, data) do
      Kernel.send(test_process, {:write_blocked, name, self(), IO.iodata_to_binary(data)})

      receive do
        :unblock_write -> :ok
      end
    end

    @impl true
    def close(_socket), do: :ok

    @impl true
    def peername(_socket), do: {:ok, :test}

    @impl true
    def secure?(_socket), do: false
  end

  defmodule FailingTransport do
    @behaviour Derpex.Transport

    @impl true
    def send(_socket, _data), do: {:error, :closed}

    @impl true
    def close(_socket), do: :ok

    @impl true
    def peername(_socket), do: {:ok, :test}

    @impl true
    def secure?(_socket), do: false
  end

  test "a stalled socket write cannot accumulate packet messages in the writer mailbox" do
    {:ok, writer} = Writer.start_link(owner: self(), transport: BlockingTransport, socket: self())
    Process.unlink(writer)

    on_exit(fn ->
      if Process.alive?(writer), do: Process.exit(writer, :kill)
    end)

    ordinary = Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
    disco = Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
    pong = Ring.new(1, notifier: writer, wake_message: Writer.wake_message())
    lifecycle = Ring.new(32, notifier: writer, wake_message: Writer.wake_message())

    :ok =
      Writer.attach(writer, %{
        ordinary: ordinary,
        disco: disco,
        pong: pong,
        lifecycle: lifecycle
      })

    source = :binary.copy(<<1>>, 32)

    assert enqueue_until_accepted(ordinary, {:recv_packet, source, "first"}) == :wake
    assert_receive {:write_started, ^writer, _frame}

    for sequence <- 1..10_000 do
      packet = <<sequence::unsigned-big-32>>

      assert Ring.enqueue(ordinary, {:recv_packet, source, packet}) in [
               {:ok, :coalesced},
               {:ok, :replaced}
             ]
    end

    assert {:messages, []} = Process.info(writer, :messages)
    assert Ring.stats(ordinary).size == 32
    assert Ring.stats(ordinary).packet_slots == 32

    send(writer, :unblock_write)
    assert_receive {:write_started, ^writer, _next_frame}
    send(writer, :unblock_write)
  end

  test "a frozen recipient does not stop an independent client flow" do
    {:ok, frozen_writer} =
      Writer.start_link(
        owner: self(),
        transport: ControlledTransport,
        socket: {self(), :frozen, :blocked}
      )

    {:ok, flowing_writer} =
      Writer.start_link(
        owner: self(),
        transport: ControlledTransport,
        socket: {self(), :flowing, :open}
      )

    Process.unlink(frozen_writer)
    Process.unlink(flowing_writer)
    frozen_rings = rings(frozen_writer)
    flowing_rings = rings(flowing_writer)
    frozen_key = :crypto.strong_rand_bytes(32)
    flowing_key = :crypto.strong_rand_bytes(32)
    source = :crypto.strong_rand_bytes(32)

    on_exit(fn ->
      Router.unregister(frozen_key, frozen_writer)
      Router.unregister(flowing_key, flowing_writer)
      if Process.alive?(frozen_writer), do: Process.exit(frozen_writer, :kill)
      if Process.alive?(flowing_writer), do: Process.exit(flowing_writer, :kill)
    end)

    assert Router.register(
             frozen_key,
             frozen_writer,
             frozen_rings.ordinary,
             frozen_rings.disco,
             frozen_rings.lifecycle
           ) == :ok

    assert Router.register(
             flowing_key,
             flowing_writer,
             flowing_rings.ordinary,
             flowing_rings.disco,
             flowing_rings.lifecycle
           ) == :ok

    assert route_until_accepted(source, frozen_key, "freeze") == :wake
    assert_receive {:write_blocked, :frozen, ^frozen_writer, _frame}

    for sequence <- 1..10_000 do
      packet = <<sequence::unsigned-big-32>>

      assert Router.route(source, frozen_key, packet) in [
               {:ok, :coalesced},
               {:ok, :replaced}
             ]
    end

    assert route_until_accepted(source, flowing_key, "still flowing") == :wake
    assert_receive {:write_finished, :flowing, frame}, 500
    assert frame =~ "still flowing"
    assert {:message_queue_len, 0} = Process.info(frozen_writer, :message_queue_len)
    assert Ring.stats(frozen_rings.ordinary).size == 32
  end

  test "a producer holding a ring lock neither spins the writer nor loses its packet" do
    parent = self()

    {:ok, writer} =
      Writer.start_link(
        owner: self(),
        transport: ControlledTransport,
        socket: {self(), :contended, :open}
      )

    hook = fn
      :after_journal ->
        if Process.get(:hold_lock) do
          send(parent, {:holding, self()})

          receive do
            :release -> :ok
          end
        end

      _phase ->
        :ok
    end

    ordinary =
      Ring.new(32, notifier: writer, wake_message: Writer.wake_message(), test_hook: hook)

    :ok =
      Writer.attach(writer, %{
        ordinary: ordinary,
        disco: Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
        pong: Ring.new(1, notifier: writer, wake_message: Writer.wake_message()),
        lifecycle: Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
      })

    source = :crypto.strong_rand_bytes(32)

    holder =
      spawn_link(fn ->
        Process.put(:hold_lock, true)
        Ring.enqueue(ordinary, {:recv_packet, source, "held"})
      end)

    assert_receive {:holding, ^holder}

    # The writer has been woken and finds the ring locked. It must idle rather
    # than re-waking itself until the producer publishes.
    {:reductions, before_reductions} = Process.info(writer, :reductions)
    Process.sleep(100)
    {:reductions, after_reductions} = Process.info(writer, :reductions)
    assert after_reductions - before_reductions < 10_000

    # The producer coalesced its wake into the one already being handled, so the
    # packet is written by the safety retry rather than by a new wakeup.
    send(holder, :release)
    assert_receive {:write_finished, :contended, frame}, 1_000
    assert frame =~ "held"
  end

  test "packets enqueued before attach are written once the rings arrive" do
    {:ok, writer} =
      Writer.start_link(
        owner: self(),
        transport: ControlledTransport,
        socket: {self(), :early, :open}
      )

    ordinary = Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
    source = :crypto.strong_rand_bytes(32)

    # The wakeup arrives while the writer still has no rings; the ring records
    # the wake as pending and will not send another one.
    assert Ring.enqueue(ordinary, {:recv_packet, source, "early"}) == {:ok, :wake}

    :ok =
      Writer.attach(writer, %{
        ordinary: ordinary,
        disco: Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
        pong: Ring.new(1, notifier: writer, wake_message: Writer.wake_message()),
        lifecycle: Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
      })

    assert_receive {:write_finished, :early, frame}
    assert frame =~ "early"
  end

  @tag :capture_log
  test "attach reports the write error its own drain runs into" do
    {:ok, writer} =
      Writer.start_link(owner: self(), transport: FailingTransport, socket: :socket)

    Process.unlink(writer)
    monitor = Process.monitor(writer)
    ordinary = Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
    source = :crypto.strong_rand_bytes(32)

    assert Ring.enqueue(ordinary, {:recv_packet, source, "early"}) == {:ok, :wake}

    assert Writer.attach(writer, %{
             ordinary: ordinary,
             disco: Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
             pong: Ring.new(1, notifier: writer, wake_message: Writer.wake_message()),
             lifecycle: Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
           }) == {:error, :closed}

    assert_receive {:DOWN, ^monitor, :process, ^writer, {:write_error, :closed}}
  end

  test "counts distinct non-zero sources only after their packets are written" do
    {:ok, writer} =
      Writer.start_link(
        owner: self(),
        transport: ControlledTransport,
        socket: {self(), :cardinality, :open}
      )

    rings = rings(writer)
    first = :crypto.strong_rand_bytes(32)
    second = :crypto.strong_rand_bytes(32)

    enqueue_until_accepted(rings.ordinary, {:recv_packet, <<0::256>>, "zero"})
    assert_receive {:write_finished, :cardinality, _frame}
    assert Writer.estimated_unique_senders(writer) == 0

    Enum.each([first, second, first], fn source ->
      enqueue_until_accepted(rings.ordinary, {:recv_packet, source, "packet"})
      assert_receive {:write_finished, :cardinality, _frame}
    end)

    assert Writer.estimated_unique_senders(writer) in 1..3
  end

  defmodule SlowTransport do
    @behaviour Derpex.Transport

    @impl true
    def send(_socket, _data) do
      Process.sleep(6_000)
      :ok
    end

    @impl true
    def close(_socket), do: :ok

    @impl true
    def peername(_socket), do: {:ok, :test}

    @impl true
    def secure?(_socket), do: false
  end

  @tag timeout: 60_000
  test "a control write waits as long as the socket is allowed to take" do
    {:ok, writer} = Writer.start_link(owner: self(), transport: SlowTransport, socket: :socket)

    mesh_timeout = Derpex.SocketOptions.mesh_write_timeout_ms()
    assert Writer.write_control(writer, "server-info", mesh_timeout + 1_000) == :ok
  end

  test "a saturated ordinary ring cannot starve the pong and disco rings" do
    {:ok, writer} =
      Writer.start_link(
        owner: self(),
        transport: ControlledTransport,
        socket: {self(), :fair, :open}
      )

    rings = rings(writer)
    source = :crypto.strong_rand_bytes(32)

    # Fill the ordinary ring before the writer can drain it, so every ordinary
    # packet is older than the pong and the disco packet that follow.
    for sequence <- 1..32 do
      enqueue_until_accepted(rings.ordinary, {:recv_packet, source, <<sequence::32>>})
    end

    enqueue_until_accepted(rings.pong, {:pong, "12345678"})
    enqueue_until_accepted(rings.disco, {:recv_packet, source, disco_packet()})

    frames = collect_frames(20)
    pong_position = Enum.find_index(frames, &match?({:pong, _payload}, &1))
    disco_position = Enum.find_index(frames, &(&1 == {:packet, disco_packet()}))

    assert pong_position, "the pong was never written"
    assert disco_position, "the disco packet was never written"
    assert ordinary_frames_before(frames, pong_position) <= 2
    assert ordinary_frames_before(frames, disco_position) <= 2
  end

  defp disco_packet, do: <<0x64, 0x65, 0x87, 0xB0, 0x8E, 0xF5>> <> :binary.copy(<<7>>, 26)

  defp ordinary_frames_before(frames, position) do
    disco = disco_packet()

    frames
    |> Enum.take(position)
    |> Enum.count(fn frame ->
      match?({:packet, _payload}, frame) and frame != {:packet, disco}
    end)
  end

  defp collect_frames(count, collected \\ [])
  defp collect_frames(0, collected), do: Enum.reverse(collected)

  defp collect_frames(count, collected) do
    receive do
      {:write_finished, :fair, frame} ->
        collect_frames(count - 1, [decode_frame(frame) | collected])
    after
      1_000 -> Enum.reverse(collected)
    end
  end

  defp decode_frame(<<0x13, _length::32, payload::binary>>), do: {:pong, payload}

  defp decode_frame(<<0x05, _length::32, _source::binary-size(32), payload::binary>>),
    do: {:packet, payload}

  defp decode_frame(frame), do: {:other, frame}

  defp rings(writer) do
    rings = %{
      ordinary: Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
      disco: Ring.new(32, notifier: writer, wake_message: Writer.wake_message()),
      pong: Ring.new(1, notifier: writer, wake_message: Writer.wake_message()),
      lifecycle: Ring.new(32, notifier: writer, wake_message: Writer.wake_message())
    }

    :ok = Writer.attach(writer, rings)
    rings
  end

  # A single producer attempt can lose the ring lock to the writer's own drain,
  # so tests that need the packet in the ring retry the drop.
  defp enqueue_until_accepted(ring, message) do
    case Ring.enqueue(ring, message) do
      {:ok, wake_state} -> wake_state
      {:dropped, :contention} -> enqueue_until_accepted(ring, message)
    end
  end

  defp route_until_accepted(source, destination, packet) do
    case Router.route(source, destination, packet) do
      {:ok, wake_state} -> wake_state
      {:dropped, :contention} -> route_until_accepted(source, destination, packet)
    end
  end
end
