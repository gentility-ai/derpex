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

    assert Ring.enqueue(ordinary, {:recv_packet, source, "first"}) == {:ok, :wake}
    assert_receive {:write_started, ^writer, _frame}

    for sequence <- 1..10_000 do
      packet = <<sequence::unsigned-big-32>>

      assert Ring.enqueue(ordinary, {:recv_packet, source, packet}) in [
               {:ok, :coalesced},
               {:ok, :replaced}
             ]
    end

    assert {:message_queue_len, 0} = Process.info(writer, :message_queue_len)
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

    assert Router.route(source, frozen_key, "freeze") == {:ok, :wake}
    assert_receive {:write_blocked, :frozen, ^frozen_writer, _frame}

    for sequence <- 1..10_000 do
      packet = <<sequence::unsigned-big-32>>

      assert Router.route(source, frozen_key, packet) in [
               {:ok, :coalesced},
               {:ok, :replaced}
             ]
    end

    assert Router.route(source, flowing_key, "still flowing") == {:ok, :wake}
    assert_receive {:write_finished, :flowing, frame}, 500
    assert frame =~ "still flowing"
    assert {:message_queue_len, 0} = Process.info(frozen_writer, :message_queue_len)
    assert Ring.stats(frozen_rings.ordinary).size == 32
  end

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
end
