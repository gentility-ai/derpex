defmodule Derpex.WriterTest do
  use ExUnit.Case, async: true

  alias Derpex.Outbox.Ring
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
end
