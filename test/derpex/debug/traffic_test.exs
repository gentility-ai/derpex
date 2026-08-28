defmodule Derpex.Debug.TrafficTest do
  use ExUnit.Case, async: false

  alias Derpex.Debug.Traffic
  alias Derpex.Outbox.Ring
  alias Derpex.Router
  alias Derpex.Writer

  defmodule Transport do
    @behaviour Derpex.Transport
    import Kernel, except: [send: 2]

    @impl true
    def send(test_process, data) do
      Kernel.send(test_process, {:written, IO.iodata_to_binary(data)})
      :ok
    end

    @impl true
    def close(_socket), do: :ok

    @impl true
    def peername(_socket), do: {:ok, :test}

    @impl true
    def secure?(_socket), do: false
  end

  test "reports the active client's unique sender estimate" do
    destination = :crypto.strong_rand_bytes(32)
    {:ok, writer} = Writer.start_link(owner: self(), transport: Transport, socket: self())
    rings = rings(writer)

    on_exit(fn ->
      Router.unregister(destination, self())
      if Process.alive?(writer), do: Process.exit(writer, :kill)
    end)

    assert :ok =
             Router.register(
               destination,
               self(),
               rings.ordinary,
               rings.disco,
               rings.lifecycle
             )

    Enum.each(1..5, fn _index ->
      source = :crypto.strong_rand_bytes(32)
      assert Router.route(source, destination, "packet") in [{:ok, :wake}, {:ok, :coalesced}]
      assert_receive {:written, _frame}
    end)

    assert {:ok, estimate} = Traffic.unique_senders(destination)
    assert estimate in 4..6
    assert Traffic.unique_senders(:crypto.strong_rand_bytes(32)) == {:error, :not_connected}
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
