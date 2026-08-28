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

    endpoint = {{192, 0, 2, 8}, 58_145}

    output = """
    ESTAB 0 0 10.0.0.1:443 192.0.2.8:58145
      cubic bytes_sent:1591815 bytes_received:158925
    """

    sample_options = [
      run_ss: fn -> {:ok, output} end,
      client_keys: fn -> %{endpoint => destination} end
    ]

    assert {:ok, counters, encoded} = Traffic.sample(%{}, sample_options)
    assert counters[endpoint] == %{sent: 1_591_815, received: 158_925}

    encoded = IO.iodata_to_binary(encoded)
    assert String.ends_with?(encoded, "\n\n")
    [record] = String.split(encoded, "\n", trim: true)
    assert {:ok, fields} = Derpex.JSON.decode_object(record)
    assert field!(fields, "Sent") == 1_591_815
    assert field!(fields, "Recv") == 158_925

    assert field!(fields, "Key") ==
             "nodekey:" <> Base.encode16(destination, case: :lower)

    assert field!(fields, "UniqueSenders") in 4..6

    assert {:ok, ^counters, unchanged} =
             Traffic.sample(counters, sample_options)

    assert IO.iodata_to_binary(unchanged) == "\n"

    assert Traffic.sample(%{}, run_ss: fn -> {:error, :enoent} end) ==
             {:error, :enoent}
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

  defp field!(fields, name), do: fields |> List.keyfind!(name, 0) |> elem(1)
end
