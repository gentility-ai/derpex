defmodule Derpex.STUN do
  @moduledoc "Supervised UDP STUN responder for Tailscale netcheck clients."

  use GenServer

  alias Derpex.STUN.Protocol

  @doc false
  def start_link(options) do
    case Keyword.fetch(options, :name) do
      {:ok, name} -> GenServer.start_link(__MODULE__, options, name: name)
      :error -> GenServer.start_link(__MODULE__, options)
    end
  end

  @doc "Returns the bound UDP address."
  @spec local_address(GenServer.server()) :: {:ok, {:inet.ip_address(), :inet.port_number()}}
  def local_address(server), do: GenServer.call(server, :local_address)

  @impl true
  def init(options) do
    port = Keyword.get(options, :port, 3_478)
    ip = Keyword.get(options, :ip, {0, 0, 0, 0})
    family = if tuple_size(ip) == 8, do: :inet6, else: :inet

    socket_options = [:binary, family, active: :once, reuseaddr: true, ip: ip]

    case :gen_udp.open(port, socket_options) do
      {:ok, socket} -> {:ok, %{socket: socket}}
      {:error, reason} -> {:stop, reason}
    end
  end

  @impl true
  def handle_call(:local_address, _from, state) do
    {:reply, :inet.sockname(state.socket), state}
  end

  @impl true
  def handle_info({:udp, socket, ip, port, packet}, %{socket: socket} = state) do
    case Protocol.parse_request(packet) do
      {:ok, transaction_id} ->
        response = Protocol.response(transaction_id, ip, port)
        _result = :gen_udp.send(socket, ip, port, response)

      {:error, _reason} ->
        :ok
    end

    :ok = :inet.setopts(socket, active: :once)
    {:noreply, state}
  end

  @impl true
  def terminate(_reason, state) do
    :gen_udp.close(state.socket)
    :ok
  end
end
