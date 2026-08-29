defmodule Derpex.Test.DerpClient do
  @moduledoc """
  A hand-rolled DERP client for the system suite.

  The suite needs clients that talk to a real listener over real TCP sockets
  and whose reads can be frozen the way `memnet.Conn.SetReadBlock` freezes them
  in the upstream Go tests. A frozen client stops re-arming its socket, so the
  kernel receive buffer fills, the server's writes block, and the pinned write
  timeout fires — exactly the situation `TestSendFreeze` exercises.

  Frame tallies live in a `:counters` reference so the test process can read
  them while the reader is blocked or deliberately frozen.
  """

  alias Derpex.ClientInfo
  alias Derpex.Crypto
  alias Derpex.Frame
  alias Derpex.Frame.Body
  alias Derpex.Handshake

  @packets 1
  @zero_source_packets 2
  @peer_gone_frames 3
  @other_frames 4
  @closed 5
  @counter_size 5

  @enforce_keys [:name, :socket, :public_key, :private_key, :server_public_key]
  defstruct [:name, :socket, :public_key, :private_key, :server_public_key]

  @type t :: %__MODULE__{
          name: String.t(),
          socket: :gen_tcp.socket(),
          public_key: binary(),
          private_key: binary(),
          server_public_key: binary()
        }

  defmodule Reader do
    @moduledoc "A reader loop owning one `Derpex.Test.DerpClient` socket."

    @enforce_keys [:pid, :counters]
    defstruct [:pid, :counters]

    @type t :: %__MODULE__{pid: pid(), counters: :counters.counters_ref()}
  end

  @doc """
  Connects to a cleartext DERP listener and completes the version 2 handshake.

  `:socket_options` are appended to the connect options, which lets a caller
  shrink the receive buffer of a client it intends to freeze.
  """
  @spec connect(String.t(), :inet.port_number(), keyword()) :: t()
  def connect(name, port, options \\ []) do
    socket_options = Keyword.get(options, :socket_options, [])
    address = Keyword.get(options, :address, {127, 0, 0, 1})

    {:ok, socket} =
      :gen_tcp.connect(
        address,
        port,
        [:binary, active: false, packet: :raw, nodelay: true] ++ socket_options,
        5_000
      )

    {public_key, private_key} = Crypto.generate_keypair()
    :ok = :gen_tcp.send(socket, upgrade_request())
    :ok = read_upgrade_response(socket, "")
    {:ok, :server_key, greeting} = recv_frame(socket, 5_000)
    {:ok, server_public_key} = Handshake.decode_server_key(greeting)

    info = %ClientInfo{version: 2, can_ack_pings: true, app_name: name}
    {:ok, client_frame} = Handshake.client_info_frame(private_key, server_public_key, info)
    :ok = :gen_tcp.send(socket, client_frame)
    {:ok, :server_info, _payload} = recv_frame(socket, 5_000)

    %__MODULE__{
      name: name,
      socket: socket,
      public_key: public_key,
      private_key: private_key,
      server_public_key: server_public_key
    }
  end

  @doc "Sends one DERP packet to `destination`."
  @spec send_packet(t(), binary(), binary()) :: :ok | {:error, term()}
  def send_packet(%__MODULE__{socket: socket}, destination, payload) do
    {:ok, frame} = Body.encode_client({:send_packet, destination, payload})
    :gen_tcp.send(socket, frame)
  end

  @doc "Closes the client socket."
  @spec close(t()) :: :ok
  def close(%__MODULE__{socket: socket}), do: :gen_tcp.close(socket)

  @doc """
  Hands the socket to a reader loop that tallies every frame it decodes.

  The loop reads in `active: :once` mode so it can also service freeze and thaw
  requests, which a blocking `:gen_tcp.recv/3` could not.
  """
  @spec start_reader(t()) :: Reader.t()
  def start_reader(%__MODULE__{socket: socket}) do
    counters = :counters.new(@counter_size, [:write_concurrency])

    pid =
      spawn_link(fn ->
        receive do
          :own -> :ok
        after
          5_000 -> exit(:no_socket_ownership)
        end

        :ok = :inet.setopts(socket, active: :once)
        read_loop(%{socket: socket, counters: counters, buffer: "", frozen?: false})
      end)

    :ok = :gen_tcp.controlling_process(socket, pid)
    send(pid, :own)
    %Reader{pid: pid, counters: counters}
  end

  @doc "Stops the reader from draining its socket, filling the kernel buffer."
  @spec freeze(Reader.t()) :: :ok
  def freeze(%Reader{pid: pid}), do: call(pid, :freeze)

  @doc "Resumes a frozen reader so it drains whatever the kernel buffered."
  @spec thaw(Reader.t()) :: :ok
  def thaw(%Reader{pid: pid}), do: call(pid, :thaw)

  @doc "Returns the number of `recv_packet` frames the reader decoded."
  @spec packets(Reader.t()) :: non_neg_integer()
  def packets(%Reader{counters: counters}), do: :counters.get(counters, @packets)

  @doc "Returns the number of `recv_packet` frames carrying a zero source key."
  @spec zero_source_packets(Reader.t()) :: non_neg_integer()
  def zero_source_packets(%Reader{counters: counters}),
    do: :counters.get(counters, @zero_source_packets)

  @doc "Returns the number of `peer_gone` frames the reader decoded."
  @spec peer_gone_frames(Reader.t()) :: non_neg_integer()
  def peer_gone_frames(%Reader{counters: counters}),
    do: :counters.get(counters, @peer_gone_frames)

  @doc "Returns the number of frames that were neither packets nor peer-gone."
  @spec other_frames(Reader.t()) :: non_neg_integer()
  def other_frames(%Reader{counters: counters}), do: :counters.get(counters, @other_frames)

  @doc "Returns true once the server has closed or reset the connection."
  @spec closed?(Reader.t()) :: boolean()
  def closed?(%Reader{counters: counters}), do: :counters.get(counters, @closed) > 0

  defp call(pid, request) do
    reference = make_ref()
    send(pid, {request, self(), reference})

    receive do
      {^reference, :ok} -> :ok
    after
      5_000 -> exit({:reader_timeout, request})
    end
  end

  defp read_loop(state) do
    receive do
      {:tcp, _socket, data} ->
        buffer = consume(state.buffer <> data, state.counters)
        unless state.frozen?, do: :ok = :inet.setopts(state.socket, active: :once)
        read_loop(%{state | buffer: buffer})

      {:tcp_closed, _socket} ->
        :counters.add(state.counters, @closed, 1)

      {:tcp_error, _socket, _reason} ->
        :counters.add(state.counters, @closed, 1)

      {:freeze, from, reference} ->
        send(from, {reference, :ok})
        read_loop(%{state | frozen?: true})

      {:thaw, from, reference} ->
        if state.frozen?, do: :ok = :inet.setopts(state.socket, active: :once)
        send(from, {reference, :ok})
        read_loop(%{state | frozen?: false})
    end
  end

  defp consume(<<type, length::unsigned-big-32, rest::binary>>, counters)
       when byte_size(rest) >= length do
    <<payload::binary-size(^length), remainder::binary>> = rest
    record(counters, type, payload)
    consume(remainder, counters)
  end

  defp consume(buffer, _counters), do: buffer

  defp record(counters, type, payload) do
    case Frame.type_name(type) do
      {:ok, :recv_packet} ->
        :counters.add(counters, @packets, 1)

        if match?(<<0::256, _rest::binary>>, payload) do
          :counters.add(counters, @zero_source_packets, 1)
        end

      {:ok, :peer_gone} ->
        :counters.add(counters, @peer_gone_frames, 1)

      _other ->
        :counters.add(counters, @other_frames, 1)
    end

    :ok
  end

  defp upgrade_request do
    "GET /derp HTTP/1.1\r\nHost: localhost\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n"
  end

  defp read_upgrade_response(socket, accumulator) do
    if String.contains?(accumulator, "\r\n\r\n") do
      :ok
    else
      {:ok, byte} = :gen_tcp.recv(socket, 1, 5_000)
      read_upgrade_response(socket, accumulator <> byte)
    end
  end

  defp recv_frame(socket, timeout) do
    with {:ok, <<type, length::unsigned-big-32>>} <- :gen_tcp.recv(socket, 5, timeout),
         {:ok, payload} <- recv_payload(socket, length, timeout),
         {:ok, name} <- Frame.type_name(type) do
      {:ok, name, payload}
    else
      :unknown -> {:error, :unknown_frame_type}
      {:error, reason} -> {:error, reason}
    end
  end

  defp recv_payload(_socket, 0, _timeout), do: {:ok, ""}
  defp recv_payload(socket, length, timeout), do: :gen_tcp.recv(socket, length, timeout)
end
