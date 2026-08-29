defmodule Derpex.Test.ChallengeServer do
  @moduledoc """
  A challenge store that also serves HTTP-01 responses over loopback.

  `Derpex.ACME.Client` publishes through any `{module, server}` exporting
  `put_challenge/3` and `delete_challenge/2`, which in production is
  `Derpex.Certificates.IPManager` behind the relay's plaintext port. This
  stands in for both halves so a client test can watch what was published and
  a fake certificate authority can fetch it back.
  """

  use GenServer

  @doc false
  def start_link(options \\ []), do: GenServer.start_link(__MODULE__, options, options)

  @doc "The base URL a certificate authority fetches challenge responses from."
  def base_url(server), do: GenServer.call(server, :base_url)

  @doc "Every path currently answering."
  def published(server), do: GenServer.call(server, :published)

  @doc "Every publication seen, in order, whether or not it is still answering."
  def history(server), do: GenServer.call(server, :history)

  @doc false
  def put_challenge(server, path, response) do
    GenServer.call(server, {:put_challenge, path, response})
  end

  @doc false
  def delete_challenge(server, path), do: GenServer.call(server, {:delete_challenge, path})

  @impl true
  def init(_options) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        ip: {127, 0, 0, 1},
        active: false,
        reuseaddr: true,
        packet: :raw
      ])

    {:ok, {_ip, port}} = :inet.sockname(listen)
    server = self()
    _acceptor = spawn_link(fn -> accept_loop(listen, server) end)

    {:ok,
     %{
       listen: listen,
       base: "http://127.0.0.1:#{port}",
       published: %{},
       history: []
     }}
  end

  @impl true
  def terminate(_reason, state), do: :gen_tcp.close(state.listen)

  @impl true
  def handle_call(:base_url, _from, state), do: {:reply, state.base, state}
  def handle_call(:published, _from, state), do: {:reply, state.published, state}
  def handle_call(:history, _from, state), do: {:reply, Enum.reverse(state.history), state}

  def handle_call({:put_challenge, path, response}, _from, state) do
    {:reply, :ok,
     %{
       state
       | published: Map.put(state.published, path, response),
         history: [{path, response} | state.history]
     }}
  end

  def handle_call({:delete_challenge, path}, _from, state) do
    {:reply, :ok, %{state | published: Map.delete(state.published, path)}}
  end

  def handle_call({:lookup, path}, _from, state) do
    {:reply, Map.get(state.published, path), state}
  end

  defp accept_loop(listen, server) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        {:ok, pid} = Task.start(fn -> serve(socket, server) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        accept_loop(listen, server)

      {:error, _closed} ->
        :ok
    end
  end

  defp serve(socket, server) do
    with {:ok, head} <- read_head(socket, ""),
         [request_line | _headers] <- String.split(head, "\r\n"),
         ["GET", target | _version] <- String.split(request_line, " ") do
      respond(socket, GenServer.call(server, {:lookup, target}))
    end

    :gen_tcp.close(socket)
  end

  defp respond(socket, nil) do
    :gen_tcp.send(socket, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
  end

  defp respond(socket, response) do
    :gen_tcp.send(socket, [
      "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ",
      Integer.to_string(byte_size(response)),
      "\r\n\r\n",
      response
    ])
  end

  defp read_head(socket, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {offset, 4} ->
        {:ok, binary_part(buffer, 0, offset)}

      :nomatch ->
        case :gen_tcp.recv(socket, 0, 10_000) do
          {:ok, chunk} -> read_head(socket, buffer <> chunk)
          {:error, reason} -> {:error, reason}
        end
    end
  end
end
