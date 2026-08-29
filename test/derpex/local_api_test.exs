defmodule Derpex.LocalAPITest do
  use ExUnit.Case, async: false

  alias Derpex.LocalAPI

  @node_key :binary.copy(<<0xAB>>, 32)

  setup do
    socket_path =
      Path.join(
        System.tmp_dir!(),
        "derpex-localapi-#{System.unique_integer([:positive, :monotonic])}.sock"
      )

    File.rm(socket_path)

    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        ip: {:local, String.to_charlist(socket_path)}
      ])

    on_exit(fn ->
      :gen_tcp.close(listener)
      File.rm(socket_path)
    end)

    {:ok, listener: listener, socket_path: socket_path}
  end

  test "sends the pinned node-key WhoIs request and accepts valid JSON", context do
    parent = self()

    server =
      serve_once(context.listener, fn socket, request ->
        send(parent, {:localapi_request, request})
        :gen_tcp.send(socket, response(200, ~s({"Node":{"ID":1}})))
      end)

    assert :ok = LocalAPI.whois_node_key(@node_key, options(context))

    assert_receive {:localapi_request, request}

    assert request ==
             "GET /localapi/v0/whois?addr=nodekey%3A#{String.duplicate("ab", 32)} HTTP/1.1\r\n" <>
               "Host: local-tailscaled.sock\r\n" <>
               "Tailscale-Cap: 145\r\n" <>
               "Connection: close\r\n\r\n"

    await_server(server)
  end

  test "decodes chunked WhoIs responses", context do
    body = ~s({"padding":"#{String.duplicate("x", 2_048)}"})
    first_size = Integer.to_string(byte_size(body), 16)

    server =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, [
          "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
          first_size,
          "\r\n",
          body,
          "\r\n0\r\n\r\n"
        ])
      end)

    assert :ok =
             LocalAPI.whois_node_key(
               @node_key,
               Keyword.put(options(context), :max_response_bytes, 4_096)
             )

    await_server(server)
  end

  test "does not count body read-ahead against the response-head bound", context do
    body = ~s({"padding":"#{String.duplicate("x", 20_000)}"})

    server =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(200, body))
      end)

    assert :ok =
             LocalAPI.whois_node_key(
               @node_key,
               Keyword.put(options(context), :max_response_bytes, 32_768)
             )

    await_server(server)
  end

  test "maps a missing peer and the old-tailscaled response", context do
    missing =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(404, "no match for IP:port\n"))
      end)

    assert LocalAPI.whois_node_key(@node_key, options(context)) ==
             {:error, :peer_not_found}

    await_server(missing)

    old =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(400, "invalid 'addr' parameter\n"))
      end)

    assert LocalAPI.whois_node_key(@node_key, options(context)) ==
             {:error, :tailscaled_too_old}

    await_server(old)
  end

  test "fails closed on malformed JSON and oversized bodies", context do
    malformed =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(200, "not-json"))
      end)

    assert {:error, {:invalid_localapi_json, _reason}} =
             LocalAPI.whois_node_key(@node_key, options(context))

    await_server(malformed)

    oversized =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(200, String.duplicate("x", 32)))
      end)

    assert LocalAPI.whois_node_key(
             @node_key,
             Keyword.put(options(context), :max_response_bytes, 8)
           ) == {:error, {:invalid_localapi_response, :response_body_too_large}}

    await_server(oversized)
  end

  test "enforces one wall timeout across the exchange", context do
    server_delay_ms = 250

    server =
      serve_once(context.listener, fn _socket, _request ->
        Process.sleep(server_delay_ms)
        :ok
      end)

    # The property is that the caller gives up on its own deadline rather than
    # waiting for this server, so the comparison is against the server's reply
    # arriving, not against a wall-clock budget a loaded machine can blow.
    would_have_replied = Process.send_after(self(), :server_would_have_replied, server_delay_ms)

    assert LocalAPI.whois_node_key(
             @node_key,
             Keyword.put(options(context), :timeout_ms, 20)
           ) == {:error, {:localapi_unavailable, :timeout}}

    refute_received :server_would_have_replied
    Process.cancel_timer(would_have_replied)
    await_server(server)
  end

  test "uses the pinned platform socket defaults" do
    assert LocalAPI.default_socket_path({:unix, :darwin}) == "/var/run/tailscaled.socket"

    assert LocalAPI.default_socket_path({:unix, :linux}) ==
             "/var/run/tailscale/tailscaled.sock"
  end

  defp serve_once(listener, responder) do
    Task.async(fn ->
      {:ok, socket} = :gen_tcp.accept(listener)

      try do
        {:ok, request} = receive_request(socket, "")
        responder.(socket, request)
      after
        :gen_tcp.close(socket)
      end
    end)
  end

  defp receive_request(_socket, buffer) when byte_size(buffer) > 16_384,
    do: {:error, :request_too_large}

  defp receive_request(socket, buffer) do
    if String.ends_with?(buffer, "\r\n\r\n") do
      {:ok, buffer}
    else
      with {:ok, data} <- :gen_tcp.recv(socket, 0, 1_000) do
        receive_request(socket, buffer <> data)
      end
    end
  end

  defp response(status, body) do
    reason = if status == 200, do: "OK", else: "Error"

    [
      "HTTP/1.1 #{status} #{reason}\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      "Content-Type: application/json\r\n",
      "Connection: close\r\n\r\n",
      body
    ]
  end

  defp options(context) do
    [socket_path: context.socket_path, timeout_ms: 500, max_response_bytes: 1_024]
  end

  defp await_server(server), do: Task.await(server, 1_000)
end
