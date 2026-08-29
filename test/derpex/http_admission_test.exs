defmodule Derpex.HTTPAdmissionTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Derpex.Certificates.Manual
  alias Derpex.HTTPAdmission

  @node_key :binary.copy(<<0xAB>>, 32)

  setup do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    {:ok, listener: listener, port: port}
  end

  test "posts the exact pinned request and accepts Allow true", context do
    parent = self()

    server =
      serve_once(context.listener, fn socket, request ->
        send(parent, {:admission_request, request})
        :gen_tcp.send(socket, response(200, ~s({"Allow":true})))
      end)

    assert :ok =
             HTTPAdmission.admit(
               @node_key,
               {203, 0, 113, 9},
               options(context, "/admit?region=17")
             )

    expected_body =
      ~s({"NodePublic":"nodekey:#{String.duplicate("ab", 32)}","Source":"203.0.113.9"})

    assert_receive {:admission_request, {head, ^expected_body}}

    assert head ==
             "POST /admit?region=17 HTTP/1.1\r\n" <>
               "Host: 127.0.0.1:#{context.port}\r\n" <>
               "Content-Length: #{byte_size(expected_body)}\r\n" <>
               "Connection: close\r\n\r\n"

    await_server(server)
  end

  test "denies false or missing Allow and uses the last duplicate field", context do
    for body <- [~s({"Allow":false}), ~s({}), ~s({"Allow":true,"Allow":false})] do
      server =
        serve_once(context.listener, fn socket, _request ->
          :gen_tcp.send(socket, response(200, body))
        end)

      assert HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, options(context)) ==
               {:error, :admission_denied}

      await_server(server)
    end
  end

  test "fails closed on non-200 and malformed decisions", context do
    non_200 =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(503, "unavailable"))
      end)

    assert HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, options(context)) ==
             {:error, {:admission_status, 503}}

    await_server(non_200)

    for body <- ["not-json", ~s({"Allow":"yes"})] do
      malformed =
        serve_once(context.listener, fn socket, _request ->
          :gen_tcp.send(socket, response(200, body))
        end)

      assert {:error, {:invalid_admission_response, _reason}} =
               HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, options(context))

      await_server(malformed)
    end
  end

  test "enforces the 4 KiB response cap even in fail-open mode", context do
    server =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, response(200, String.duplicate("x", 4_097)))
      end)

    assert HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, options(context)) ==
             {:error, {:invalid_admission_response, :response_body_too_large}}

    await_server(server)
  end

  test "fails closed when a response body is truncated", context do
    server =
      serve_once(context.listener, fn socket, _request ->
        :gen_tcp.send(socket, [
          "HTTP/1.1 200 OK\r\nContent-Length: 20\r\nConnection: close\r\n\r\n",
          "{}"
        ])
      end)

    assert HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, options(context)) ==
             {:error, {:invalid_admission_response, :closed}}

    await_server(server)
  end

  test "transport unavailability follows fail-open configuration", context do
    :gen_tcp.close(context.listener)
    unavailable_options = options(context)

    log =
      capture_log(fn ->
        assert :ok =
                 HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, unavailable_options)
      end)

    assert log =~ "admission controller is unavailable"

    assert {:error, {:admission_unavailable, _reason}} =
             HTTPAdmission.admit(
               @node_key,
               {127, 0, 0, 1},
               Keyword.put(unavailable_options, :fail_open, false)
             )
  end

  test "rate-limits the admission-unavailable warning", context do
    :gen_tcp.close(context.listener)
    unavailable_options = options(context)

    log =
      capture_log(fn ->
        Enum.each(1..100, fn _attempt ->
          assert :ok = HTTPAdmission.admit(@node_key, {127, 0, 0, 1}, unavailable_options)
        end)
      end)

    warnings =
      log
      |> String.split("admission controller is unavailable")
      |> length()
      |> Kernel.-(1)

    assert warnings == 1
  end

  test "validates absolute controller URLs" do
    assert {:ok, %URI{scheme: "https", host: "admit.example.com"}} =
             HTTPAdmission.parse_url("https://admit.example.com/check")

    for invalid <- ["", "/relative", "ftp://example.com/check", "http:///missing-host"] do
      assert HTTPAdmission.parse_url(invalid) == {:error, :invalid_admission_url}
    end
  end

  test "verifies an HTTPS controller certificate and decision" do
    assert {:ok, {certificate, private_key}} = Manual.generate_ip("127.0.0.1")

    {:ok, listener} =
      :ssl.listen(0,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.3"],
        certs_keys: [
          %{
            cert: [certificate],
            key: {:RSAPrivateKey, :public_key.der_encode(:RSAPrivateKey, private_key)}
          }
        ]
      )

    {:ok, {{127, 0, 0, 1}, port}} = :ssl.sockname(listener)
    on_exit(fn -> :ssl.close(listener) end)

    server =
      Task.async(fn ->
        {:ok, transport_socket} = :ssl.transport_accept(listener, 1_000)
        {:ok, socket} = :ssl.handshake(transport_socket, 1_000)

        try do
          {:ok, _request} = receive_ssl_request(socket, "")
          :ssl.send(socket, response(200, ~s({"Allow":true})))
        after
          :ssl.close(socket)
        end
      end)

    verify_test_certificate = fn otp_certificate, der_certificate, event, state ->
      case event do
        {:bad_cert, :selfsigned_peer} ->
          if der_certificate == certificate and
               :public_key.pkix_verify_hostname(otp_certificate, ip: {127, 0, 0, 1}) do
            {:valid, state}
          else
            {:fail, event}
          end

        {:bad_cert, _reason} ->
          {:fail, event}

        {:extension, _extension} ->
          {:unknown, state}

        valid when valid in [:valid, :valid_peer] ->
          {:valid, state}
      end
    end

    assert :ok =
             HTTPAdmission.admit(
               @node_key,
               {2001, 0xDB8, 0, 0, 0, 0, 0, 7},
               url: "https://127.0.0.1:#{port}/admit",
               fail_open: false,
               timeout_ms: 1_000,
               tls_options: [
                 cacerts: [certificate],
                 verify_fun: {verify_test_certificate, nil}
               ]
             )

    await_server(server)
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

  defp receive_request(socket, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {head_length, 4} ->
        <<head::binary-size(^head_length), "\r\n\r\n", read_ahead::binary>> = buffer
        content_length = content_length(head)

        with {:ok, body} <- receive_exact(socket, read_ahead, content_length) do
          {:ok, {head <> "\r\n\r\n", body}}
        end

      :nomatch ->
        with {:ok, data} <- :gen_tcp.recv(socket, 0, 1_000) do
          receive_request(socket, buffer <> data)
        end
    end
  end

  defp content_length(head) do
    [_, length] = Regex.run(~r/\r\nContent-Length: (\d+)\r\n/, "\r\n" <> head <> "\r\n")
    String.to_integer(length)
  end

  defp receive_ssl_request(socket, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {head_length, 4} ->
        <<head::binary-size(^head_length), "\r\n\r\n", read_ahead::binary>> = buffer
        receive_ssl_exact(socket, read_ahead, content_length(head))

      :nomatch ->
        with {:ok, data} <- :ssl.recv(socket, 0, 1_000) do
          receive_ssl_request(socket, buffer <> data)
        end
    end
  end

  defp receive_ssl_exact(_socket, buffer, length) when byte_size(buffer) >= length,
    do: {:ok, binary_part(buffer, 0, length)}

  defp receive_ssl_exact(socket, buffer, length) do
    with {:ok, data} <- :ssl.recv(socket, 0, 1_000) do
      receive_ssl_exact(socket, buffer <> data, length)
    end
  end

  defp receive_exact(_socket, buffer, length) when byte_size(buffer) >= length,
    do: {:ok, binary_part(buffer, 0, length)}

  defp receive_exact(socket, buffer, length) do
    with {:ok, data} <- :gen_tcp.recv(socket, 0, 1_000) do
      receive_exact(socket, buffer <> data, length)
    end
  end

  defp response(status, body) do
    [
      "HTTP/1.1 #{status} Response\r\n",
      "Content-Length: #{byte_size(body)}\r\n",
      "Connection: close\r\n\r\n",
      body
    ]
  end

  defp options(context, path \\ "/admit") do
    [
      url: "http://127.0.0.1:#{context.port}#{path}",
      fail_open: true,
      timeout_ms: 500,
      max_response_bytes: 4_096
    ]
  end

  defp await_server(server), do: Task.await(server, 1_000)
end
