defmodule Derpex.HTTPClientTest do
  use ExUnit.Case, async: true

  alias Derpex.HTTPClient

  @chunked "HTTP/1.1 200 OK\r\n" <>
             "Transfer-Encoding: chunked\r\n\r\n" <>
             "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"

  test "reassembles a chunked response split at every byte boundary" do
    # Each split lands the server's two writes in separate reads, so in turn
    # every "\r\n" chunk-size terminator and every "\r\n\r\n" head or trailer
    # terminator straddles a read boundary.
    for split <- 0..byte_size(@chunked) do
      <<first::binary-size(^split), second::binary>> = @chunked
      uri = serve([first, second])

      assert {:ok, {200, headers, "hello world"}} =
               HTTPClient.request(uri, "GET / HTTP/1.1\r\nHost: test\r\n\r\n"),
             "chunked response split after #{split} bytes was misparsed"

      assert HTTPClient.header(headers, "transfer-encoding") == "chunked"
    end
  end

  test "reports a response head larger than the client bound" do
    head = "HTTP/1.1 200 OK\r\nX-Filler: " <> :binary.copy("f", 32_768) <> "\r\n\r\n"
    uri = serve([head])

    assert {:error, {:response_head, :response_head_too_large}} =
             HTTPClient.request(uri, "GET / HTTP/1.1\r\nHost: test\r\n\r\n")
  end

  defp serve(writes) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        ip: {127, 0, 0, 1},
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true
      ])

    {:ok, port} = :inet.port(listen)

    spawn_link(fn ->
      {:ok, socket} = :gen_tcp.accept(listen, 5_000)
      {:ok, _request_head} = :gen_tcp.recv(socket, 0, 5_000)

      Enum.each(writes, fn write ->
        :ok = :gen_tcp.send(socket, write)
        # Force the next write into a read of its own on the client side.
        Process.sleep(2)
      end)

      :gen_tcp.close(socket)
      :gen_tcp.close(listen)
    end)

    URI.parse("http://127.0.0.1:#{port}/")
  end
end
