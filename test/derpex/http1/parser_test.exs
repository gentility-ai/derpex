defmodule Derpex.HTTP1.ParserTest do
  use ExUnit.Case, async: true

  alias Derpex.HTTP1.Parser
  alias Derpex.HTTP1.Request

  @request "GET /derp?region=1 HTTP/1.1\r\nHost: derp.example\r\nUpgrade: DERP\r\nX-Test: one\r\nX-Test: two\r\n\r\nread-ahead"

  test "parses every chunk boundary and preserves read-ahead bytes" do
    for split <- 0..byte_size(@request) do
      <<first::binary-size(^split), second::binary>> = @request
      parser = Parser.new()

      result =
        case Parser.push(parser, first) do
          {:more, parser} ->
            Parser.push(parser, second)

          {:ok, request, read_ahead, parser} ->
            {:ok, request, read_ahead <> second, parser}
        end

      assert {:ok, request, "read-ahead", _parser} = result
      assert request.method == "GET"
      assert Request.path(request) == "/derp"
      assert Request.header(request, "UPGRADE") == "DERP"
      assert Request.header(request, "x-test") == "one"
    end
  end

  test "enforces request-line, header-count, and total-byte limits" do
    parser = Parser.new(max_request_line_bytes: 4)
    assert Parser.push(parser, "GET / HTTP/1.1\r\n\r\n") == {:error, :request_line_too_large}

    parser = Parser.new(max_headers: 1)

    assert Parser.push(parser, "GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n") ==
             {:error, :too_many_headers}

    parser = Parser.new(max_header_bytes: 16)
    assert Parser.push(parser, :binary.copy("x", 16)) == {:error, :headers_too_large}
  end

  test "rejects invalid methods, versions, names, and control bytes" do
    assert Parser.push(Parser.new(), "G ET / HTTP/1.1\r\n\r\n") ==
             {:error, :invalid_request_line}

    assert Parser.push(Parser.new(), "GET / HTTP/2\r\n\r\n") ==
             {:error, :invalid_request_line}

    assert Parser.push(Parser.new(), "GET / HTTP/1.1\r\nBad Name: x\r\n\r\n") ==
             {:error, :invalid_header}

    assert Parser.push(Parser.new(), "GET / HTTP/1.1\r\nX: bad\0value\r\n\r\n") ==
             {:error, :invalid_header}
  end

  test "scans only the new bytes for the header terminator" do
    header_bytes = 400 * 1_024
    prefix = "GET / HTTP/1.1\r\nHost: derp.example\r\nX-Filler: "
    filler = :binary.copy("f", header_bytes - byte_size(prefix))

    {microseconds, result} =
      :timer.tc(fn ->
        prefix
        |> Kernel.<>(filler)
        |> push_one_byte_at_a_time(Parser.new())
      end)

    assert {:more, parser} = result
    assert {:ok, request, "", _parser} = Parser.push(parser, "\r\n\r\n")
    assert Request.header(request, "x-filler") == filler

    assert div(microseconds, 1_000) < 200,
           "one-byte-at-a-time push of #{header_bytes} header bytes took #{div(microseconds, 1_000)} ms"
  end

  test "still enforces max_header_bytes across incremental pushes" do
    parser = Parser.new(max_header_bytes: 32)

    assert {:error, :headers_too_large} =
             push_one_byte_at_a_time(:binary.copy("x", 64), parser)
  end

  defp push_one_byte_at_a_time(<<>>, parser), do: {:more, parser}

  defp push_one_byte_at_a_time(<<byte, rest::binary>>, parser) do
    case Parser.push(parser, <<byte>>) do
      {:more, parser} -> push_one_byte_at_a_time(rest, parser)
      other -> other
    end
  end
end
