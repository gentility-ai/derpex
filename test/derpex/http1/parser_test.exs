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
end
