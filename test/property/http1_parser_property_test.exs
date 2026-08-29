defmodule Derpex.HTTP1.ParserPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Derpex.HTTP1.Parser
  alias Derpex.HTTP1.Request

  @moduletag :property

  # Small enough that the generators reach the cap, large enough for a realistic
  # request head to still fit.
  @max_header_bytes 512

  # A process that trickles gigabytes through the parser may still reference the
  # fixture binaries it started with, and nothing else.
  @leak_budget 2 * 1_024 * 1_024

  @token_bytes ~c"abcdefgABCDEFG0189!#$%&'*+-.^_`|~"
  @target_bytes ~c"/abcXYZ019?=&%-._~:@"
  @value_bytes ~c"abcXYZ019/;=,\"\\(){}[]<>@?-_.:!"

  property "arbitrary chunking parses to the same request as the whole head" do
    check all {head, request} <- request_head(),
              body <- binary(max_length: 24),
              sizes <- list_of(integer(0..8), max_length: 80) do
      stream = head <> body

      assert {:ok, whole, read_ahead, parser} = Parser.push(Parser.new(), stream)
      assert whole == request
      assert read_ahead == body
      assert parser.buffer == ""

      assert {:ok, ^request, ^body} = feed(Parser.new(), chunk(stream, sizes))
    end
  end

  property "an incomplete head is never mistaken for a complete one" do
    check all {head, _request} <- request_head(),
              sizes <- list_of(integer(0..8), max_length: 80) do
      chunks = chunk(head, sizes)

      for prefix <- partial_prefixes(chunks, byte_size(head)) do
        assert {:more, parser} = feed(Parser.new(), prefix)
        assert byte_size(parser.buffer) == Enum.sum_by(prefix, &byte_size/1)
      end
    end
  end

  property "arbitrary bytes never raise and stay inside the header cap" do
    check all chunks <- list_of(head_bytes(), max_length: 24) do
      Enum.reduce_while(chunks, parser(), fn chunk, parser ->
        case Parser.push(parser, chunk) do
          {:more, parser} ->
            assert byte_size(parser.buffer) < @max_header_bytes
            {:cont, parser}

          {:ok, %Request{} = request, read_ahead, parser} ->
            assert is_binary(request.method)
            assert is_binary(read_ahead)
            assert parser.buffer == ""
            {:halt, parser}

          {:error, reason} ->
            assert is_atom(reason)
            {:halt, parser()}
        end
      end)
    end
  end

  property "rejects rather than buffers a head that outgrows the cap" do
    check all padding <- integer(@max_header_bytes..(4 * @max_header_bytes)),
              sizes <- list_of(integer(1..64), max_length: 80) do
      head = "GET / HTTP/1.1\r\nX-Pad: " <> String.duplicate("p", padding) <> "\r\n\r\n"

      assert {:error, :headers_too_large} = feed(parser(), chunk(head, sizes))
    end
  end

  test "trickling many oversized heads keeps binary memory bounded" do
    chunk = String.duplicate("p", 1_024)
    head_chunks = List.duplicate(chunk, 64)
    iterations = 600
    before = referenced_binary_bytes()

    for _iteration <- 1..iterations do
      parser = Parser.new(max_header_bytes: 1_024 * 1_024)
      assert {:more, parser} = feed(parser, ["GET / HTTP/1.1\r\nX-Pad: " | head_chunks])
      assert byte_size(parser.buffer) < 1_024 * 1_024
      assert {:ok, %Request{}, "", _parser} = Parser.push(parser, "\r\n\r\n")
    end

    assert iterations * length(head_chunks) * byte_size(chunk) > 32 * 1_024 * 1_024
    assert referenced_binary_bytes() - before < @leak_budget
  end

  defp parser, do: Parser.new(max_header_bytes: @max_header_bytes)

  defp request_head do
    gen all method <- token(8),
            target <- bytes(@target_bytes, 1, 24),
            version <- member_of(["HTTP/1.0", "HTTP/1.1"]),
            headers <- list_of(header(), max_length: 6) do
      lines = ["#{method} #{target} #{version}" | Enum.map(headers, &header_line/1)]
      head = Enum.join(lines, "\r\n") <> "\r\n\r\n"

      request = %Request{
        method: method,
        target: target,
        version: version,
        headers: Enum.map(headers, fn {name, _ows, value} -> {String.downcase(name), value} end)
      }

      {head, request}
    end
  end

  defp header do
    gen all name <- token(12),
            leading <- bytes(~c" \t", 0, 3),
            value <- bytes(@value_bytes, 0, 24),
            trailing <- bytes(~c" \t", 0, 3) do
      {name, {leading, trailing}, value}
    end
  end

  defp header_line({name, {leading, trailing}, value}) do
    name <> ":" <> leading <> value <> trailing
  end

  defp token(max_length), do: bytes(@token_bytes, 1, max_length)

  # `list_of(max_length: n)` is also bounded by the generation size, which stays
  # near 100 for a default run count. Driving the length with an integer reaches
  # the declared length on every run.
  defp bytes(alphabet, min_length, max_length) do
    letters = member_of(Enum.map(alphabet, &<<&1>>))

    bind(integer(min_length..max_length), fn length ->
      map(list_of(letters, length: length), &IO.iodata_to_binary/1)
    end)
  end

  defp head_bytes do
    one_of([
      binary(max_length: 48),
      constant("\r\n"),
      constant("\r\n\r\n"),
      map(request_head(), fn {head, _request} -> head end),
      map(integer(0..3), &String.duplicate("A", @max_header_bytes * &1))
    ])
  end

  defp feed(parser, []), do: {:more, parser}

  defp feed(parser, [chunk | rest]) do
    case Parser.push(parser, chunk) do
      {:more, parser} ->
        feed(parser, rest)

      {:ok, request, read_ahead, _parser} ->
        {:ok, request, IO.iodata_to_binary([read_ahead | rest])}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp partial_prefixes(chunks, head_length) do
    0..length(chunks)
    |> Enum.map(&Enum.take(chunks, &1))
    |> Enum.filter(&(Enum.sum_by(&1, fn chunk -> byte_size(chunk) end) < head_length))
  end

  defp chunk("", _sizes), do: []
  defp chunk(binary, []), do: [binary]

  defp chunk(binary, [size | sizes]) do
    size = min(size, byte_size(binary))
    <<head::binary-size(^size), tail::binary>> = binary
    [head | chunk(tail, sizes)]
  end

  # `:erlang.memory(:binary)` is VM-global and moves under any concurrent test;
  # the refc binaries this process still holds after a collection are the signal
  # a retained buffer would show up in.
  defp referenced_binary_bytes do
    :erlang.garbage_collect()
    {:binary, references} = Process.info(self(), :binary)
    Enum.sum_by(references, &elem(&1, 1))
  end
end
