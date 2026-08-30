defmodule Derpex.STUN.ProtocolPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  import Bitwise

  alias Derpex.STUN.Protocol

  @moduletag :property

  @binding_request 0x0001
  @binding_success 0x0101
  @magic_cookie <<0x21, 0x12, 0xA4, 0x42>>
  @software_attribute 0x8022
  @fingerprint_attribute 0x8028
  @xor_mapped_address 0x0020
  @fingerprint_xor 0x5354554E

  # A process that parses tens of megabytes may still reference the fixture
  # packets it started with, and nothing else.
  @leak_budget 256 * 1_024

  property "every well-formed Tailscale binding request round trips its transaction ID" do
    check all transaction_id <- binary(length: 12),
              declared_length <- integer(0..65_535),
              padding <- list_of(attribute(), max_length: 4),
              seed <- integer(0..3) do
      attributes = insert_software(padding, seed)

      assert Protocol.parse_request(request(transaction_id, attributes, declared_length)) ==
               {:ok, transaction_id}
    end
  end

  property "a request without the tailnode software attribute is rejected" do
    check all transaction_id <- binary(length: 12),
              software <- filter(binary(max_length: 16), &(&1 != "tailnode")) do
      attributes = [{@software_attribute, software}]

      assert Protocol.parse_request(request(transaction_id, attributes)) ==
               {:error, :invalid_stun_request}
    end
  end

  property "any single flipped bit invalidates the fingerprint" do
    check all transaction_id <- binary(length: 12),
              offset <- integer(0..39),
              bit <- integer(0..7) do
      packet = request(transaction_id, [{@software_attribute, "tailnode"}])
      offset = rem(offset, byte_size(packet))

      <<prefix::binary-size(^offset), byte, suffix::binary>> = packet
      flipped = <<prefix::binary, bxor(byte, 1 <<< bit), suffix::binary>>

      assert Protocol.parse_request(flipped) == {:error, :invalid_stun_request}
    end
  end

  property "trailing bytes after the fingerprint are rejected" do
    check all transaction_id <- binary(length: 12),
              trailer <- binary(min_length: 1, max_length: 16) do
      packet = request(transaction_id, [{@software_attribute, "tailnode"}])

      assert Protocol.parse_request(packet <> trailer) == {:error, :invalid_stun_request}
    end
  end

  property "arbitrary bytes never raise" do
    check all packet <- packet_bytes() do
      case Protocol.parse_request(packet) do
        {:ok, transaction_id} -> assert byte_size(transaction_id) == 12
        {:error, reason} -> assert reason == :invalid_stun_request
      end
    end
  end

  property "binding responses round trip the peer address and port" do
    check all transaction_id <- binary(length: 12),
              ip <- ip_address(),
              port <- integer(0..65_535) do
      response = Protocol.response(transaction_id, ip, port)

      assert read_response(response) == {transaction_id, family(ip), address_bytes(ip), port}
    end
  end

  property "an IPv4-mapped IPv6 peer encodes as its IPv4 address" do
    check all transaction_id <- binary(length: 12),
              {a, b, c, d} <- ipv4(),
              port <- integer(0..65_535) do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, a * 256 + b, c * 256 + d}

      assert Protocol.response(transaction_id, mapped, port) ==
               Protocol.response(transaction_id, {a, b, c, d}, port)
    end
  end

  test "parsing many large packets keeps binary memory bounded" do
    packets =
      Enum.map(1..8, fn index ->
        request(<<0::96>>, [
          {@software_attribute, "tailnode"},
          {0x0006, String.duplicate("p", 4 * 1_024 * index)}
        ])
      end)

    iterations = 1_500
    before = referenced_binary_bytes()

    for _iteration <- 1..iterations, packet <- packets do
      assert Protocol.parse_request(packet) == {:ok, <<0::96>>}
    end

    assert iterations * Enum.sum_by(packets, &byte_size/1) > 32 * 1_024 * 1_024
    assert referenced_binary_bytes() - before < @leak_budget
  end

  defp attribute do
    gen all type <- attribute_type(),
            value <- binary(max_length: 24) do
      {type, value}
    end
  end

  defp attribute_type do
    filter(integer(0..0xFFFF), &(&1 not in [@software_attribute, @fingerprint_attribute]))
  end

  defp insert_software(attributes, position) do
    {before, rest} = Enum.split(attributes, position)
    before ++ [{@software_attribute, "tailnode"}] ++ rest
  end

  defp request(transaction_id, attributes, declared_length \\ nil) do
    encoded = Enum.map_join(attributes, "", &encode_attribute/1)
    declared_length = declared_length || byte_size(encoded) + 8

    prefix =
      <<@binding_request::unsigned-big-16, declared_length::unsigned-big-16, @magic_cookie,
        transaction_id::binary, encoded::binary>>

    fingerprint = bxor(:erlang.crc32(prefix), @fingerprint_xor)
    prefix <> <<@fingerprint_attribute::unsigned-big-16, 4::unsigned-big-16, fingerprint::32>>
  end

  defp encode_attribute({type, value}) do
    padding = :binary.copy(<<0>>, rem(4 - rem(byte_size(value), 4), 4))

    <<type::unsigned-big-16, byte_size(value)::unsigned-big-16, value::binary, padding::binary>>
  end

  defp packet_bytes do
    one_of([
      binary(max_length: 64),
      map(binary(length: 12), &request(&1, [{@software_attribute, "tailnode"}])),
      map(binary(length: 12), &request(&1, [{@software_attribute, "somebody"}])),
      map(
        binary(max_length: 24),
        &(<<@binding_request::unsigned-big-16, 0::unsigned-big-16>> <> &1)
      ),
      map(
        binary(max_length: 24),
        &(<<@binding_request::unsigned-big-16, 0xFFFF::unsigned-big-16, @magic_cookie, 0::96>> <>
            &1)
      )
    ])
  end

  # A hand-rolled reader of RFC 5389 XOR-MAPPED-ADDRESS, independent of
  # `Derpex.STUN.Protocol`.
  defp read_response(response) do
    <<@binding_success::unsigned-big-16, length::unsigned-big-16, @magic_cookie,
      transaction_id::binary-size(12), attributes::binary>> = response

    assert byte_size(attributes) == length

    <<@xor_mapped_address::unsigned-big-16, value_length::unsigned-big-16, value::binary>> =
      attributes

    assert byte_size(value) == value_length

    <<0, family, xor_port::unsigned-big-16, xor_address::binary>> = value
    mask = @magic_cookie <> transaction_id
    address = :crypto.exor(xor_address, binary_part(mask, 0, byte_size(xor_address)))

    {transaction_id, family, address, bxor(xor_port, 0x2112)}
  end

  defp ip_address, do: one_of([ipv4(), ipv6()])

  defp ipv4 do
    gen all bytes <- list_of(integer(0..255), length: 4) do
      List.to_tuple(bytes)
    end
  end

  # The `::ffff:0:0/96` prefix has its own property; here it would collide with
  # the IPv4 encoding.
  defp ipv6 do
    gen all head <- integer(1..0xFFFF),
            tail <- list_of(integer(0..0xFFFF), length: 7) do
      List.to_tuple([head | tail])
    end
  end

  defp family({_a, _b, _c, _d}), do: 1
  defp family(_ip), do: 2

  defp address_bytes({a, b, c, d}), do: <<a, b, c, d>>

  defp address_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end

  # `:erlang.memory(:binary)` is VM-global and moves under any concurrent test;
  # the refc binaries this process still holds after a collection are the signal
  # a retained packet would show up in.
  defp referenced_binary_bytes do
    :erlang.garbage_collect()
    {:binary, references} = Process.info(self(), :binary)
    Enum.sum_by(references, &elem(&1, 1))
  end
end
