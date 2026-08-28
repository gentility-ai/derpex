defmodule Derpex.STUN.ProtocolTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Derpex.STUN.Protocol

  @fingerprint_xor 0x5354554E
  @transaction_id <<1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12>>

  test "accepts the official Tailscale binding request shape" do
    assert Protocol.parse_request(request(@transaction_id)) == {:ok, @transaction_id}
  end

  test "matches upstream handling of the unused declared attribute length" do
    assert Protocol.parse_request(request(@transaction_id, "tailnode", 255)) ==
             {:ok, @transaction_id}
  end

  test "requires tailnode software and a valid final fingerprint" do
    assert {:error, :invalid_stun_request} =
             Protocol.parse_request(request(@transaction_id, "somebody"))

    request = request(@transaction_id)
    prefix_length = byte_size(request) - 1
    <<prefix::binary-size(^prefix_length), last>> = request

    assert {:error, :invalid_stun_request} = Protocol.parse_request(prefix <> <<bxor(last, 1)>>)

    assert {:error, :invalid_stun_request} =
             Protocol.parse_request(request <> <<0x80, 0x01, 0, 0>>)
  end

  test "generates the canonical IPv4 XOR-MAPPED-ADDRESS response" do
    expected =
      <<
        0x0101::16,
        12::16,
        0x2112A442::32,
        @transaction_id,
        0x0020::16,
        8::16,
        0,
        1,
        0x112B::16,
        0xE1,
        0x12,
        0xA6,
        0x43
      >>

    assert Protocol.response(@transaction_id, {192, 0, 2, 1}, 12_345) == expected

    assert Protocol.response(@transaction_id, {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}, 12_345) ==
             expected
  end

  test "generates the canonical IPv6 XOR-MAPPED-ADDRESS response" do
    assert Protocol.response(@transaction_id, {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, 3_478) ==
             <<
               0x0101::16,
               24::16,
               0x2112A442::32,
               @transaction_id,
               0x0020::16,
               20::16,
               0,
               2,
               0x2C84::16,
               0x01,
               0x13,
               0xA9,
               0xFA,
               1,
               2,
               3,
               4,
               5,
               6,
               7,
               8,
               9,
               10,
               11,
               13
             >>
  end

  defp request(transaction_id, software \\ "tailnode", declared_length \\ nil) do
    software_attribute = <<0x8022::16, byte_size(software)::16, software::binary>>
    attributes_length = byte_size(software_attribute) + 8
    declared_length = declared_length || attributes_length

    fingerprint_input =
      <<0x0001::16, declared_length::16, 0x2112A442::32, transaction_id::binary,
        software_attribute::binary>>

    fingerprint = bxor(:erlang.crc32(fingerprint_input), @fingerprint_xor)
    fingerprint_input <> <<0x8028::16, 4::16, fingerprint::32>>
  end
end
