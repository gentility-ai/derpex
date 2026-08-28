defmodule Derpex.STUN.Protocol do
  @moduledoc "Tailscale-compatible STUN request validation and binding responses."

  import Bitwise

  @binding_request 0x0001
  @binding_success 0x0101
  @magic_cookie <<0x21, 0x12, 0xA4, 0x42>>
  @magic_cookie_integer 0x2112A442
  @software_attribute 0x8022
  @fingerprint_attribute 0x8028
  @xor_mapped_address 0x0020
  @software "tailnode"
  @fingerprint_xor 0x5354554E

  @type transaction_id :: <<_::96>>

  @doc "Returns the transaction ID only for a fingerprinted Tailscale binding request."
  @spec parse_request(binary()) :: {:ok, transaction_id()} | {:error, atom()}
  def parse_request(
        <<@binding_request::unsigned-big-16, _declared_length::unsigned-big-16, @magic_cookie,
          transaction_id::binary-size(12), attributes::binary>> = packet
      ) do
    fingerprint_input_length = byte_size(packet) - 8

    with {:ok, software?, @fingerprint_attribute, fingerprint} <-
           parse_attributes(attributes, false, nil, nil),
         true <- software?,
         true <- byte_size(packet) >= 28,
         <<fingerprint_input::binary-size(^fingerprint_input_length),
           @fingerprint_attribute::unsigned-big-16, 4::unsigned-big-16,
           ^fingerprint::unsigned-big-32>> <- packet,
         expected = bxor(:erlang.crc32(fingerprint_input), @fingerprint_xor),
         true <- fingerprint == expected do
      {:ok, transaction_id}
    else
      _invalid -> {:error, :invalid_stun_request}
    end
  end

  def parse_request(_packet), do: {:error, :invalid_stun_request}

  @doc "Builds a binding success response for an IPv4 or IPv6 UDP peer."
  @spec response(transaction_id(), :inet.ip_address(), :inet.port_number()) :: binary()
  def response(<<transaction_id::binary-size(12)>>, ip, port) when port in 0..65_535 do
    {family, address} = address_bytes(ip)
    xor_port = bxor(port, 0x2112)
    mask = @magic_cookie <> transaction_id
    xor_address = :crypto.exor(address, binary_part(mask, 0, byte_size(address)))
    attribute_value = <<0, family, xor_port::unsigned-big-16, xor_address::binary>>

    attribute =
      <<@xor_mapped_address::unsigned-big-16, byte_size(attribute_value)::unsigned-big-16,
        attribute_value::binary>>

    <<@binding_success::unsigned-big-16, byte_size(attribute)::unsigned-big-16,
      @magic_cookie_integer::unsigned-big-32, transaction_id::binary, attribute::binary>>
  end

  defp parse_attributes("", software?, last_type, fingerprint),
    do: {:ok, software?, last_type, fingerprint}

  defp parse_attributes(
         <<type::unsigned-big-16, length::unsigned-big-16, rest::binary>>,
         software?,
         _last_type,
         fingerprint
       ) do
    padded_length = band(length + 3, bnot(3))

    if byte_size(rest) >= padded_length do
      <<value_and_padding::binary-size(^padded_length), remaining::binary>> = rest
      <<value::binary-size(^length), _padding::binary>> = value_and_padding
      software? = software? or (type == @software_attribute and value == @software)

      fingerprint =
        case {type, value} do
          {@fingerprint_attribute, <<fingerprint::unsigned-big-32>>} -> fingerprint
          _other -> fingerprint
        end

      parse_attributes(remaining, software?, type, fingerprint)
    else
      {:error, :malformed_attributes}
    end
  end

  defp parse_attributes(_malformed, _software?, _last_type, _fingerprint),
    do: {:error, :malformed_attributes}

  defp address_bytes({a, b, c, d}),
    do: {1, <<a, b, c, d>>}

  defp address_bytes({0, 0, 0, 0, 0, 0xFFFF, a, b}),
    do: {1, <<a::unsigned-big-16, b::unsigned-big-16>>}

  defp address_bytes({a, b, c, d, e, f, g, h}),
    do: {2, <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>}
end
