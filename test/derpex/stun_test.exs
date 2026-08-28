defmodule Derpex.STUNTest do
  use ExUnit.Case, async: true

  import Bitwise

  alias Derpex.STUN

  @transaction_id <<12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1>>

  test "responds to valid UDP requests and ignores other datagrams" do
    server = start_supervised!({STUN, ip: {127, 0, 0, 1}, port: 0})
    {:ok, {{127, 0, 0, 1}, server_port}} = STUN.local_address(server)
    {:ok, socket} = :gen_udp.open(0, [:binary, active: false, ip: {127, 0, 0, 1}])
    on_exit(fn -> :gen_udp.close(socket) end)

    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, server_port, request(@transaction_id))
    {:ok, {{127, 0, 0, 1}, ^server_port, response}} = :gen_udp.recv(socket, 0, 1_000)

    assert <<0x0101::16, _length::16, 0x2112A442::32, @transaction_id, _attributes::binary>> =
             response

    :ok = :gen_udp.send(socket, {127, 0, 0, 1}, server_port, "not STUN")
    assert {:error, :timeout} = :gen_udp.recv(socket, 0, 25)
  end

  defp request(transaction_id) do
    fingerprint_input =
      <<0x0001::16, 20::16, 0x2112A442::32, transaction_id::binary, 0x8022::16, 8::16,
        "tailnode">>

    fingerprint = bxor(:erlang.crc32(fingerprint_input), 0x5354554E)
    fingerprint_input <> <<0x8028::16, 4::16, fingerprint::32>>
  end
end
