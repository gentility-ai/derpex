defmodule Derpex.TCPInfoTest do
  use ExUnit.Case, async: true

  alias Derpex.TCPInfo

  test "decodes Linux tcpi_rtt at its stable native-layout offset" do
    info = [:binary.copy(<<0>>, 68), <<12_345::32-native>>, :binary.copy(<<0>>, 32)]

    assert TCPInfo.decode(IO.iodata_to_binary(info)) == {:ok, 12_345}
    assert TCPInfo.decode(:binary.copy(<<0>>, 71)) == {:error, :invalid_tcp_info}
  end

  test "allows bounded socket reads to be injected without platform assumptions" do
    reader = fn :socket -> {:ok, 4_321} end
    assert TCPInfo.supported?(reader: reader)
    assert TCPInfo.rtt_microseconds(:socket, reader: reader) == {:ok, 4_321}
  end
end
