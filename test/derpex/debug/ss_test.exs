defmodule Derpex.Debug.SSTest do
  use ExUnit.Case, async: true

  alias Derpex.Debug.SS

  test "parses numeric IPv4 and IPv6 endpoints with byte counters" do
    output = """
    ESTAB 0 0 10.0.0.1:443 192.0.2.8:58145
      cubic rtt:1 bytes_sent:1591815 bytes_acked:1590791 bytes_received:158925
    ESTAB 0 0 [2001:db8::1]:443 [2001:db8::2]:4242
      cubic bytes_received:42 bytes_sent:99
    """

    assert SS.parse(output) == %{
             {{192, 0, 2, 8}, 58_145} => %{sent: 1_591_815, received: 158_925},
             {{0x2001, 0xDB8, 0, 0, 0, 0, 0, 2}, 4_242} => %{sent: 99, received: 42}
           }
  end

  test "skips service names and malformed pairs like the upstream parser" do
    output = """
    ESTAB 0 0 10.0.0.1:443 192.0.2.8:https
      cubic bytes_sent:bad bytes_received:12
    incomplete
      bytes_sent:1
    """

    assert SS.parse(output) == %{}
  end
end
