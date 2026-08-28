defmodule Derpex.DiscoTest do
  use ExUnit.Case, async: true

  alias Derpex.Disco

  test "recognizes only sufficiently long packets with the discovery magic" do
    magic = <<0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC>>

    assert Disco.looks_like_wrapper?(magic <> :binary.copy(<<0>>, 56))
    refute Disco.looks_like_wrapper?(magic <> :binary.copy(<<0>>, 55))
    refute Disco.looks_like_wrapper?(<<0>> <> :binary.copy(<<0>>, 61))
  end
end
