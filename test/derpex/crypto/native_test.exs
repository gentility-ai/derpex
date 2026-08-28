defmodule Derpex.Crypto.NativeTest do
  use ExUnit.Case, async: true

  test "loads the source-built NIF during development" do
    assert Derpex.Crypto.loaded?()
  end
end
