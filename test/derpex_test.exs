defmodule DerpexTest do
  use ExUnit.Case, async: true

  test "reports the application version" do
    assert Derpex.version() == "0.1.0-dev"
  end
end
