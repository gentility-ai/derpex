defmodule DerpexTest do
  use ExUnit.Case, async: true

  test "reports the application version" do
    assert Derpex.version() == Mix.Project.config()[:version]
  end
end
