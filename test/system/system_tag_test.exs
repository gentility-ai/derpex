defmodule Derpex.System.SystemTagTest do
  use ExUnit.Case, async: true

  @moduletag :system

  # Placeholder inhabitant of the system suite until the SIGHUP test lands. It
  # keeps `mix test.system` exercising a real ExUnit run and proves the suite
  # never rides along with a plain `mix test`.
  test "the system suite only runs when its tag is included" do
    configuration = ExUnit.configuration()

    assert :system in configuration[:include]
    assert :system in configuration[:exclude]
  end
end
