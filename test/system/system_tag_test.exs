defmodule Derpex.System.SystemTagTest do
  use ExUnit.Case, async: true

  @moduletag :system

  # The signal and send-freeze tests landed alongside this one, so it is no
  # longer holding the suite open. What it still does is check the mechanism
  # the other two rely on: that :system is both included and excluded here, so
  # these files run under `mix test.system` and never ride along with a plain
  # `mix test`. A tag that stopped working would otherwise show up as a suite
  # that silently got faster.
  test "the system suite only runs when its tag is included" do
    configuration = ExUnit.configuration()

    assert :system in configuration[:include]
    assert :system in configuration[:exclude]
  end
end
