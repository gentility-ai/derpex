defmodule Derpex.SendQueueConfigTest do
  use ExUnit.Case, async: true

  alias Derpex.SendQueueConfig

  test "matches the upstream default, empty, and explicit depth behavior" do
    assert SendQueueConfig.default_depth() == 32
    assert SendQueueConfig.parse(nil) == {:ok, 32}
    assert SendQueueConfig.parse("") == {:ok, 32}
    assert SendQueueConfig.parse("64") == {:ok, 64}
  end

  test "rejects values that cannot back a fixed-capacity ring" do
    assert SendQueueConfig.parse("0") == {:error, :invalid_send_queue_depth}
    assert SendQueueConfig.parse("-1") == {:error, :invalid_send_queue_depth}
    assert SendQueueConfig.parse("64 packets") == {:error, :invalid_send_queue_depth}
    assert_raise ArgumentError, fn -> SendQueueConfig.validate!(0) end
  end
end
