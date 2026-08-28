defmodule Derpex.OperationsTest do
  use ExUnit.Case, async: false

  alias Derpex.HTTP1.Request
  alias Derpex.Operations

  @token "0123456789abcdef0123456789abcdef"

  test "requires an explicitly configured constant-time bearer credential" do
    request = %Request{method: "GET", target: "/metrics", version: "HTTP/1.1", headers: []}

    assert Operations.authorize(request, []) == :disabled
    assert Operations.authorize(request, enabled: true, token: "short") == :disabled
    assert Operations.authorize(request, enabled: true, token: @token) == :unauthorized

    authorized = %{request | headers: [{"authorization", "Bearer " <> @token}]}
    assert Operations.authorize(authorized, enabled: true, token: @token) == :authorized
  end

  test "reports healthy aggregate state and deterministic fixed-cardinality metrics" do
    assert Operations.health(:live) == :ok
    assert Operations.health(:ready) == :ok
    assert Operations.consistency_check() == :ok

    metrics = Operations.prometheus()
    lines = String.split(metrics, "\n", trim: true)
    assert lines == Enum.sort(lines)
    assert metrics =~ "derp_gauge_current_connections "
    assert metrics =~ "derp_gauge_current_home_connections "
    assert metrics =~ ~s(derp_counter_packets_received_kind{kind="disco"} )
    assert metrics =~ "derpex_accept_tracked_ips "
    assert metrics =~ "derpex_vm_memory_bytes "
    refute metrics =~ "node_id"
    refute metrics =~ "organization_id"
    refute metrics =~ "source_ip"
  end
end
