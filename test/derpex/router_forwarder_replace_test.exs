defmodule Derpex.RouterForwarderReplaceTest do
  use ExUnit.Case, async: false

  alias Derpex.Outbox.Ring
  alias Derpex.Router

  test "re-registering a forwarder identity publishes the fresh ring" do
    key = :crypto.strong_rand_bytes(32)
    source = :crypto.strong_rand_bytes(32)
    identity = self()

    stale = Ring.new(4, notifier: self(), wake_message: :stale_ready)
    fresh = Ring.new(4, notifier: self(), wake_message: :fresh_ready)
    on_exit(fn -> Ring.delete(fresh) end)

    assert Router.add_forwarder(key, identity, stale) == :ok
    assert Ring.delete(stale) == :ok

    assert Router.add_forwarder(key, identity, fresh) == :ok
    on_exit(fn -> Router.remove_forwarder(key, identity) end)

    assert Router.route(source, key, "fresh") in [{:ok, :wake}, {:ok, :coalesced}]
    assert Ring.take(fresh) == {:ok, {:forward_packet, source, key, "fresh"}}
  end
end
