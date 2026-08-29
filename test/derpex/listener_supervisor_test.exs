defmodule Derpex.ListenerSupervisorTest do
  use ExUnit.Case, async: true

  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor
  alias Derpex.Secret

  test "derives the server public key once per listener into its handler options" do
    {server_public, server_private} = Crypto.generate_keypair()
    listener = [port: 0, num_acceptors: 1, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    handler_options = Keyword.fetch!(options, :handler_options)

    assert Keyword.fetch!(handler_options, :server_public_key) == server_public
  end

  test "a configured socket write timeout reaches the handler that must respect it" do
    {_server_public, server_private} = Crypto.generate_keypair()

    listener = [
      port: 0,
      num_acceptors: 1,
      transport_options: [ip: {127, 0, 0, 1}],
      socket_options: [write_timeout_ms: 10_000]
    ]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start
    handler_options = Keyword.fetch!(options, :handler_options)
    transport_options = Keyword.fetch!(options, :transport_options)

    # The handler's control writes and the socket itself follow the same
    # deadline; a control write that gave up first would abandon a write the
    # socket was still allowed to be making.
    assert Keyword.fetch!(handler_options, :write_timeout_ms) == 10_000
    assert Keyword.fetch!(transport_options, :send_timeout) == 10_000
  end

  test "an unconfigured listener hands the handler the pinned default" do
    {_server_public, server_private} = Crypto.generate_keypair()
    listener = [port: 0, num_acceptors: 1, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [child_spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(server_private)})

    assert {ThousandIsland, :start_link, [options]} = child_spec.start

    assert Keyword.fetch!(Keyword.fetch!(options, :handler_options), :write_timeout_ms) ==
             Derpex.SocketOptions.default_write_timeout_ms()
  end
end
