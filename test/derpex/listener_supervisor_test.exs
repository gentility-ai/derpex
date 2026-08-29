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
end
