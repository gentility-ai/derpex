defmodule Derpex.ListenerCapsTest do
  @moduledoc """
  How the configured connection ceiling is divided between listeners.

  `DERPEX_MAX_CONNECTIONS` is what an operator sized for the DERP listener. A
  relay that also runs the plaintext challenge listener must not accept twice
  that between them, least of all with the extra headroom on the port that
  needs no authentication.
  """

  use ExUnit.Case, async: false

  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor
  alias Derpex.Secret

  setup do
    previous = Application.fetch_env(:derpex, :max_connections)

    on_exit(fn ->
      case previous do
        {:ok, value} -> Application.put_env(:derpex, :max_connections, value)
        :error -> Application.delete_env(:derpex, :max_connections)
      end
    end)

    Application.put_env(:derpex, :max_connections, 4_096)
    :ok
  end

  test "the DERP listener takes the configured ceiling and the challenge listener does not" do
    {_public, private} = Crypto.generate_keypair()

    challenge = [
      port: 0,
      num_acceptors: 4,
      max_connections: 256,
      transport_options: [ip: {127, 0, 0, 1}]
    ]

    derp = [port: 0, num_acceptors: 4, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [challenge_spec, derp_spec]}} =
             ListenerSupervisor.init({[challenge, derp], Secret.wrap(private)})

    assert connections(challenge_spec) == 64
    assert connections(derp_spec) == 1_024

    # Together they are the ceiling plus a small fixed allowance, not twice it.
    total = (connections(challenge_spec) + connections(derp_spec)) * 4
    assert total == 4_096 + 256
  end

  test "a listener without its own ceiling still divides the global one" do
    {_public, private} = Crypto.generate_keypair()
    listener = [port: 0, num_acceptors: 8, transport_options: [ip: {127, 0, 0, 1}]]

    assert {:ok, {_flags, [spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(private)})

    assert connections(spec) == 512
  end

  test "an explicit per-listener ceiling never reaches Thousand Island" do
    {_public, private} = Crypto.generate_keypair()

    listener = [
      port: 0,
      num_acceptors: 1,
      max_connections: 16,
      transport_options: [ip: {127, 0, 0, 1}]
    ]

    assert {:ok, {_flags, [spec]}} =
             ListenerSupervisor.init({[listener], Secret.wrap(private)})

    assert {ThousandIsland, :start_link, [options]} = spec.start
    refute Keyword.has_key?(options, :max_connections)
    assert Keyword.fetch!(options, :num_connections) == 16
  end

  defp connections(child_spec) do
    {ThousandIsland, :start_link, [options]} = child_spec.start
    Keyword.fetch!(options, :num_connections)
  end
end
