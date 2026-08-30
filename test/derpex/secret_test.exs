defmodule Derpex.SecretTest do
  use ExUnit.Case, async: false

  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor
  alias Derpex.Mesh.Client
  alias Derpex.Secret

  test "wraps binaries and nil but refuses an already-wrapped secret" do
    secret = Secret.wrap("key material")

    assert is_function(secret, 0)
    assert Secret.reveal(secret) == "key material"
    assert Secret.wrap(nil) == nil
    assert Secret.reveal(nil) == nil

    assert_raise FunctionClauseError, fn -> Secret.wrap(opaque(secret)) end
  end

  test "refuses to reveal a raw binary that was never wrapped" do
    assert_raise FunctionClauseError, fn -> Secret.reveal(opaque("key material")) end
  end

  test "renders as a function rather than its bytes" do
    private_key = :crypto.strong_rand_bytes(32)
    rendered = inspect(Secret.wrap(private_key), limit: :infinity, structs: false)

    assert rendered =~ "#Function<"
    refute_secret(rendered, private_key)
  end

  test "keeps listener key material out of every supervised process state" do
    {_server_public, server_private} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    listener = [
      port: 0,
      num_acceptors: 1,
      transport_options: [ip: {127, 0, 0, 1}],
      handler_options: [mesh_key: Secret.wrap(mesh_key)]
    ]

    supervisor =
      start_supervised!({ListenerSupervisor, {[listener], Secret.wrap(server_private)}})

    [{_id, listener_pid, _type, _modules}] = Supervisor.which_children(supervisor)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(listener_pid)

    {:ok, socket} =
      :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false], 1_000)

    on_exit(fn -> :gen_tcp.close(socket) end)

    states = await_connection_state(supervisor)
    rendered = inspect(states, limit: :infinity, structs: false)

    refute_secret(rendered, server_private)
    refute_secret(rendered, mesh_key)
  end

  test "keeps mesh client key material out of its process state" do
    {_public_key, private_key} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, reuseaddr: true])

    {:ok, {_ip, unavailable_port}} = :inet.sockname(listener)
    :gen_tcp.close(listener)

    client =
      start_supervised!(
        {Client,
         url: "http://127.0.0.1:#{unavailable_port}/derp",
         private_key: Secret.wrap(private_key),
         mesh_key: Secret.wrap(mesh_key),
         connect_timeout: 250,
         reconnect_interval: 60_000}
      )

    rendered = inspect(:sys.get_state(client), limit: :infinity, structs: false)

    refute_secret(rendered, private_key)
    refute_secret(rendered, mesh_key)
  end

  # Returns the same term with a type the compiler cannot narrow, so a
  # deliberate misuse below is checked at run time instead of being reported
  # as a compile-time type warning.
  defp opaque(term), do: :erlang.binary_to_term(:erlang.term_to_binary(term))

  defp refute_secret(rendered, key) do
    refute rendered =~ Base.encode16(key)
    refute rendered =~ Base.encode16(key, case: :lower)
    refute rendered =~ inspect(key, limit: :infinity, binaries: :as_binaries)
  end

  # The per-connection handler only holds session state once ThousandIsland has
  # run `handle_connection/2`, so wait for it rather than sampling a race.
  defp await_connection_state(supervisor, attempts \\ 100) do
    states = [:sys.get_state(supervisor) | child_states(supervisor)]

    cond do
      Enum.any?(states, &(inspect(&1, limit: :infinity) =~ "Derpex.Session")) -> states
      attempts == 0 -> flunk("no handler state observed for the accepted connection")
      true -> await_connection_state(supervisor, attempts - 1)
    end
  end

  defp child_states(supervisor) do
    supervisor
    |> Supervisor.which_children()
    |> Enum.flat_map(fn
      {_id, pid, :supervisor, _modules} when is_pid(pid) ->
        [process_state(pid) | child_states(pid)]

      {_id, pid, :worker, _modules} when is_pid(pid) ->
        [process_state(pid)]

      _restarting ->
        []
    end)
  end

  defp process_state(pid) do
    :sys.get_state(pid, 500)
  catch
    :exit, _reason -> nil
  end
end
