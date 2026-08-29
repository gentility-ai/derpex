defmodule Derpex.Certificates.ReloaderTest do
  use ExUnit.Case, async: false

  alias Derpex.Certificates.Manual
  alias Derpex.Certificates.Reloader
  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor

  test "atomically retains the last good certificate snapshot" do
    {active, replacement} = certificate_pair_directories()
    original_key_pem = File.read!(active.key_path)
    snapshot_key = {__MODULE__, make_ref()}
    server_public_key = :crypto.strong_rand_bytes(32)

    {:ok, reloader} =
      Reloader.start_link(
        snapshot_key: snapshot_key,
        certificate_path: active.certificate_path,
        key_path: active.key_path,
        server_public_key: server_public_key,
        interval_ms: 60_000
      )

    on_exit(fn -> if Process.alive?(reloader), do: GenServer.stop(reloader) end)

    assert current_leaf(snapshot_key) == active.certificate_der
    rotate_files(active, replacement)
    assert Reloader.reload(reloader) == {:ok, :changed}
    assert current_leaf(snapshot_key) == replacement.certificate_der

    File.write!(active.key_path, original_key_pem)

    assert {:error, "TLS private key does not match leaf certificate"} =
             Reloader.reload(reloader)

    assert current_leaf(snapshot_key) == replacement.certificate_der
    assert %{reloads: 2, failures: 1, last_error: last_error} = Reloader.stats(reloader)
    refute is_nil(last_error)

    GenServer.stop(reloader)
    assert Reloader.current_options(snapshot_key) == :undefined
  end

  test "new SNI handshakes use a rotated certificate without restarting the listener" do
    {active, replacement} = certificate_pair_directories()
    {_server_public, server_private} = Crypto.generate_keypair()

    supervisor = start_supervised!({ListenerSupervisor, {[listener(active)], server_private}})
    children = Supervisor.which_children(supervisor)
    listener_pid = child_pid(children, ThousandIsland)
    reloader_pid = child_pid(children, Reloader)

    assert peer_certificate(listener_pid, "reload.test") == active.certificate_der
    rotate_files(active, replacement)
    assert Reloader.reload(reloader_pid) == {:ok, :changed}
    assert peer_certificate(listener_pid, "reload.test") == replacement.certificate_der
    assert Process.alive?(listener_pid)
  end

  test "new no-SNI handshakes use a rotated certificate and keep live connections" do
    {active, replacement} = certificate_pair_directories()
    {_server_public, server_private} = Crypto.generate_keypair()

    supervisor = start_supervised!({ListenerSupervisor, {[listener(active)], server_private}})
    children = Supervisor.which_children(supervisor)
    listener_pid = child_pid(children, ThousandIsland)
    reloader_pid = child_pid(children, Reloader)

    {:ok, listener_info} = ThousandIsland.listener_info(listener_pid)
    assert peer_certificate(listener_pid, nil) == active.certificate_der

    established = open_idle_connection(listener_pid)
    rotate_files(active, replacement)
    assert Reloader.reload(reloader_pid) == {:ok, :changed}

    assert peer_certificate(listener_pid, nil) == replacement.certificate_der
    assert peer_certificate(listener_pid, "reload.test") == replacement.certificate_der

    assert Process.alive?(listener_pid)
    assert Process.alive?(established)
    assert ThousandIsland.listener_info(listener_pid) == {:ok, listener_info}
  end

  defp open_idle_connection(listener) do
    {:ok, {_ip, port}} = ThousandIsland.listener_info(listener)
    openssl = System.find_executable("openssl") || flunk("openssl is required for this test")
    {:ok, existing} = ThousandIsland.connection_pids(listener)

    command =
      Port.open(
        {:spawn_executable, openssl},
        [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          args: ["s_client", "-connect", "127.0.0.1:#{port}", "-noservername", "-quiet"]
        ]
      )

    on_exit(fn -> if Port.info(command), do: Port.close(command) end)
    await_connection(listener, MapSet.new(existing), 400)
  end

  defp await_connection(listener, existing, attempts) do
    {:ok, pids} = ThousandIsland.connection_pids(listener)

    case Enum.find(pids, &(not MapSet.member?(existing, &1))) do
      pid when is_pid(pid) ->
        pid

      nil when attempts > 0 ->
        Process.sleep(5)
        await_connection(listener, existing, attempts - 1)

      nil ->
        flunk("no connection was accepted by the TLS listener")
    end
  end

  defp listener(active) do
    [
      port: 0,
      transport_module: ThousandIsland.Transports.SSL,
      certificate_reload_interval_ms: 60_000,
      num_acceptors: 1,
      transport_options: [
        certfile: active.certificate_path,
        keyfile: active.key_path,
        ip: {127, 0, 0, 1},
        versions: [:"tlsv1.3"],
        alpn_preferred_protocols: ["http/1.1"]
      ]
    ]
  end

  defp certificate_pair_directories do
    root = Path.join(System.tmp_dir!(), "derpex-reloader-#{System.unique_integer([:positive])}")
    active_directory = Path.join(root, "active")
    replacement_directory = Path.join(root, "replacement")
    on_exit(fn -> File.rm_rf!(root) end)

    {:ok, active} = Manual.load_or_create(active_directory, "127.0.0.1")
    {:ok, replacement} = Manual.load_or_create(replacement_directory, "127.0.0.1")
    {active, replacement}
  end

  defp rotate_files(active, replacement) do
    File.cp!(replacement.certificate_path, active.certificate_path)
    File.cp!(replacement.key_path, active.key_path)
  end

  defp current_leaf(snapshot_key) do
    [certs_keys: [%{cert: [leaf, _meta_certificate], key: _private_key}]] =
      Reloader.current_options(snapshot_key)

    leaf
  end

  defp child_pid(children, module) do
    children
    |> Enum.find_value(fn
      {{^module, _index}, pid, _type, _modules} -> pid
      _other -> nil
    end)
    |> tap(&assert(is_pid(&1)))
  end

  defp peer_certificate(listener, server_name) do
    {:ok, {_ip, port}} = ThousandIsland.listener_info(listener)
    openssl = System.find_executable("openssl") || flunk("openssl is required for this test")

    server_name_arguments =
      if server_name, do: ["-servername", server_name], else: ["-noservername"]

    command =
      Port.open(
        {:spawn_executable, openssl},
        [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          args:
            ["s_client", "-connect", "127.0.0.1:#{port}", "-showcerts"] ++
              server_name_arguments
        ]
      )

    {output, 0} = collect_openssl(command, "", false)

    [{:Certificate, certificate, :not_encrypted} | _rest] = :public_key.pem_decode(output)
    certificate
  end

  defp collect_openssl(command, output, quit_sent?) do
    receive do
      {^command, {:data, data}} ->
        output = output <> data

        quit_sent? =
          if quit_sent? or :binary.match(output, "-----END CERTIFICATE-----") == :nomatch do
            quit_sent?
          else
            true = Port.command(command, "Q\n")
            true
          end

        collect_openssl(command, output, quit_sent?)

      {^command, {:exit_status, status}} ->
        {output, status}
    after
      2_000 ->
        Port.close(command)
        flunk("openssl certificate handshake timed out")
    end
  end
end
