defmodule Derpex.Certificates.ReloaderTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Derpex.Certificates.Manual
  alias Derpex.Certificates.Reloader
  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor
  alias Derpex.Secret

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

    on_exit(fn -> stop_reloader(reloader) end)

    assert current_leaf(snapshot_key) == active.certificate_der
    rotate_files(active, replacement)
    assert Reloader.reload(reloader) == {:ok, :changed}
    assert current_leaf(snapshot_key) == replacement.certificate_der

    File.write!(active.key_path, original_key_pem)

    assert Reloader.reload(reloader) == {:error, :private_key_mismatch}

    assert current_leaf(snapshot_key) == replacement.certificate_der
    assert %{reloads: 2, failures: 1, last_error: last_error} = Reloader.stats(reloader)
    refute is_nil(last_error)

    GenServer.stop(reloader)
    assert Reloader.current_options(snapshot_key) == :undefined
  end

  test "logs a fixed reason atom and never certificate or key bytes" do
    {active, replacement} = certificate_pair_directories()
    snapshot_key = {__MODULE__, make_ref()}

    {:ok, reloader} =
      Reloader.start_link(
        snapshot_key: snapshot_key,
        certificate_path: active.certificate_path,
        key_path: active.key_path,
        server_public_key: :crypto.strong_rand_bytes(32),
        interval_ms: 60_000
      )

    on_exit(fn -> stop_reloader(reloader) end)

    File.cp!(replacement.key_path, active.key_path)
    assert Reloader.reload(reloader) == {:error, :private_key_mismatch}

    File.write!(active.key_path, <<0, 1, 2, 3, 0xFF>>)

    log =
      capture_log(fn ->
        send(reloader, :derpex_reload_certificate)
        assert Reloader.reload(reloader) == {:error, :invalid_private_key}
      end)

    assert log =~ "DERP TLS certificate reload failed: invalid_private_key"
    refute log =~ "<<"
    assert %{last_error: :invalid_private_key} = Reloader.stats(reloader)

    File.write!(active.certificate_path, "-----BEGIN NOTHING-----\n")
    assert Reloader.reload(reloader) == {:error, :invalid_certificate}

    File.cp!(replacement.certificate_path, active.certificate_path)
    File.rm!(active.key_path)
    assert Reloader.reload(reloader) == {:error, :missing_key_file}

    File.rm!(active.certificate_path)
    assert Reloader.reload(reloader) == {:error, :missing_certificate_file}
  end

  test "new SNI handshakes use a rotated certificate without restarting the listener" do
    {active, replacement} = certificate_pair_directories()
    {_server_public, server_private} = Crypto.generate_keypair()

    supervisor =
      start_supervised!({ListenerSupervisor, {[listener(active)], Secret.wrap(server_private)}})

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

    supervisor =
      start_supervised!({ListenerSupervisor, {[listener(active)], Secret.wrap(server_private)}})

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

  test "listeners sharing a port but not an address keep their own certificate" do
    {first, second} = certificate_pair_directories()
    {_server_public, server_private} = Crypto.generate_keypair()
    port = free_loopback_port()

    listeners = [
      listener(first, port: port),
      listener(second, port: port, ip: {0, 0, 0, 0, 0, 0, 0, 1}, family: :inet6)
    ]

    supervisor = start_supervised!({ListenerSupervisor, {listeners, Secret.wrap(server_private)}})
    [first_listener, second_listener] = listener_pids(supervisor)

    assert peer_certificate(first_listener, nil) == first.certificate_der
    assert peer_certificate(second_listener, nil) == second.certificate_der
  end

  # The reloader traps exits, so it shuts down with the linking test process
  # rather than outliving it; the on_exit stop is best effort.
  defp stop_reloader(reloader) do
    if Process.alive?(reloader), do: GenServer.stop(reloader)
    :ok
  catch
    :exit, _already_stopping -> :ok
  end

  defp free_loopback_port do
    {:ok, socket} = :gen_tcp.listen(0, ip: {127, 0, 0, 1}, reuseaddr: true)
    {:ok, {_ip, port}} = :inet.sockname(socket)
    :ok = :gen_tcp.close(socket)
    port
  end

  defp listener_pids(supervisor) do
    supervisor
    |> Supervisor.which_children()
    |> Enum.flat_map(fn
      {{ThousandIsland, index}, pid, _type, _modules} -> [{index, pid}]
      _other -> []
    end)
    |> Enum.sort()
    |> Enum.map(&elem(&1, 1))
  end

  defp open_idle_connection(listener) do
    openssl = System.find_executable("openssl") || flunk("openssl is required for this test")
    {:ok, existing} = ThousandIsland.connection_pids(listener)

    command =
      Port.open(
        {:spawn_executable, openssl},
        [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          args: ["s_client", "-connect", connect_target(listener), "-noservername", "-quiet"]
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

  defp listener(active, overrides \\ []) do
    {family, overrides} = Keyword.pop(overrides, :family)
    {ip, overrides} = Keyword.pop(overrides, :ip, {127, 0, 0, 1})

    transport_options =
      [
        certfile: active.certificate_path,
        keyfile: active.key_path,
        ip: ip,
        versions: [:"tlsv1.3"],
        alpn_preferred_protocols: ["http/1.1"]
      ] ++ List.wrap(family)

    [
      port: 0,
      transport_module: ThousandIsland.Transports.SSL,
      certificate_reload_interval_ms: 60_000,
      num_acceptors: 1,
      transport_options: transport_options
    ]
    |> Keyword.merge(overrides)
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

  defp connect_target(listener) do
    {:ok, {ip, port}} = ThousandIsland.listener_info(listener)
    host = ip |> :inet.ntoa() |> List.to_string()
    host = if tuple_size(ip) == 8, do: "[" <> host <> "]", else: host
    host <> ":" <> Integer.to_string(port)
  end

  defp peer_certificate(listener, server_name) do
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
            ["s_client", "-connect", connect_target(listener), "-showcerts"] ++
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
