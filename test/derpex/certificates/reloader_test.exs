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

    listener = [
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

    supervisor = start_supervised!({ListenerSupervisor, {[listener], server_private}})
    children = Supervisor.which_children(supervisor)
    listener_pid = child_pid(children, ThousandIsland)
    reloader_pid = child_pid(children, Reloader)

    assert peer_certificate(listener_pid) == active.certificate_der
    rotate_files(active, replacement)
    assert Reloader.reload(reloader_pid) == {:ok, :changed}
    assert peer_certificate(listener_pid) == replacement.certificate_der
    assert Process.alive?(listener_pid)
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

  defp peer_certificate(listener) do
    {:ok, {_ip, port}} = ThousandIsland.listener_info(listener)
    openssl = System.find_executable("openssl") || flunk("openssl is required for this test")

    command =
      Port.open(
        {:spawn_executable, openssl},
        [
          :binary,
          :exit_status,
          :stderr_to_stdout,
          args: [
            "s_client",
            "-connect",
            "127.0.0.1:#{port}",
            "-servername",
            "reload.test",
            "-showcerts"
          ]
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
