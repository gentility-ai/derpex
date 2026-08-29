defmodule Derpex.Interop.RustClientTest do
  use ExUnit.Case, async: false

  @moduletag :rust_interop

  alias Derpex.Certificates
  alias Derpex.Certificates.Manual
  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Secret

  setup_all do
    upstream =
      System.get_env("DERPEX_TAILSCALE_RS_DIR") ||
        raise "DERPEX_TAILSCALE_RS_DIR must name the pinned tailscale-rs checkout"

    expected_commit =
      Path.expand("../../interop/upstream.lock", __DIR__)
      |> File.read!()
      |> then(&Regex.run(~r/\[rust\].*?commit = "([0-9a-f]+)"/s, &1, capture: :all_but_first))
      |> List.first()

    {actual_commit, 0} = System.cmd("git", ["rev-parse", "HEAD"], cd: upstream)
    assert String.trim(actual_commit) == expected_commit

    {:ok, upstream: upstream}
  end

  test "official Rust clients authenticate and relay packets", %{upstream: upstream} do
    {server_public, server_private} = Crypto.generate_keypair()

    directory =
      Path.join(System.tmp_dir!(), "derpex-rust-tls-#{System.unique_integer([:positive])}")

    {:ok, manual} = Manual.load_or_create(directory, "127.0.0.1")
    on_exit(fn -> File.rm_rf!(directory) end)

    transport_options =
      Certificates.transport_options(
        manual.certificate_path,
        manual.key_path,
        server_public
      ) ++
        [
          ip: {127, 0, 0, 1},
          versions: [:"tlsv1.3"],
          alpn_preferred_protocols: ["http/1.1"]
        ]

    {:ok, server} =
      ThousandIsland.start_link(
        port: 0,
        transport_module: ThousandIsland.Transports.SSL,
        transport_options: transport_options,
        handler_module: Handler,
        handler_options: [
          server_private_key: Secret.wrap(server_private),
          server_public_key: server_public
        ]
      )

    on_exit(fn -> if Process.alive?(server), do: Process.exit(server, :shutdown) end)
    {:ok, {_ip, port}} = ThousandIsland.listener_info(server)
    crate = rust_smoke_crate(upstream)

    {output, status} =
      System.cmd(
        "cargo",
        ["run", "--quiet", "--manifest-path", crate.manifest, "--", to_string(port)],
        stderr_to_stdout: true,
        env: [{"CARGO_TARGET_DIR", crate.target}]
      )

    assert status == 0, output
    assert output =~ "official Rust clients authenticated and relayed both directions"
  end

  defp rust_smoke_crate(upstream) do
    root = Path.join(System.tmp_dir!(), "derpex-rust-smoke-#{System.unique_integer([:positive])}")
    source_directory = Path.join(root, "src")
    File.mkdir_p!(source_directory)
    on_exit(fn -> File.rm_rf!(root) end)

    source = Path.expand("../../interop/rust/client_smoke.rs", __DIR__)
    File.cp!(source, Path.join(source_directory, "main.rs"))
    File.cp!(Path.join(upstream, "Cargo.lock"), Path.join(root, "Cargo.lock"))

    manifest = """
    [package]
    name = "derpex-rust-smoke"
    version = "0.0.0"
    edition = "2024"

    [dependencies]
    tokio = { version = "1", features = ["full"] }
    ts_derp = { path = "#{toml_path(Path.join(upstream, "ts_derp"))}", features = ["insecure-for-tests"] }
    ts_keys = { path = "#{toml_path(Path.join(upstream, "ts_keys"))}" }
    """

    manifest_path = Path.join(root, "Cargo.toml")
    File.write!(manifest_path, manifest)

    %{
      manifest: manifest_path,
      target: Path.expand("../../_build/rust_interop", __DIR__)
    }
  end

  defp toml_path(path) do
    path
    |> String.replace("\\", "\\\\")
    |> String.replace("\"", "\\\"")
  end
end
