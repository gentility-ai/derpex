defmodule Derpex.Certificates.ACMEBootTest do
  @moduledoc """
  The whole certificate lifecycle through the real boot path.

  `Boot.children/1` starts what the application starts, `ListenerSupervisor`
  builds the listeners the way the application builds them, and a fake
  certificate authority validates the HTTP-01 challenge by fetching it back
  from the plaintext listener. What is asserted at the end is what a client
  sees: a TLS handshake with no SNI whose leaf was signed by the authority.
  """

  use ExUnit.Case, async: false

  alias Derpex.Certificates.Boot
  alias Derpex.Certificates.IPManager
  alias Derpex.Crypto
  alias Derpex.ListenerSupervisor
  alias Derpex.Operations
  alias Derpex.Secret
  alias Derpex.Test.FakeACME

  @moduletag timeout: 60_000

  setup do
    directory =
      Path.join(System.tmp_dir!(), "derpex-acme-boot-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)
    on_exit(fn -> :persistent_term.erase({IPManager, :bootstrap_subjects}) end)

    authority = start_supervised!(FakeACME)
    {:ok, directory: directory, authority: authority}
  end

  test "boots on a placeholder, orders, and then serves the issued leaf", context do
    {:ok, plan} =
      Boot.plan(
        mode: "letsencrypt",
        directory: context.directory,
        hostname: "127.0.0.1",
        ip_certificate_issuer: "acme",
        directory_url: FakeACME.directory_url(context.authority),
        challenge_listener: true
      )

    # The application starts these before any listener.
    for child <- Boot.children(plan) do
      start_supervised!(child)
    end

    {_public, private} = Crypto.generate_keypair()

    challenge = [
      port: 0,
      num_acceptors: 1,
      transport_options: [ip: {127, 0, 0, 1}],
      plaintext_challenge: true
    ]

    tls = [
      port: 0,
      num_acceptors: 1,
      transport_module: ThousandIsland.Transports.SSL,
      transport_options: [ip: {127, 0, 0, 1}, versions: [:"tlsv1.3"]]
    ]

    listeners = Enum.map([challenge, tls], &Boot.listener_options(plan, &1))

    # The challenge listener is first, so it is accepting before the TLS
    # listener starts the first order.
    assert {:ok, {_flags, [challenge_spec, tls_spec]}} =
             ListenerSupervisor.init({listeners, Secret.wrap(private)})

    challenge_server = start_supervised!(spec(challenge_spec, :challenge))
    assert {:ok, {_ip, challenge_port}} = ThousandIsland.listener_info(challenge_server)
    :ok = FakeACME.set_challenge_base(context.authority, "http://127.0.0.1:#{challenge_port}")

    # Binding the TLS listener must not have waited on the authority: the
    # relay is up, on a placeholder, and reports itself unready.
    assert IPManager.bootstrap_certificate_active?()
    assert Operations.health(:ready) == {:error, :not_ready}
    assert Operations.prometheus() =~ "derpex_tls_bootstrap_certificate_active 1"

    tls_server = start_supervised!(spec(tls_spec, :tls))
    assert {:ok, {_ip, tls_port}} = ThousandIsland.listener_info(tls_server)

    # Only now, with both listeners accepting, does the relay order — which is
    # what `Boot.post_listener_children/1` arranges in the running application.
    assert [bootstrap] = Boot.post_listener_children(plan)
    start_supervised!(bootstrap)

    root = FakeACME.root_certificate(context.authority)
    assert await_issued(context.authority) == 1

    # A client that sends no SNI now completes a handshake whose leaf the
    # authority signed, not the placeholder the socket was bound with.
    assert {:ok, socket} = await_issued_handshake(tls_port, root)
    on_exit(fn -> :ssl.close(socket) end)
    assert {:ok, peer} = :ssl.peercert(socket)
    assert issuer_common_name(peer) == "fake IP ACME root"

    refute IPManager.bootstrap_certificate_active?()
    assert Operations.prometheus() =~ "derpex_tls_bootstrap_certificate_active 0"
  end

  defp spec(child_spec, id), do: %{child_spec | id: id}

  defp await_issued(authority, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 30_000

    cond do
      FakeACME.orders(authority) > 0 ->
        FakeACME.orders(authority)

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("the relay never ordered a certificate")

      true ->
        Process.sleep(25)
        await_issued(authority, deadline)
    end
  end

  # The issued chain replaces the placeholder through the listener snapshot, so
  # the handshake is retried until the snapshot carries the real leaf.
  defp await_issued_handshake(port, root, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 30_000

    options = [
      verify: :verify_peer,
      cacerts: [root],
      server_name_indication: :disable,
      customize_hostname_check: [match_fun: fn _reference, _presented -> true end],
      active: false
    ]

    case :ssl.connect(~c"127.0.0.1", port, options, 5_000) do
      {:ok, socket} ->
        {:ok, socket}

      {:error, reason} ->
        if System.monotonic_time(:millisecond) >= deadline do
          flunk("no issued certificate was served: #{inspect(reason)}")
        else
          Process.sleep(50)
          await_issued_handshake(port, root, deadline)
        end
    end
  end

  defp issuer_common_name(certificate_der) do
    {:rdnSequence, [[{:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, name}}]]} =
      certificate_der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(4)

    IO.chardata_to_string(name)
  end
end
