defmodule Derpex.ACME.SecurityTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureLog

  alias Derpex.ACME.Client
  alias Derpex.ACME.HTTP
  alias Derpex.ACME.JWS
  alias Derpex.Certificates.Boot
  alias Derpex.Certificates.IPManager
  alias Derpex.HTTPClient

  describe "URLs a certificate authority supplies" do
    test "must be HTTPS unless the authority is on loopback" do
      assert {:error, {:acme_insecure_url, _url}} =
               HTTP.get("http://acme.example.com/directory")

      assert {:error, {:acme_insecure_url, _url}} =
               HTTP.post("http://198.51.100.7/new-order", "{}")

      # Loopback is the documented exception: it is how the fake authority in
      # this suite is reached and is not reachable off the host.
      for host <- ["127.0.0.1", "127.9.9.9", "localhost", "[::1]"] do
        assert {:error, {:acme_transport, _reason}} =
                 HTTP.get("http://#{host}:1/directory", timeout_ms: 50)
      end
    end

    test "must stay on the origin the operator pinned" do
      {:ok, origin} = HTTP.origin("https://acme.example.com/directory")

      for url <- [
            "https://evil.example.com/new-order",
            "https://acme.example.com:8443/new-order",
            "http://acme.example.com/new-order"
          ] do
        assert {:error, reason} = HTTP.post(url, "{}", origin: origin)
        assert elem(reason, 0) in [:acme_cross_origin_url, :acme_insecure_url]
      end
    end

    test "an origin is the scheme, host, and effective port" do
      assert HTTP.origin("https://acme.example.com/directory") ==
               {:ok, {"https", "acme.example.com", 443}}

      assert HTTP.origin("http://127.0.0.1:8080/directory") ==
               {:ok, {"http", "127.0.0.1", 8080}}

      assert {:error, {:acme_url, _}} = HTTP.origin("not-a-url")
    end
  end

  describe "the configured directory URL" do
    test "is refused at boot unless it is HTTPS or loopback" do
      assert {:error, message} = plan("http://acme.example.com/directory")
      assert message =~ "DERPEX_ACME_DIRECTORY_URL must be https"

      assert {:error, message} = plan("acme.example.com/directory")
      assert message =~ "absolute HTTPS URL"

      assert {:ok, _plan} = plan("https://acme.example.com/directory")
      assert {:ok, _plan} = plan("http://127.0.0.1:4000/directory")
    end

    defp plan(directory_url) do
      Boot.plan(
        mode: "letsencrypt",
        directory: "/var/lib/derpex",
        hostname: "derp.example.com",
        directory_url: directory_url,
        challenge_listener: true
      )
    end
  end

  describe "transport security" do
    test "a caller cannot turn peer verification off" do
      {:ok, listener} = :gen_tcp.listen(0, [:binary, ip: {127, 0, 0, 1}, active: false])
      {:ok, {_ip, port}} = :inet.sockname(listener)
      on_exit(fn -> :gen_tcp.close(listener) end)

      uri = URI.parse("https://127.0.0.1:#{port}/")
      request = ["GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"]

      # The handshake has to fail on trust, never succeed because the caller
      # asked for it not to be checked.
      assert {:error, {:connect, reason}} =
               HTTPClient.request(uri, request,
                 timeout_ms: 500,
                 tls_options: [verify: :verify_none, cacerts: []]
               )

      refute match?({:tls_alert, {:handshake_failure, _}}, reason) and false
      assert reason != :ok
    end
  end

  describe "process state holding key material" do
    test "the certificate manager redacts its keys from sys and crash reports" do
      directory =
        Path.join(System.tmp_dir!(), "derpex-redact-#{System.unique_integer([:positive])}")

      on_exit(fn -> File.rm_rf!(directory) end)

      manager =
        start_supervised!(
          {IPManager, directory: directory, issuer: &IPManager.self_signed_issuer/2}
        )

      assert {:ok, certificate} = IPManager.certificate(manager, "203.0.113.7")

      # The key never leaves the manager in the first place.
      refute Map.has_key?(certificate, :private_key)
      :ok = IPManager.put_challenge(manager, "/.well-known/acme-challenge/tok", "answer")

      # What `:ssl` is handed does carry the key, and that is the copy the
      # process state must not render.
      assert {:ok, %{key: {_type, key_der}}} =
               IPManager.certs_keys(manager, "203.0.113.7", "", "meta")

      rendered = inspect(:sys.get_status(manager), limit: :infinity, printable_limit: :infinity)

      refute rendered =~ Base.encode16(key_der)
      refute rendered =~ inspect(key_der, limit: :infinity, binaries: :as_binaries)
      refute rendered =~ "answer"
      assert rendered =~ ":redacted"
    end

    test "the ACME client redacts its account and external account keys" do
      account_key = JWS.generate_account_key()
      mac_key = :crypto.strong_rand_bytes(32)

      directory =
        Path.join(System.tmp_dir!(), "derpex-redact-acme-#{System.unique_integer([:positive])}")

      File.mkdir_p!(directory)
      on_exit(fn -> File.rm_rf!(directory) end)
      write_account_key(directory, account_key)

      client =
        start_supervised!(
          {Client,
           directory_url: "https://127.0.0.1:1/directory",
           directory: directory,
           external_account: %{kid: "eab", key: mac_key},
           challenge: {IPManager, IPManager}}
        )

      rendered = inspect(:sys.get_status(client), limit: :infinity, printable_limit: :infinity)
      refute rendered =~ Base.encode16(mac_key)
      refute rendered =~ inspect(mac_key, limit: :infinity, binaries: :as_binaries)
      assert rendered =~ ":redacted"
    end

    test "a crash report carries no key material" do
      directory =
        Path.join(System.tmp_dir!(), "derpex-crash-#{System.unique_integer([:positive])}")

      on_exit(fn -> File.rm_rf!(directory) end)

      {:ok, manager} =
        IPManager.start_link(directory: directory, issuer: &IPManager.self_signed_issuer/2)

      Process.unlink(manager)

      assert {:ok, %{key: {_type, key_der}}} =
               IPManager.certs_keys(manager, "203.0.113.7", "", "meta")

      marker = key_der |> Base.encode16() |> binary_part(0, 32)

      log =
        capture_log(fn ->
          reference = Process.monitor(manager)
          send(manager, {:"$gen_call", {self(), make_ref()}, :deliberately_unhandled})
          assert_receive {:DOWN, ^reference, :process, ^manager, _reason}, 2_000
        end)

      # The report is there, and the key the state holds is not, in either the
      # state itself or the arguments the exception renders.
      assert log =~ "FunctionClauseError"
      refute log =~ marker
      refute log =~ inspect(key_der, limit: :infinity, binaries: :as_binaries)
    end

    defp write_account_key(directory, key) do
      pem =
        :ECPrivateKey
        |> :public_key.pem_entry_encode(key)
        |> List.wrap()
        |> :public_key.pem_encode()

      File.write!(Path.join(directory, "acme-account.key"), pem)
    end
  end

  describe "problem documents" do
    test "are bounded before they reach a log line" do
      long = String.duplicate("z", 4_000)

      response = %{
        status: 400,
        headers: [{"content-type", "application/problem+json"}],
        body: ~s({"type":"urn:#{long}","detail":"#{long}"})
      }

      assert %{type: type, detail: detail} = HTTP.problem(response)
      assert byte_size(type) == 256
      assert byte_size(detail) == 256
    end
  end
end
