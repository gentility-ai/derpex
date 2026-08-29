defmodule Derpex.Certificates.BootTest do
  use ExUnit.Case, async: true

  alias Derpex.ACME
  alias Derpex.Certificates.Boot
  alias Derpex.Certificates.IPManager

  @gcp_directory "https://dv.acme-v02.api.pki.goog/directory"
  @letsencrypt_directory "https://acme-v02.api.letsencrypt.org/directory"

  test "defaults to the manual mode a relay boots with today" do
    assert {:ok, plan} = Boot.plan([])
    assert plan.mode == :manual
    assert plan.ip_certificate_issuer == nil
    assert plan.acme == nil
    assert Boot.children(plan) == []
    assert Boot.challenge_options(plan) == []
    assert Boot.listener_options(plan, port: 443) == [port: 443]
  end

  test "keeps the upstream error for an unknown certificate mode" do
    assert Boot.plan(mode: "selfsigned", directory: "/var/lib/derpex") ==
             {:error, ~s(unsupport cert mode: "selfsigned")}
  end

  test "applies upstream manual-mode validation once a certificate directory is configured" do
    assert {:ok, plan} =
             Boot.plan(mode: "manual", directory: "/var/lib/derpex", hostname: "203.0.113.7")

    assert plan.directory == "/var/lib/derpex"
    assert plan.hostname == "203.0.113.7"
  end

  describe "ACME certificate modes" do
    test "letsencrypt orders for a DNS hostname through the certificate manager" do
      assert {:ok, plan} = acme_plan(mode: "letsencrypt", hostname: "derp.example.com")

      assert plan.mode == :acme
      assert plan.ip_certificate_issuer == :acme
      refute plan.ip_certificates
      assert plan.acme.directory_url == @letsencrypt_directory
      assert plan.acme.hostnames == ["derp.example.com"]
      assert plan.acme.external_account == nil

      assert [{ACME.Client, client}, {IPManager, manager}] = Boot.children(plan)
      assert Keyword.fetch!(client, :directory_url) == @letsencrypt_directory
      assert Keyword.fetch!(client, :challenge) == {IPManager, IPManager}
      assert Keyword.fetch!(manager, :hostnames) == ["derp.example.com"]
      assert is_function(Keyword.fetch!(manager, :issuer), 2)

      assert Boot.challenge_options(plan) == [acme_challenges: {IPManager, IPManager}]

      assert Boot.listener_options(plan, port: 443) ==
               [ip_certificate_manager: {IPManager, "derp.example.com"}, port: 443]

      # The plaintext listener answers challenges and binds no certificate.
      challenge_listener = Boot.listener_options(plan, port: 80, plaintext_challenge: true)
      refute Keyword.has_key?(challenge_listener, :ip_certificate_manager)
      refute Keyword.has_key?(challenge_listener, :plaintext_challenge)

      assert Keyword.fetch!(challenge_listener, :handler_options) ==
               [acme_challenges: {IPManager, IPManager}]
    end

    test "DERPEX_IP_CERT_ISSUER=acme orders for the address a connection arrives on" do
      assert {:ok, plan} =
               acme_plan(
                 mode: "letsencrypt",
                 hostname: "203.0.113.7",
                 ip_certificate_issuer: "acme"
               )

      assert plan.ip_certificate_issuer == :acme
      assert plan.ip_certificates
      assert plan.acme.hostnames == []
    end

    test "gcp requires an external account binding and uses its directory" do
      assert {:error, message} = acme_plan(mode: "gcp", hostname: "derp.example.com")
      assert message =~ "--acme-eab-kid"

      assert {:ok, plan} =
               acme_plan(
                 mode: "gcp",
                 hostname: "derp.example.com",
                 email: "security@example.com",
                 eab_kid: "kid-1",
                 eab_key: Base.url_encode64(:binary.copy(<<7>>, 32), padding: false)
               )

      assert plan.acme.directory_url == @gcp_directory
      assert plan.acme.email == "security@example.com"
      assert plan.acme.external_account.kid == "kid-1"
      assert plan.acme.external_account.key == :binary.copy(<<7>>, 32)
    end

    test "refuses an ACME mode with nowhere to answer an HTTP-01 challenge" do
      assert {:error, message} =
               Boot.plan(
                 mode: "letsencrypt",
                 directory: "/var/lib/derpex",
                 hostname: "derp.example.com"
               )

      assert message =~ "HTTP-01"
      assert message =~ "DERPEX_HTTP_PORT"
    end

    test "refuses an ACME mode alongside operator certificates" do
      assert {:error, message} =
               acme_plan(
                 mode: "letsencrypt",
                 hostname: "derp.example.com",
                 certfile: "/run/secrets/derpex.crt",
                 keyfile: "/run/secrets/derpex.key"
               )

      assert message =~ "ACME certificate mode"
      assert message =~ "DERPEX_TLS_CERTFILE"
    end

    test "keeps upstream's refusal of an IP hostname without IP certificates" do
      assert {:error, message} = acme_plan(mode: "letsencrypt", hostname: "203.0.113.7")
      assert message =~ "--acme-ip-certs"
    end
  end

  describe "the self-signed IP issuer" do
    test "wires the certificate manager without an ACME client" do
      assert {:ok, plan} =
               Boot.plan(
                 ip_certificate_issuer: "self",
                 directory: "/var/lib/derpex",
                 hostname: "203.0.113.7"
               )

      assert plan.mode == :manual
      assert plan.acme == nil
      assert [{IPManager, options}] = Boot.children(plan)
      assert Keyword.fetch!(options, :name) == IPManager
      assert Keyword.fetch!(options, :directory) == "/var/lib/derpex"
      assert is_function(Keyword.fetch!(options, :issuer), 2)
      assert Boot.challenge_options(plan) == []

      assert Boot.listener_options(plan, port: 443) ==
               [ip_certificate_manager: {IPManager, "203.0.113.7"}, port: 443]
    end

    test "requires a certificate directory and an IP hostname" do
      assert {:error, directory_message} =
               Boot.plan(ip_certificate_issuer: "self", hostname: "203.0.113.7")

      assert directory_message =~ "DERPEX_CERT_DIR"

      assert {:error, hostname_message} =
               Boot.plan(
                 ip_certificate_issuer: "self",
                 directory: "/var/lib/derpex",
                 hostname: "derp.example.com"
               )

      assert hostname_message =~ "DERPEX_CERT_HOSTNAME"
    end

    test "cannot be combined with operator certificates" do
      assert {:error, message} =
               Boot.plan(
                 ip_certificate_issuer: "self",
                 directory: "/var/lib/derpex",
                 hostname: "203.0.113.7",
                 certfile: "/run/secrets/derpex.crt"
               )

      assert message =~ "DERPEX_IP_CERT_ISSUER=self"
      assert message =~ "DERPEX_TLS_CERTFILE"
    end
  end

  test "refuses an IP certificate issuer that is neither self nor acme" do
    assert {:error, message} = Boot.plan(ip_certificate_issuer: "letsencrypt")
    assert message =~ "DERPEX_IP_CERT_ISSUER"
    assert message =~ "\"self\""
  end

  test "refuses the ACME IP issuer without an ACME certificate mode" do
    assert {:error, message} =
             Boot.plan(
               mode: "manual",
               directory: "/var/lib/derpex",
               hostname: "203.0.113.7",
               ip_certificate_issuer: "acme"
             )

    assert message =~ "DERPEX_CERT_MODE=letsencrypt"
  end

  test "leaves operator certificates alone without an issuer" do
    assert {:ok, plan} =
             Boot.plan(certfile: "/run/secrets/derpex.crt", keyfile: "/run/secrets/derpex.key")

    assert plan.ip_certificate_issuer == nil
    assert Boot.children(plan) == []
  end

  test "raises the same message it reports when a plan is demanded" do
    assert_raise ArgumentError, ~r/DERPEX_HTTP_PORT/, fn ->
      Boot.plan!(
        mode: "letsencrypt",
        directory: "/var/lib/derpex",
        hostname: "derp.example.com"
      )
    end
  end

  defp acme_plan(options) do
    options
    |> Keyword.put_new(:directory, "/var/lib/derpex")
    |> Keyword.put(:challenge_listener, true)
    |> Boot.plan()
  end
end
