defmodule Derpex.Certificates.BootTest do
  use ExUnit.Case, async: true

  alias Derpex.Certificates.Boot
  alias Derpex.Certificates.IPManager

  test "defaults to the manual mode a relay boots with today" do
    assert Boot.plan([]) ==
             {:ok,
              %{
                mode: :manual,
                directory: "",
                hostname: "",
                ip_certificate_issuer: nil
              }}

    assert Boot.plan(mode: "manual") ==
             {:ok, %{mode: :manual, directory: "", hostname: "", ip_certificate_issuer: nil}}
  end

  test "rejects the ACME certificate modes at boot with a clear error" do
    for mode <- ["letsencrypt", "gcp"] do
      assert {:error, message} =
               Boot.plan(mode: mode, directory: "/var/lib/derpex", hostname: "derp.example.com")

      assert message =~ "DERPEX_CERT_MODE=#{mode}"
      assert message =~ "ACME"
      assert message =~ "PLAN.md section 2.3"
      assert message =~ "DERPEX_CERT_MODE=manual"
    end
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

  test "rejects an IP certificate issuer other than the self-signed one" do
    assert {:error, message} = Boot.plan(ip_certificate_issuer: "letsencrypt")
    assert message =~ "DERPEX_IP_CERT_ISSUER"
    assert message =~ "ACME"
    assert message =~ "PLAN.md section 2.3"
  end

  test "requires a certificate directory and an IP hostname for the self-signed issuer" do
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

  test "starts no certificate manager unless the self-signed IP issuer is selected" do
    assert {:ok, plan} = Boot.plan(mode: "manual", directory: "/var/lib/derpex")
    assert Boot.children(plan) == []
    assert Boot.listener_options(plan, port: 443) == [port: 443]
  end

  test "wires the IP certificate manager behind the self-signed issuer" do
    assert {:ok, plan} =
             Boot.plan(
               ip_certificate_issuer: "self",
               directory: "/var/lib/derpex",
               hostname: "203.0.113.7"
             )

    assert [{IPManager, options}] = Boot.children(plan)
    assert Keyword.fetch!(options, :name) == IPManager
    assert Keyword.fetch!(options, :directory) == "/var/lib/derpex"
    assert is_function(Keyword.fetch!(options, :issuer), 2)

    assert Boot.listener_options(plan, port: 443) ==
             [ip_certificate_manager: {IPManager, "203.0.113.7"}, port: 443]
  end

  test "refuses the self-signed IP issuer alongside operator certificates" do
    assert {:error, message} =
             Boot.plan(
               ip_certificate_issuer: "self",
               directory: "/var/lib/derpex",
               hostname: "203.0.113.7",
               certfile: "/run/secrets/derpex.crt",
               keyfile: "/run/secrets/derpex.key"
             )

    assert message =~ "DERPEX_IP_CERT_ISSUER=self"
    assert message =~ "DERPEX_TLS_CERTFILE"
    assert message =~ "DERPEX_TLS_KEYFILE"

    assert {:error, ^message} =
             Boot.plan(
               ip_certificate_issuer: "self",
               directory: "/var/lib/derpex",
               hostname: "203.0.113.7",
               certfile: "/run/secrets/derpex.crt"
             )
  end

  test "leaves operator certificates alone without the self-signed issuer" do
    assert {:ok, plan} =
             Boot.plan(certfile: "/run/secrets/derpex.crt", keyfile: "/run/secrets/derpex.key")

    assert plan.ip_certificate_issuer == nil
    assert Boot.children(plan) == []
  end

  test "raises the same message it reports when a plan is demanded" do
    assert_raise ArgumentError, ~r/PLAN.md section 2.3/, fn ->
      Boot.plan!(mode: "letsencrypt", directory: "/var/lib/derpex", hostname: "derp.example.com")
    end
  end
end
