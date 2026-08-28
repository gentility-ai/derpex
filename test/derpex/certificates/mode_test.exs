defmodule Derpex.Certificates.ModeTest do
  use ExUnit.Case, async: true

  alias Derpex.Certificates.Mode

  test "matches production autocert hostname policy" do
    allowed = [
      "derp.tailscale.com",
      "derp.tailscale.com.",
      "derp1.tailscale.com",
      "derp1b.tailscale.com",
      "derp2.tailscale.com",
      "derp02.tailscale.com",
      "derp-nyc.tailscale.com",
      "derpfoo.tailscale.com"
    ]

    rejected = ["derp02.bar.tailscale.com", "example.net"]
    assert Enum.all?(allowed, &Mode.production_hostname_allowed?/1)
    refute Enum.any?(rejected, &Mode.production_hostname_allowed?/1)
  end

  test "validates GCP external account binding inputs and both base64 forms" do
    base = [directory: "/tmp/certs", hostname: "test.example.com"]

    assert {:error, error} = Mode.provider("gcp", base ++ [email: "test@example.com"])
    assert error =~ "requires --acme-eab-kid and --acme-eab-key"

    assert {:error, error} =
             Mode.provider("gcp", base ++ [eab_kid: "kid", eab_key: "dGVzdC1rZXk"])

    assert error =~ "requires --acme-email"

    assert {:error, error} =
             Mode.provider(
               "gcp",
               base ++ [eab_kid: "kid", eab_key: "not-valid!", email: "test@example.com"]
             )

    assert error =~ "invalid --acme-eab-key"

    for key <- ["dGVzdC1rZXk", "dGVzdC1rZXk="] do
      assert {:ok, %{type: :acme, eab: %{kid: "kid", key: "test-key"}}} =
               Mode.provider(
                 "gcp",
                 base ++ [eab_kid: "kid", eab_key: key, email: "test@example.com"]
               )
    end
  end

  test "gates IP certificate modes and composes the hostname provider" do
    directory = "/tmp/certs"

    cases = [
      {"letsencrypt", "1.2.3.4", false, "--acme-ip-certs"},
      {"gcp", "1.2.3.4", false, "--certmode=gcp requires --hostname to be a DNS name"},
      {"gcp", "1.2.3.4", true, "--acme-ip-certs requires --certmode=letsencrypt"},
      {"manual", "1.2.3.4", true, "--acme-ip-certs requires --certmode=letsencrypt"}
    ]

    Enum.each(cases, fn {mode, hostname, ip_certificates?, expected_error} ->
      assert {:error, error} =
               Mode.provider(mode,
                 directory: directory,
                 hostname: hostname,
                 ip_certificates: ip_certificates?
               )

      assert error =~ expected_error
    end)

    assert {:ok, %{type: :ip_acme, next: nil}} =
             Mode.provider("letsencrypt",
               directory: directory,
               hostname: "1.2.3.4",
               ip_certificates: true
             )

    assert {:ok, %{type: :ip_acme, next: %{type: :acme}}} =
             Mode.provider("letsencrypt",
               directory: directory,
               hostname: "derp.example.com",
               ip_certificates: true
             )
  end
end
