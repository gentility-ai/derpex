defmodule Derpex.Certificates.IPManagerTest do
  use ExUnit.Case, async: true

  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Manual

  test "issues IPv4 and IPv6 short-lived certificates, validates SNI, and reuses disk cache" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    calls = start_supervised!({Agent, fn -> [] end})

    issuer = fn ip, profile ->
      Agent.update(calls, &[{ip, profile} | &1])

      with {:ok, {certificate_der, private_key}} <- Manual.generate_ip(ip) do
        {:ok, %{certificate_der: certificate_der, private_key: private_key}}
      end
    end

    manager = start_supervised!({IPManager, directory: directory, issuer: issuer})

    assert {:ok, ipv4_certificate} = IPManager.certificate(manager, "203.0.113.7")
    assert :ok = Manual.verify_certificate(ipv4_certificate.certificate_der, "203.0.113.7")

    assert {:ok, ipv6_certificate} = IPManager.certificate(manager, "2001:db8::7")
    assert :ok = Manual.verify_certificate(ipv6_certificate.certificate_der, "2001:db8::7")

    assert Agent.get(calls, &Enum.reverse/1) == [
             {"203.0.113.7", "shortlived"},
             {"2001:db8::7", "shortlived"}
           ]

    assert {:ok, ^ipv4_certificate} =
             IPManager.certificate(manager, "203.0.113.7", "203.0.113.7")

    assert {:error, {:sni_ip_mismatch, "203.0.113.8", "203.0.113.7"}} =
             IPManager.certificate(manager, "203.0.113.7", "203.0.113.8")

    assert {:error, {:no_certificate_for_hostname, "derp.example.com"}} =
             IPManager.certificate(manager, "203.0.113.7", "derp.example.com")

    second_manager =
      start_supervised!(
        Supervisor.child_spec(
          {IPManager, directory: directory, issuer: issuer},
          id: {:second_ip_manager, make_ref()}
        )
      )

    assert {:ok, cached_certificate} = IPManager.certificate(second_manager, "203.0.113.7")
    assert cached_certificate.certificate_der == ipv4_certificate.certificate_der
    assert length(Agent.get(calls, & &1)) == 2

    assert :ok = IPManager.put_challenge(manager, "/.well-known/acme-challenge/token", "answer")

    assert IPManager.http_response(manager, "/.well-known/acme-challenge/token") ==
             {:ok, "answer"}

    assert IPManager.http_response(manager, "/.well-known/acme-challenge/missing") ==
             :not_found

    assert IPManager.http_response(manager, "/other") == :fallback
  end

  test "delegates DNS SNI to the next provider without issuing an IP certificate" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-next-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    parent = self()

    issuer = fn ip, profile ->
      send(parent, {:unexpected_issue, ip, profile})
      {:error, :unexpected}
    end

    next_provider = fn hostname -> {:ok, {:hostname_certificate, hostname}} end

    manager =
      start_supervised!(
        {IPManager, directory: directory, issuer: issuer, next_provider: next_provider}
      )

    assert IPManager.certificate(manager, "203.0.113.7", "derp.example.com") ==
             {:ok, {:hostname_certificate, "derp.example.com"}}

    refute_receive {:unexpected_issue, _ip, _profile}
  end
end
