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

  test "caches issued certificates through the atomic private-file path" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-modes-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)

    issuer = fn ip, _profile ->
      with {:ok, {certificate_der, private_key}} <- Manual.generate_ip(ip) do
        {:ok, %{certificate_der: certificate_der, private_key: private_key}}
      end
    end

    manager = start_supervised!({IPManager, directory: directory, issuer: issuer})
    assert {:ok, _certificate} = IPManager.certificate(manager, "203.0.113.7")

    assert file_mode(directory) == 0o700
    assert file_mode(Path.join(directory, "203.0.113.7.key")) == 0o600
    assert file_mode(Path.join(directory, "203.0.113.7.crt")) == 0o644
    assert Enum.filter(File.ls!(directory), &String.contains?(&1, ".tmp.")) == []
  end

  test "issues under the canonical unmapped address for an IPv4-mapped IPv6 connection" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-unmap-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    calls = start_supervised!({Agent, fn -> [] end})

    issuer = fn ip, profile ->
      Agent.update(calls, &[{ip, profile} | &1])
      IPManager.self_signed_issuer(ip, profile)
    end

    manager = start_supervised!({IPManager, directory: directory, issuer: issuer})

    assert {:ok, certificate} = IPManager.certificate(manager, "::ffff:203.0.113.7")
    assert Agent.get(calls, &Enum.reverse/1) == [{"203.0.113.7", "shortlived"}]
    assert :ok = Manual.verify_certificate(certificate.certificate_der, "203.0.113.7")
    assert File.exists?(Path.join(directory, "203.0.113.7.crt"))

    # The same address in either notation is one entry, and an IPv4-mapped SNI
    # matches an IPv4 connection, as Go's sniIP.Unmap() comparison does.
    assert IPManager.certificate(manager, "203.0.113.7") == {:ok, certificate}

    assert IPManager.certificate(manager, "203.0.113.7", "::ffff:203.0.113.7") ==
             {:ok, certificate}

    assert IPManager.certificate(manager, "::ffff:203.0.113.7", "203.0.113.7") ==
             {:ok, certificate}

    assert length(Agent.get(calls, & &1)) == 1
  end

  test "builds one certs_keys entry per certificate and appends the listener metacertificate" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-keys-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)

    manager =
      start_supervised!(
        {IPManager, directory: directory, issuer: &IPManager.self_signed_issuer/2}
      )

    meta_certificate = "metacertificate"

    assert {:ok, %{cert: [leaf, ^meta_certificate], key: {type, key_der}}} =
             IPManager.certs_keys(manager, "203.0.113.7", "", meta_certificate)

    assert type in [:RSAPrivateKey, :ECPrivateKey, :PrivateKeyInfo]
    assert is_binary(key_der)
    assert :ok = Manual.verify_certificate(leaf, "203.0.113.7")

    # A second listener metacertificate reuses the key encoded at issuance.
    other = "other-metacertificate"

    assert {:ok, %{cert: [^leaf, ^other], key: {^type, ^key_der}}} =
             IPManager.certs_keys(manager, "203.0.113.7", "203.0.113.7", other)

    assert IPManager.certs_keys(manager, "203.0.113.7", "203.0.113.8", meta_certificate) ==
             {:error, {:sni_ip_mismatch, "203.0.113.8", "203.0.113.7"}}
  end

  test "refuses a disk-cached certificate whose key does not match it" do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-pairing-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    calls = start_supervised!({Agent, fn -> 0 end})

    issuer = fn ip, profile ->
      Agent.update(calls, &(&1 + 1))
      IPManager.self_signed_issuer(ip, profile)
    end

    manager = start_supervised!({IPManager, directory: directory, issuer: issuer})
    assert {:ok, cached} = IPManager.certificate(manager, "203.0.113.7")
    assert Agent.get(calls, & &1) == 1

    # Swap in a well-formed key that belongs to a different certificate.
    {:ok, {_other_der, other_key}} = Manual.generate_ip("203.0.113.7")

    File.write!(
      Path.join(directory, "203.0.113.7.key"),
      :public_key.pem_encode([:public_key.pem_entry_encode(:RSAPrivateKey, other_key)])
    )

    second =
      start_supervised!(
        Supervisor.child_spec({IPManager, directory: directory, issuer: issuer},
          id: :pairing_reader
        )
      )

    assert {:ok, reissued} = IPManager.certificate(second, "203.0.113.7")
    assert Agent.get(calls, & &1) == 2
    refute reissued.certificate_der == cached.certificate_der
  end

  defp file_mode(path) do
    {:ok, stat} = File.stat(path)
    Bitwise.band(stat.mode, 0o777)
  end
end
