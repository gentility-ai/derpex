defmodule Derpex.Certificates.IPManagerFlightTest do
  use ExUnit.Case, async: true

  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Manual

  setup do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-flight-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, directory: directory}
  end

  test "concurrent callers for one address share a single issuance", context do
    parent = self()

    issuer = fn ip, profile ->
      send(parent, {:issuing, ip, self()})
      receive do: (:release -> :ok)
      IPManager.self_signed_issuer(ip, profile)
    end

    manager = start_supervised!({IPManager, directory: context.directory, issuer: issuer})

    callers =
      for _each <- 1..3 do
        Task.async(fn -> IPManager.certificate(manager, "203.0.113.7") end)
      end

    assert_receive {:issuing, "203.0.113.7", flight}, 1_000
    refute_receive {:issuing, "203.0.113.7", _other}, 100
    send(flight, :release)

    results = Task.await_many(callers, 5_000)
    assert [{:ok, certificate}] = Enum.uniq(results)
    assert :ok = Manual.verify_certificate(certificate.certificate_der, "203.0.113.7")
    refute_receive {:issuing, _ip, _pid}, 100
  end

  test "an issuance in flight does not stall another address", context do
    parent = self()

    issuer = fn ip, profile ->
      send(parent, {:issuing, ip, self()})
      if ip == "203.0.113.9", do: receive(do: (:release -> :ok))
      IPManager.self_signed_issuer(ip, profile)
    end

    manager = start_supervised!({IPManager, directory: context.directory, issuer: issuer})
    assert {:ok, _ready} = IPManager.certificate(manager, "203.0.113.7")
    assert_receive {:issuing, "203.0.113.7", _first}, 1_000

    slow = Task.async(fn -> IPManager.certificate(manager, "203.0.113.9") end)
    assert_receive {:issuing, "203.0.113.9", flight}, 1_000

    # The manager is still answering while that issuance is outstanding.
    assert {:ok, _cached} = IPManager.certificate(manager, "203.0.113.7")
    send(flight, :release)
    assert {:ok, _issued} = Task.await(slow, 5_000)
  end

  test "a crashed issuance is reported to its callers and backs off", context do
    issuer = fn _ip, _profile -> exit(:issuer_died) end
    manager = start_supervised!({IPManager, directory: context.directory, issuer: issuer})

    assert {:error, {:issuance, {:flight_failed, :issuer_died}}} =
             IPManager.certificate(manager, "203.0.113.7")

    assert Process.alive?(manager)
    assert {:error, {:issuance_deferred, _at}} = IPManager.certificate(manager, "203.0.113.7")
  end

  test "an issuance can publish an HTTP-01 challenge through the manager", context do
    parent = self()
    name = :"derpex_ipcert_flight_#{System.unique_integer([:positive])}"
    path = "/.well-known/acme-challenge/tok"

    issuer = fn ip, profile ->
      :ok = IPManager.put_challenge(name, path, "answer")
      send(parent, {:published, IPManager.http_response(name, path)})
      :ok = IPManager.delete_challenge(name, path)
      IPManager.self_signed_issuer(ip, profile)
    end

    manager =
      start_supervised!({IPManager, name: name, directory: context.directory, issuer: issuer})

    # The flight runs outside the manager, so it can call back into it while a
    # certificate request is still outstanding. ACME needs exactly this.
    assert {:ok, _certificate} = IPManager.certificate(manager, "203.0.113.7")
    assert_received {:published, {:ok, "answer"}}
    assert IPManager.http_response(manager, path) == :not_found
  end
end
