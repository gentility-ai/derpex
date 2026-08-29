defmodule Derpex.Certificates.IPManagerValidityTest do
  use ExUnit.Case, async: false

  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Manual
  alias Derpex.Clock

  # `Derpex.Certificates.Manual.generate_ip/1` dates a certificate from the
  # injected clock: NotBefore a minute back, NotAfter a year on.
  @backdate_seconds 60
  @lifetime_seconds 365 * 24 * 60 * 60 + 60
  @issued_at_ms 1_700_000_000_000

  # Upstream renews once less than a third of the lifetime remains. Measured
  # from issuance, that is the first second at which a renewal must happen.
  @renewal_seconds @lifetime_seconds - div(@lifetime_seconds, 3) - @backdate_seconds + 1

  setup do
    start_supervised!({Clock.Manual, monotonic_time: 0, system_time: @issued_at_ms})
    previous = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Clock.Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous) end)

    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-clock-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    {:ok, directory: directory}
  end

  test "reissues a certificate once two thirds of its lifetime has elapsed", context do
    {manager, calls} = start_manager(context.directory)

    assert {:ok, first} = IPManager.certificate(manager, "203.0.113.7")
    assert issued(calls) == 1

    :ok = Clock.Manual.advance((@renewal_seconds - 1) * 1_000)
    assert IPManager.certificate(manager, "203.0.113.7") == {:ok, first}
    assert issued(calls) == 1

    :ok = Clock.Manual.advance(1_000)
    assert {:ok, renewed} = IPManager.certificate(manager, "203.0.113.7")
    assert issued(calls) == 2
    refute renewed.certificate_der == first.certificate_der
    assert :ok = Manual.verify_certificate(renewed.certificate_der, "203.0.113.7")
  end

  test "keeps serving a still-valid certificate when a renewal fails", context do
    {manager, calls} = start_manager(context.directory, [:ok, {:error, :issuer_unavailable}])

    assert {:ok, first} = IPManager.certificate(manager, "203.0.113.7")
    :ok = Clock.Manual.advance(@renewal_seconds * 1_000)

    assert IPManager.certificate(manager, "203.0.113.7") == {:ok, first}
    assert issued(calls) == 2
  end

  test "refuses a disk-cached certificate that has expired", context do
    cached = cache_certificate(context.directory)
    :ok = Clock.Manual.advance((@lifetime_seconds + 1) * 1_000)

    {manager, calls} = start_manager(context.directory, [:ok], :reader)
    assert {:ok, reissued} = IPManager.certificate(manager, "203.0.113.7")
    assert issued(calls) == 1
    refute reissued.certificate_der == cached.certificate_der
  end

  test "refuses a disk-cached certificate that is not yet valid", context do
    cached = cache_certificate(context.directory)
    :ok = Clock.Manual.set_system_time(@issued_at_ms - (@backdate_seconds + 1) * 1_000)

    {manager, calls} = start_manager(context.directory, [:ok], :reader)
    assert {:ok, reissued} = IPManager.certificate(manager, "203.0.113.7")
    assert issued(calls) == 1
    refute reissued.certificate_der == cached.certificate_der
  end

  test "refuses an issued certificate that is outside its own validity window", context do
    parent = self()

    issuer = fn ip, _profile ->
      send(parent, :issued)
      :ok = Clock.Manual.set_system_time(@issued_at_ms - 10 * @lifetime_seconds * 1_000)
      result = IPManager.self_signed_issuer(ip, IPManager.profile())
      :ok = Clock.Manual.set_system_time(@issued_at_ms)
      result
    end

    manager =
      start_supervised!(
        Supervisor.child_spec({IPManager, directory: context.directory, issuer: issuer},
          id: :stale_issuer
        )
      )

    assert {:error, {:issuance, {:certificate_not_valid_now, _from, _until}}} =
             IPManager.certificate(manager, "203.0.113.7")

    assert_received :issued
    refute File.exists?(Path.join(context.directory, "203.0.113.7.crt"))
  end

  defp cache_certificate(directory) do
    {manager, _calls} = start_manager(directory, [:ok], :writer)
    assert {:ok, certificate} = IPManager.certificate(manager, "203.0.113.7")
    :ok = stop_supervised(:writer)
    certificate
  end

  defp start_manager(directory, outcomes \\ [:ok], id \\ :ip_manager) do
    calls = start_supervised!({Agent, fn -> {0, outcomes} end}, id: {:calls, id})

    issuer = fn ip, profile ->
      outcome =
        Agent.get_and_update(calls, fn {count, [outcome | rest]} ->
          {outcome, {count + 1, if(rest == [], do: [outcome], else: rest)}}
        end)

      case outcome do
        :ok -> IPManager.self_signed_issuer(ip, profile)
        {:error, reason} -> {:error, reason}
      end
    end

    manager =
      start_supervised!(
        Supervisor.child_spec({IPManager, directory: directory, issuer: issuer}, id: id)
      )

    {manager, calls}
  end

  defp issued(calls), do: Agent.get(calls, fn {count, _outcomes} -> count end)
end
