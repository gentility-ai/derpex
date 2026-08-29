defmodule Derpex.Certificates.IPManagerBoundsTest do
  @moduledoc """
  What a stalled certificate authority may cost the relay.

  An issuance that hangs must not let hellos accumulate in the manager, must
  not block the manager for anything else, and must not leave callers waiting
  without end.
  """

  use ExUnit.Case, async: false

  alias Derpex.Certificates.IPManager

  @moduletag timeout: 120_000

  setup do
    directory =
      Path.join(System.tmp_dir!(), "derpex-ipcert-bounds-#{System.unique_integer([:positive])}")

    on_exit(fn -> File.rm_rf!(directory) end)
    on_exit(fn -> :persistent_term.erase({IPManager, :bootstrap_subjects}) end)
    {:ok, directory: directory}
  end

  test "a thousand hellos against a stalled issuer stay bounded", context do
    parent = self()

    issuer = fn ip, profile ->
      send(parent, {:issuing, self()})
      receive do: (:release -> :ok)
      IPManager.self_signed_issuer(ip, profile)
    end

    manager = start_supervised!({IPManager, directory: context.directory, issuer: issuer})
    meta = "meta"
    sni = IPManager.sni_fun(manager, "203.0.113.7", meta)

    hellos =
      for _each <- 1..1_000 do
        Task.async(fn -> sni.(~c"203.0.113.7") end)
      end

    assert_receive {:issuing, flight}, 5_000

    # Every hello is waiting on one order, and the manager keeps at most the
    # cap of them; the rest are refused rather than queued.
    await_waiters(manager, "203.0.113.7")
    state = :sys.get_state(manager)
    waiters = state.entries["203.0.113.7"].flight.waiters
    assert length(waiters) <= 256
    assert map_size(state.waiters) == length(waiters)

    # The manager is answering other work throughout.
    assert IPManager.http_response(manager, "/nowhere") == :fallback

    results = Task.await_many(hellos, 30_000)
    assert :unrecognized in results, "no hello was refused while the issuer stalled"

    send(flight, :release)

    # Once the order finishes the manager holds no waiters at all, and the
    # next hello is answered from the certificate.
    await_idle(manager)
    assert :sys.get_state(manager).waiters == %{}
    assert [certs_keys: [%{cert: [_leaf, ^meta]}]] = sni.(~c"203.0.113.7")
  end

  test "a caller that gives up is dropped rather than kept", context do
    parent = self()

    issuer = fn ip, profile ->
      send(parent, {:issuing, self()})
      receive do: (:release -> :ok)
      IPManager.self_signed_issuer(ip, profile)
    end

    manager = start_supervised!({IPManager, directory: context.directory, issuer: issuer})

    caller =
      spawn(fn -> IPManager.certificate(manager, "203.0.113.7") end)

    assert_receive {:issuing, flight}, 5_000
    await_waiters(manager, "203.0.113.7")
    assert map_size(:sys.get_state(manager).waiters) == 1

    reference = Process.monitor(caller)
    Process.exit(caller, :kill)
    assert_receive {:DOWN, ^reference, :process, ^caller, :killed}, 5_000

    await_no_waiters(manager)
    assert :sys.get_state(manager).entries["203.0.113.7"].flight.waiters == []

    send(flight, :release)
    await_idle(manager)
  end

  test "renewals reach every listener bound to the subject", context do
    manager =
      start_supervised!(
        {IPManager, directory: context.directory, issuer: &IPManager.self_signed_issuer/2}
      )

    first = {__MODULE__, :first, System.unique_integer([:positive])}
    second = {__MODULE__, :second, System.unique_integer([:positive])}
    on_exit(fn -> Enum.each([first, second], &:persistent_term.erase/1) end)

    # Two listeners on one address — an IPv4 and an IPv6 bind, say — each with
    # its own snapshot and its own metacertificate.
    assert IPManager.publish_to(manager, first, "203.0.113.7", "meta-one") == :bootstrap
    assert IPManager.publish_to(manager, second, "203.0.113.7", "meta-two") == :bootstrap

    assert {:ok, certificate} = IPManager.certificate(manager, "203.0.113.7")
    leaf = certificate.certificate_der

    assert [%{cert: [^leaf, "meta-one"]}] = :persistent_term.get(first)
    assert [%{cert: [^leaf, "meta-two"]}] = :persistent_term.get(second)

    # A renewal reaches both, not just the one registered last.
    :ok = IPManager.ensure(manager, "203.0.113.7")
    await_idle(manager)
    assert [%{cert: [^leaf, "meta-one"]}] = :persistent_term.get(first)
    assert [%{cert: [^leaf, "meta-two"]}] = :persistent_term.get(second)
  end

  defp await_waiters(manager, ip, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 10_000
    state = :sys.get_state(manager)

    cond do
      match?(%{flight: %{waiters: [_ | _]}}, Map.get(state.entries, ip)) ->
        :ok

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("no hello was recorded as waiting")

      true ->
        Process.sleep(5)
        await_waiters(manager, ip, deadline)
    end
  end

  defp await_no_waiters(manager, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 10_000

    cond do
      :sys.get_state(manager).waiters == %{} ->
        :ok

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("a dead caller was still held as a waiter")

      true ->
        Process.sleep(5)
        await_no_waiters(manager, deadline)
    end
  end

  defp await_idle(manager, deadline \\ nil) do
    deadline = deadline || System.monotonic_time(:millisecond) + 10_000
    state = :sys.get_state(manager)

    cond do
      state.flights == %{} and Enum.all?(state.entries, fn {_ip, e} -> is_nil(e.flight) end) ->
        :ok

      System.monotonic_time(:millisecond) >= deadline ->
        flunk("an issuance was still in flight")

      true ->
        Process.sleep(5)
        await_idle(manager, deadline)
    end
  end
end
