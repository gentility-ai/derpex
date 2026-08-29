defmodule Derpex.Admission.GentilityTest do
  use ExUnit.Case, async: false

  alias Derpex.Admission.Gentility
  alias Derpex.Admission.Gentility.Cache
  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation
  alias Derpex.Admission.Gentility.UsageContract
  alias Derpex.Admission.Request
  alias Derpex.ClientInfo
  alias Derpex.Clock.Manual

  @private_key :binary.copy(<<0x10>>, 32)
  @public_key elem(:crypto.generate_key(:eddsa, :ed25519, @private_key), 0)
  @signing_key_id "gentility-2026-08"

  setup do
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    start_supervised!({Manual, system_time: 1_000})
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)
    :ok
  end

  test "uses a verified live lease, reconnects from cache during outage, and closes at expiry" do
    parent = self()
    node_key = node_key(1)
    signed = signed_lease(node_key)
    {:ok, authority} = Agent.start_link(fn -> {:ok, signed} end)

    controller =
      start_controller(
        authority: fn _request -> Agent.get(authority, & &1) end,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)

    assert {:ok, %{gentility: %{source: :live, organization_id: "org_01"}}} =
             Gentility.authorize(request(node_key), policy)

    Agent.update(authority, fn _response -> {:error, :unavailable} end)

    assert {:ok, %{gentility: %{source: :cached, lease_expires_at_ms: 2_000}}} =
             Gentility.authorize(request(node_key), policy)

    assert Gentility.authorize(request(node_key(2)), policy) ==
             {:error, :no_cached_lease}

    Manual.advance(1_000)
    assert_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 0
    assert Gentility.authorize(request(node_key), policy) == {:error, :no_cached_lease}
  end

  test "any authority failure serves the cached lease instead of denying" do
    node_key = node_key(24)
    {:ok, authority} = Agent.start_link(fn -> {:ok, signed_lease(node_key)} end)

    controller = start_controller(authority: fn _request -> Agent.get(authority, & &1) end)
    policy = Gentility.policy(controller)

    assert {:ok, %{gentility: %{source: :live}}} = Gentility.authorize(request(node_key), policy)

    for failure <- [
          {:error, {:http, 503}},
          {:error, :closed},
          {:error, :unavailable},
          :not_a_response
        ] do
      Agent.update(authority, fn _response -> failure end)

      assert {:ok, %{gentility: %{source: :cached}}} =
               Gentility.authorize(request(node_key), policy)
    end
  end

  test "a denial arrives as a signed revocation record, not an authority error" do
    parent = self()
    node_key = node_key(25)
    {:ok, authority} = Agent.start_link(fn -> {:ok, signed_lease(node_key)} end)

    controller =
      start_controller(
        authority: fn _request -> Agent.get(authority, & &1) end,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)

    Agent.update(authority, fn _response -> {:ok, signed_revocation(node_key, 10)} end)

    assert Gentility.authorize(request(node_key), policy) == {:error, :lease_revoked}
    assert_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 0

    Agent.update(authority, fn _response -> {:error, :unavailable} end)
    assert Gentility.authorize(request(node_key), policy) == {:error, :no_cached_lease}

    Agent.update(authority, fn _response -> {:ok, signed_revocation(node_key(26), 10)} end)

    assert Gentility.authorize(request(node_key), policy) ==
             {:error, :revocation_node_key_mismatch}
  end

  test "a revocation that does not cover the cached lease keeps serving it" do
    parent = self()
    node_key = node_key(35)

    {:ok, authority} =
      Agent.start_link(fn -> {:ok, signed_lease(node_key, policy_revision: 11)} end)

    controller =
      start_controller(
        authority: fn _request -> Agent.get(authority, & &1) end,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)

    Agent.update(authority, fn _response -> {:ok, signed_revocation(node_key, 10)} end)

    assert {:ok, %{gentility: %{source: :cached, policy_revision: 11}}} =
             Gentility.authorize(request(node_key), policy)

    refute_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 1
    assert Gentility.stats(controller).revocations == 1

    assert {:ok, %{gentility: %{source: :cached}}} =
             Gentility.authorize(request(node_key), policy)

    assert Gentility.stats(controller).revocations == 1

    Agent.update(authority, fn _response -> {:ok, signed_revocation(node_key, 11)} end)

    assert Gentility.authorize(request(node_key), policy) == {:error, :lease_revoked}
    assert_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 0
  end

  test "an authority record of no known type is rejected as an unknown record" do
    node_key = node_key(36)

    controller =
      start_controller(authority: fn _request -> {:ok, :binary.copy(<<0x7F>>, 128)} end)

    assert Gentility.authorize(request(node_key), Gentility.policy(controller)) ==
             {:error, :unknown_record_type}
  end

  test "counts every authorization outcome and rate-limits the outage warning" do
    node_key = node_key(43)
    {:ok, authority} = Agent.start_link(fn -> {:ok, signed_lease(node_key)} end)

    controller =
      start_controller(
        authority: fn _request -> Agent.get(authority, & &1) end,
        log_interval_ms: 60_000
      )

    policy = Gentility.policy(controller)

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert {:ok, %{gentility: %{source: :live}}} =
                 Gentility.authorize(request(node_key), policy)

        Agent.update(authority, fn _response -> {:error, :unavailable} end)

        for _attempt <- 1..3 do
          assert {:ok, %{gentility: %{source: :cached}}} =
                   Gentility.authorize(request(node_key), policy)
        end

        assert Gentility.authorize(request(node_key(44)), policy) == {:error, :no_cached_lease}
      end)

    assert log =~ "authority unavailable"
    assert length(String.split(log, "authority unavailable")) == 2

    counts = Gentility.stats(controller).authorize_counts
    assert counts[{:live, :ok}] == 1
    assert counts[{:cached, :ok}] == 3
    assert counts[{:denied, :no_cached_lease}] == 1
  end

  test "counts closed peers by cause and reports the nearest lease expiry" do
    node_key = node_key(45)

    controller =
      start_controller(
        authority: fn request -> {:ok, signed_lease(request.node_key)} end,
        close_peer: fn _key -> 0 end
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)

    stats = Gentility.stats(controller)
    assert stats.nearest_lease_expiry_seconds == 1
    refute stats.cache_load_error
    refute stats.cache_persist_error

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        assert Gentility.revoke(controller, signed_revocation(node_key, 10)) == {:ok, :applied}
      end)

    assert log =~ "revocation applied"
    stats = Gentility.stats(controller)
    assert stats.close_peer_counts == %{revocation: 1}
    assert stats.nearest_lease_expiry_seconds == nil

    assert {:ok, _context} = Gentility.authorize(request(node_key(46)), policy)
    Manual.advance(1_000)
    eventually(fn -> Gentility.stats(controller).close_peer_counts[:expiry] == 1 end)
  end

  test "counts admission shed by the concurrency gate without a controller call" do
    parent = self()

    authority = fn _request ->
      send(parent, {:authority_started, self()})
      receive do: (:release -> {:ok, signed_lease(node_key(47))})
    end

    controller = start_controller(authority: authority, max_concurrent_requests: 1)
    policy = Gentility.policy(controller)
    first = Task.async(fn -> Gentility.authorize(request(node_key(47)), policy) end)
    assert_receive {:authority_started, authority_process}

    assert Gentility.authorize(request(node_key(48)), policy) == {:error, :admission_overloaded}

    send(authority_process, :release)
    assert {:ok, _context} = Task.await(first)

    counts = Gentility.stats(controller).authorize_counts
    assert counts[{:denied, :overloaded}] == 1
  end

  test "exports fixed-cardinality admission metrics through operations" do
    node_key = node_key(49)

    start_supervised!(
      {Gentility,
       [
         name: Gentility,
         authority: fn request -> {:ok, signed_lease(request.node_key)} end,
         verification_keys: %{@signing_key_id => @public_key},
         clock: Manual,
         max_lease_ms: 1_000,
         max_future_skew_ms: 0,
         expiry_jitter: fn _lifetime_ms -> 0 end
       ]}
    )

    assert {:ok, _context} = Gentility.authorize(request(node_key), Gentility.policy(Gentility))

    text = Derpex.Operations.prometheus()

    assert text =~ ~s(derpex_gentility_authorize_total{outcome="live",reason="ok"} 1)
    assert text =~ ~s(derpex_gentility_authorize_total{outcome="cached",reason="ok"} 0)
    assert text =~ ~s(derpex_gentility_authorize_total{outcome="denied",reason="cache_full"} 0)
    assert text =~ ~s(derpex_gentility_close_peer_total{cause="expiry"} 0)
    assert text =~ "derpex_gentility_nearest_lease_expiry_seconds 1"
    assert text =~ "derpex_gentility_cache_load_error 0"
    assert text =~ "derpex_gentility_cache_persist_error 0"

    series =
      text
      |> String.split("\n", trim: true)
      |> Enum.filter(&String.starts_with?(&1, "derpex_gentility_authorize_total"))

    assert length(series) == length(Gentility.authorize_labels())
  end

  test "renews a claimed lease before expiry without closing its connection" do
    parent = self()
    node_key = node_key(40)

    {:ok, authority} =
      Agent.start_link(fn ->
        {:ok, signed_lease(node_key, issued_at_ms: 1_000, expires_at_ms: 11_000)}
      end)

    renewed = signed_lease(node_key, issued_at_ms: 9_000, expires_at_ms: 19_000)

    controller =
      start_controller(
        authority: fn request ->
          send(parent, {:authorized, request.metadata})

          if request.metadata[:renewal],
            do: {:ok, renewed},
            else: Agent.get(authority, & &1)
        end,
        max_lease_ms: 10_000,
        close_peer: fn key -> send(parent, {:closed, key}) end,
        close_connection: fn connection, reason ->
          send(parent, {:quota_close, connection, reason})
        end
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert_receive {:authorized, %{}}
    [connection] = connections(1)
    assert {:ok, ^context} = Gentility.claim(request(node_key), context, connection, policy)

    # Only a renewal can refresh the lease from here: a fresh authorization is
    # answered with an outage.
    Agent.update(authority, fn _response -> {:error, :unavailable} end)

    Manual.advance(8_000)
    assert_receive {:authorized, %{renewal: true}}

    eventually(fn ->
      match?(
        {:ok, %{gentility: %{source: :cached, lease_expires_at_ms: 19_000}}},
        Gentility.authorize(request(node_key), policy)
      )
    end)

    # Past the original expiry: only a renewal that replaced the lease can keep
    # this node cached and its connection open.
    Manual.advance(2_500)
    refute_receive {:closed, ^node_key}
    refute_receive {:quota_close, ^connection, _reason}
    assert Gentility.stats(controller).cache_entries == 1
    assert Process.alive?(connection)

    Process.exit(connection, :kill)
  end

  test "a failed renewal keeps serving the lease until it expires" do
    parent = self()
    node_key = node_key(41)

    {:ok, authority} =
      Agent.start_link(fn ->
        {:ok, signed_lease(node_key, issued_at_ms: 1_000, expires_at_ms: 11_000)}
      end)

    controller =
      start_controller(
        authority: fn request ->
          send(parent, {:authorized, request.metadata})
          Agent.get(authority, & &1)
        end,
        max_lease_ms: 10_000,
        renewal_retry_ms: 60_000,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert_receive {:authorized, %{}}
    [connection] = connections(1)
    assert {:ok, ^context} = Gentility.claim(request(node_key), context, connection, policy)

    Agent.update(authority, fn _response -> {:error, {:http, 503}} end)

    Manual.advance(8_000)
    assert_receive {:authorized, %{renewal: true}}
    refute_receive {:closed, ^node_key}

    assert {:ok, %{gentility: %{source: :cached, lease_expires_at_ms: 11_000}}} =
             Gentility.authorize(request(node_key), policy)

    Manual.advance(2_000)
    assert_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 0

    Process.exit(connection, :kill)
  end

  test "an idle lease is never renewed and simply expires" do
    parent = self()
    node_key = node_key(42)

    controller =
      start_controller(
        authority: fn request ->
          send(parent, {:authorized, request.metadata})
          {:ok, signed_lease(request.node_key, issued_at_ms: 1_000, expires_at_ms: 11_000)}
        end,
        max_lease_ms: 10_000,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)
    assert_receive {:authorized, %{}}

    Manual.advance(8_000)
    refute_receive {:authorized, _metadata}

    Manual.advance(3_000)
    assert_receive {:closed, ^node_key}
  end

  test "spreads expiry closes across the last tenth of the lease" do
    parent = self()
    count = 20

    controller =
      start_controller(
        authority: fn request ->
          {:ok, signed_lease(request.node_key, issued_at_ms: 1_000, expires_at_ms: 11_000)}
        end,
        max_lease_ms: 10_000,
        expiry_jitter: nil,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)

    for index <- 1..count do
      assert {:ok, _context} = Gentility.authorize(request(<<index::256>>), policy)
    end

    Manual.advance(9_000)
    assert closed_keys() == []

    Manual.advance(500)
    early = closed_keys()

    Manual.advance(500)
    late = closed_keys()

    assert early != []
    assert late != []
    assert length(early) + length(late) == count
    assert Gentility.stats(controller).cache_entries == 0
  end

  test "active revocation is idempotent, rejects stale leases, and allows a newer revision" do
    parent = self()
    node_key = node_key(3)
    {:ok, authority} = Agent.start_link(fn -> {:ok, signed_lease(node_key)} end)

    controller =
      start_controller(
        authority: fn _request -> Agent.get(authority, & &1) end,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)

    revocation = signed_revocation(node_key, 10)
    assert Gentility.revoke(controller, revocation) == {:ok, :applied}
    assert_receive {:closed, ^node_key}
    assert Gentility.revoke(controller, revocation) == {:ok, :stale}
    refute_receive {:closed, ^node_key}

    assert Gentility.authorize(request(node_key), policy) == {:error, :lease_revoked}

    Agent.update(authority, fn _response -> {:ok, signed_lease(node_key, policy_revision: 11)} end)

    assert {:ok, %{gentility: %{policy_revision: 11}}} =
             Gentility.authorize(request(node_key), policy)

    assert Gentility.revoke(controller, revocation) == {:ok, :applied}
    refute_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 1
  end

  @tag :tmp_dir
  test "persists a restrictive bounded cache and recovers it without Gentility", %{
    tmp_dir: tmp_dir
  } do
    path = Path.join(tmp_dir, "admission.cache")
    node_key = node_key(4)

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        cache_path: path
      )

    policy = Gentility.policy(controller)

    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)
    assert :ok = stop_supervised(Gentility)

    assert {:ok, stat} = File.stat(path)
    assert Bitwise.band(stat.mode, 0o777) == 0o600

    controller =
      start_controller(authority: fn _request -> {:error, :unavailable} end, cache_path: path)

    assert {:ok, %{gentility: %{source: :cached}}} =
             Gentility.authorize(request(node_key), Gentility.policy(controller))
  end

  @tag :tmp_dir
  test "debounces lease writes and persists a revocation immediately", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "admission.cache")

    controller =
      start_controller(
        authority: fn request -> {:ok, signed_lease(request.node_key, expires_at_ms: 11_000)} end,
        max_lease_ms: 10_000,
        cache_path: path,
        cache_persist_ms: 5_000
      )

    policy = Gentility.policy(controller)

    for index <- 1..1_000 do
      assert {:ok, _context} = Gentility.authorize(request(<<index::256>>), policy)
    end

    assert Gentility.stats(controller).cache_entries == 1_000
    refute File.exists?(path)

    assert Gentility.revoke(controller, signed_revocation(<<1::256>>, 10)) == {:ok, :applied}
    assert File.exists?(path)
    revoked_size = File.stat!(path).size

    assert {:ok, _context} = Gentility.authorize(request(<<1_001::256>>), policy)
    assert File.stat!(path).size == revoked_size

    Manual.advance(5_000)
    eventually(fn -> File.stat!(path).size > revoked_size end)

    assert :ok = stop_supervised(Gentility)

    recovered =
      start_controller(
        authority: fn _request -> {:error, :unavailable} end,
        max_lease_ms: 10_000,
        cache_path: path
      )

    assert Gentility.stats(recovered).cache_entries == 1_000
    assert Gentility.stats(recovered).revocations == 1
  end

  @tag :tmp_dir
  test "writes the lease cache when the controller shuts down", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "admission.cache")
    node_key = node_key(38)

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        cache_path: path,
        cache_persist_ms: 600_000
      )

    assert {:ok, _context} = Gentility.authorize(request(node_key), Gentility.policy(controller))
    refute File.exists?(path)

    assert :ok = stop_supervised(Gentility)
    assert File.exists?(path)
  end

  @tag :tmp_dir
  test "recovers a cache holding two records for one node key", %{tmp_dir: tmp_dir} do
    parent = self()
    path = Path.join(tmp_dir, "admission.cache")
    node_key = node_key(39)

    :ok =
      Cache.store(
        path,
        [
          signed_lease(node_key, expires_at_ms: 1_500),
          signed_lease(node_key, expires_at_ms: 11_000)
        ],
        []
      )

    controller =
      start_controller(
        authority: fn _request -> {:error, :unavailable} end,
        max_lease_ms: 10_000,
        cache_path: path,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    assert Gentility.stats(controller).cache_entries == 1

    Manual.advance(600)
    assert Gentility.stats(controller).cache_entries == 1
    refute_receive {:closed, ^node_key}

    assert {:ok, %{gentility: %{source: :cached, lease_expires_at_ms: 11_000}}} =
             Gentility.authorize(request(node_key), Gentility.policy(controller))

    Manual.advance(10_000)
    assert_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 0
    refute_receive {:closed, ^node_key}
  end

  test "a controller refuses to start on invalid options" do
    assert {:error, {:invalid_verification_keys, _child}} =
             start_supervised(
               {Gentility,
                authority: fn _request -> {:error, :unavailable} end, verification_keys: %{}}
             )
  end

  @tag :tmp_dir
  test "corrupt durable state fails closed without preventing startup", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "admission.cache")
    File.write!(path, "not a cache")

    controller =
      start_controller(authority: fn _request -> {:error, :unavailable} end, cache_path: path)

    assert Gentility.stats(controller).load_error == :invalid_cache

    assert Gentility.authorize(request(node_key(5)), Gentility.policy(controller)) ==
             {:error, :no_cached_lease}
  end

  test "evicts at the hard cache bound and closes a possibly active evictee" do
    parent = self()

    controller =
      start_controller(
        authority: fn request -> {:ok, signed_lease(request.node_key)} end,
        max_cache_entries: 2,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)

    for byte <- 6..8 do
      assert {:ok, _context} = Gentility.authorize(request(node_key(byte)), policy)
    end

    first = node_key(6)
    assert_receive {:closed, ^first}
    assert Gentility.stats(controller).cache_entries == 2
  end

  test "evicts the soonest-expiring lease that no connection is claiming" do
    parent = self()
    keeper = node_key(27)
    soonest = node_key(28)
    admitted = node_key(29)

    controller =
      start_controller(
        authority: fn request -> {:ok, expiring_lease(request)} end,
        max_lease_ms: 10_000,
        max_cache_entries: 2,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)

    assert {:ok, _keeper} = Gentility.authorize(keeper_request(keeper, 9_000), policy)
    assert {:ok, _soonest} = Gentility.authorize(keeper_request(soonest, 4_000), policy)
    assert {:ok, _admitted} = Gentility.authorize(keeper_request(admitted, 8_000), policy)

    assert_receive {:closed, ^soonest}
    refute_receive {:closed, ^keeper}
    assert Gentility.stats(controller).cache_entries == 2
    assert Gentility.stats(controller).cache_full == 0
  end

  test "rejects a new admission with cache_full rather than closing a claimed peer" do
    parent = self()
    claimed = node_key(30)
    later = node_key(31)
    rejected = node_key(32)

    controller =
      start_controller(
        authority: fn request -> {:ok, expiring_lease(request)} end,
        max_lease_ms: 10_000,
        max_cache_entries: 2,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    {:ok, claimed_context} = Gentility.authorize(keeper_request(claimed, 4_000), policy)
    {:ok, later_context} = Gentility.authorize(keeper_request(later, 9_000), policy)
    [first, second] = connections(2)

    assert {:ok, ^claimed_context} =
             Gentility.claim(request(claimed), claimed_context, first, policy)

    assert {:ok, ^later_context} = Gentility.claim(request(later), later_context, second, policy)

    assert Gentility.authorize(keeper_request(rejected, 8_000), policy) ==
             {:error, :cache_full}

    refute_receive {:closed, _key}
    stats = Gentility.stats(controller)
    assert stats.cache_entries == 2
    assert stats.active_connections == 2
    assert stats.cache_full == 1

    assert Gentility.release(first, policy) == :ok

    assert {:ok, %{gentility: %{source: :live}}} =
             Gentility.authorize(keeper_request(rejected, 8_000), policy)

    assert_receive {:closed, ^claimed}
    assert Gentility.stats(controller).cache_full == 1

    Enum.each([first, second], &Process.exit(&1, :kill))
  end

  test "an expired lease is evicted before a live one even while it is claimed" do
    parent = self()
    expiring = node_key(33)
    admitted = node_key(34)

    controller =
      start_controller(
        authority: fn request -> {:ok, expiring_lease(request)} end,
        max_lease_ms: 10_000,
        max_cache_entries: 1,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(keeper_request(expiring, 1_500), policy)
    [connection] = connections(1)
    assert {:ok, ^context} = Gentility.claim(request(expiring), context, connection, policy)

    assert Gentility.authorize(keeper_request(admitted, 9_000), policy) == {:error, :cache_full}

    Manual.set_system_time(1_600)

    assert {:ok, %{gentility: %{source: :live}}} =
             Gentility.authorize(keeper_request(admitted, 9_000), policy)

    assert_receive {:closed, ^expiring}
    assert Gentility.stats(controller).cache_entries == 1

    Process.exit(connection, :kill)
  end

  @tag timeout: 600_000
  test "claims and releases in constant time against a full lease cache" do
    # The shape of the cost, not the size of the cache, is what this pins down,
    # and ten thousand leases already fail an implementation that scans them.
    # DERPEX_SLOW_TESTS=1 runs the full hundred thousand.
    entries = if System.get_env("DERPEX_SLOW_TESTS") == "1", do: 100_000, else: 10_000
    samples = 500
    now = System.system_time(:millisecond)

    controller =
      start_supervised!(
        {Gentility,
         [
           authority: fn request -> {:ok, perf_lease(request.node_key, now)} end,
           verification_keys: %{@signing_key_id => @public_key},
           clock: Derpex.Clock.System,
           max_lease_ms: 900_000,
           max_future_skew_ms: 30_000,
           max_cache_entries: entries
         ]}
      )

    policy = Gentility.policy(controller)

    contexts =
      Enum.reduce(1..entries, %{}, fn index, contexts ->
        node_key = <<index::256>>
        assert {:ok, context} = Gentility.authorize(request(node_key), policy)
        if index <= samples, do: Map.put(contexts, node_key, context), else: contexts
      end)

    assert Gentility.stats(controller).cache_entries == entries

    connections = connections(samples)

    claims =
      connections
      |> Enum.with_index(1)
      |> Enum.map(fn {connection, index} ->
        node_key = <<index::256>>
        context = Map.fetch!(contexts, node_key)
        request = request(node_key)

        {microseconds, result} =
          :timer.tc(fn -> Gentility.claim(request, context, connection, policy) end)

        assert {:ok, _context} = result
        {microseconds, connection}
      end)

    releases =
      Enum.map(claims, fn {_microseconds, connection} ->
        {microseconds, :ok} = :timer.tc(fn -> Gentility.release(connection, policy) end)
        microseconds
      end)

    claim_p99 = percentile(Enum.map(claims, &elem(&1, 0)), 99)
    release_p99 = percentile(releases, 99)

    assert claim_p99 < 100,
           "claim p99 was #{claim_p99} us over #{samples} samples with #{entries} cached leases"

    assert release_p99 < 100,
           "release p99 was #{release_p99} us over #{samples} samples with #{entries} cached leases"

    Enum.each(connections, &Process.exit(&1, :kill))
  end

  @tag :tmp_dir
  @tag timeout: 600_000
  test "authorizes in constant time while the cache is durable", %{tmp_dir: tmp_dir} do
    entries = if System.get_env("DERPEX_SLOW_TESTS") == "1", do: 100_000, else: 10_000
    now = System.system_time(:millisecond)

    controller =
      start_supervised!(
        {Gentility,
         [
           authority: fn request -> {:ok, perf_lease(request.node_key, now)} end,
           verification_keys: %{@signing_key_id => @public_key},
           clock: Derpex.Clock.System,
           max_lease_ms: 900_000,
           max_future_skew_ms: 30_000,
           max_cache_entries: entries,
           cache_path: Path.join(tmp_dir, "admission.cache"),
           cache_persist_ms: 100
         ]}
      )

    policy = Gentility.policy(controller)

    samples =
      Enum.map(1..entries, fn index ->
        request = request(<<index::256>>)
        {microseconds, result} = :timer.tc(fn -> Gentility.authorize(request, policy) end)
        assert {:ok, _context} = result
        microseconds
      end)

    assert Gentility.stats(controller).cache_entries == entries
    authorize_p99 = percentile(samples, 99)

    assert authorize_p99 < 1_500,
           "authorize p99 was #{authorize_p99} us over #{entries} admissions with a cache_path"
  end

  test "reclaims byte-budget rows on the prune timer, not on the admission path" do
    node_key = node_key(37)

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        budget_prune_ms: 30_000
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)
    assert :ets.info(policy.byte_budgets, :size) == 2

    assert Gentility.revoke(controller, signed_revocation(node_key, 10)) == {:ok, :applied}
    assert Gentility.stats(controller).cache_entries == 0
    assert :ets.info(policy.byte_budgets, :size) == 2
    assert Gentility.stats(controller).budget_nodes == 0

    Manual.advance(30_000)
    eventually(fn -> :ets.info(policy.byte_budgets, :size) == 0 end)
  end

  test "rejects excess authorization work before it enters controller state" do
    parent = self()

    authority = fn _request ->
      send(parent, {:authority_started, self()})
      receive do: (:release -> {:ok, signed_lease(node_key(9))})
    end

    controller = start_controller(authority: authority, max_concurrent_requests: 1)
    policy = Gentility.policy(controller)
    first = Task.async(fn -> Gentility.authorize(request(node_key(9)), policy) end)
    assert_receive {:authority_started, authority_process}

    assert Gentility.authorize(request(node_key(10)), policy) ==
             {:error, :admission_overloaded}

    send(authority_process, :release)
    assert {:ok, _context} = Task.await(first)
    assert Gentility.stats(controller).active_requests == 0
  end

  test "reconciliation validates the whole batch before applying missed revocations" do
    parent = self()
    keys = [node_key(11), node_key(12)]

    controller =
      start_controller(
        authority: fn request -> {:ok, signed_lease(request.node_key)} end,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)

    Enum.each(keys, fn key ->
      assert {:ok, _context} = Gentility.authorize(request(key), policy)
    end)

    records = Enum.map(keys, &signed_revocation(&1, 10))

    assert Gentility.reconcile(controller, records ++ ["invalid"]) ==
             {:error, :invalid_signed_record}

    refute_receive {:closed, _key}
    assert Gentility.stats(controller).cache_entries == 2

    assert Gentility.reconcile(controller, records) == {:ok, %{applied: 2, stale: 0}}
    assert_receive {:closed, key_a}
    assert_receive {:closed, key_b}
    assert MapSet.new([key_a, key_b]) == MapSet.new(keys)
  end

  test "verification-key rotation fails closed for leases signed only by a retired key" do
    parent = self()
    node_key = node_key(13)

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        close_peer: fn key -> send(parent, {:closed, key}) end
      )

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)

    {new_public, _new_private} = :crypto.generate_key(:eddsa, :ed25519)
    assert Gentility.update_verification_keys(controller, %{"next" => new_public}) == :ok
    assert_receive {:closed, ^node_key}
    assert Gentility.stats(controller).cache_entries == 0

    assert Gentility.authorize(request(node_key), policy) ==
             {:error, {:unknown_signing_key, @signing_key_id}}
  end

  test "claims and releases exact per-node and per-organization connection allocations" do
    node_a = node_key(14)
    node_b = node_key(15)

    controller =
      start_controller(
        authority: fn request ->
          {:ok,
           signed_lease(request.node_key,
             node_connection_limit: 2,
             organization_connection_limit: 2
           )}
        end
      )

    policy = Gentility.policy(controller)
    {:ok, context_a} = Gentility.authorize(request(node_a), policy)
    {:ok, context_b} = Gentility.authorize(request(node_b), policy)
    [first, second, third] = connections(3)

    assert Gentility.claim(request(node_a), context_a, first, policy) == {:ok, context_a}
    assert Gentility.claim(request(node_a), context_a, second, policy) == {:ok, context_a}

    assert Gentility.claim(request(node_a), context_a, third, policy) ==
             {:error, :node_connection_limit}

    assert Gentility.claim(request(node_b), context_b, third, policy) ==
             {:error, :organization_connection_limit}

    assert Gentility.stats(controller).active_connections == 2
    assert Gentility.release(first, policy) == :ok
    assert Gentility.claim(request(node_b), context_b, third, policy) == {:ok, context_b}
    assert Gentility.stats(controller).active_connections == 2

    Enum.each([first, second, third], &Process.exit(&1, :kill))
    eventually(fn -> Gentility.stats(controller).active_connections == 0 end)
  end

  test "a live quota revision closes only the newest excess connections" do
    parent = self()
    node_key = node_key(16)

    {:ok, authority} =
      Agent.start_link(fn ->
        signed_lease(node_key,
          quota_revision: 3,
          node_connection_limit: 4,
          organization_connection_limit: 10
        )
      end)

    controller =
      start_controller(
        authority: fn _request -> {:ok, Agent.get(authority, & &1)} end,
        close_connection: fn connection, reason ->
          send(parent, {:quota_close, connection, reason})
        end
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    [oldest, middle, newest] = connections(3)

    Enum.each([oldest, middle, newest], fn connection ->
      assert {:ok, ^context} = Gentility.claim(request(node_key), context, connection, policy)
    end)

    Agent.update(authority, fn _wire ->
      signed_lease(node_key,
        quota_revision: 4,
        node_connection_limit: 1,
        organization_connection_limit: 10
      )
    end)

    assert {:ok, %{gentility: %{quota_revision: 4}}} =
             Gentility.authorize(request(node_key), policy)

    assert_receive {:quota_close, ^newest, :quota_revision}
    assert_receive {:quota_close, ^middle, :quota_revision}
    refute_receive {:quota_close, ^oldest, :quota_revision}

    Enum.each([oldest, middle, newest], &Process.exit(&1, :kill))
  end

  test "will not roll a cached policy or quota revision backwards" do
    node_key = node_key(17)

    {:ok, authority} =
      Agent.start_link(fn -> signed_lease(node_key, policy_revision: 20, quota_revision: 8) end)

    controller =
      start_controller(authority: fn _request -> {:ok, Agent.get(authority, & &1)} end)

    policy = Gentility.policy(controller)
    assert {:ok, _context} = Gentility.authorize(request(node_key), policy)

    Agent.update(authority, fn _wire ->
      signed_lease(node_key, policy_revision: 19, quota_revision: 9)
    end)

    assert Gentility.authorize(request(node_key), policy) == {:error, :stale_lease}

    Agent.update(authority, fn _wire ->
      signed_lease(node_key, policy_revision: 20, quota_revision: 7)
    end)

    assert Gentility.authorize(request(node_key), policy) == {:error, :stale_lease}
  end

  test "reserves shared node and organization byte budgets and applies live revisions" do
    node_key = node_key(18)

    {:ok, authority} =
      Agent.start_link(fn ->
        signed_lease(node_key,
          quota_revision: 3,
          node_bytes_per_second: 100,
          node_byte_burst: 100,
          organization_bytes_per_second: 100,
          organization_byte_burst: 100
        )
      end)

    controller =
      start_controller(
        authority: fn _request -> {:ok, Agent.get(authority, & &1)} end,
        max_byte_delay_ms: 1_000
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert Gentility.reserve_bytes(context, 100, policy) == {:ok, 0}
    assert Gentility.reserve_bytes(context, 50, policy) == {:ok, 500_000}

    Manual.advance(500)

    Agent.update(authority, fn _wire ->
      signed_lease(node_key,
        quota_revision: 4,
        node_bytes_per_second: 200,
        node_byte_burst: 200,
        organization_bytes_per_second: 200,
        organization_byte_burst: 200
      )
    end)

    assert {:ok, revised_context} = Gentility.authorize(request(node_key), policy)
    assert Gentility.reserve_bytes(revised_context, 100, policy) == {:ok, 500_000}
  end

  test "closes instead of accumulating an unbounded byte-budget delay" do
    node_key = node_key(19)

    controller =
      start_controller(
        authority: fn _request ->
          {:ok,
           signed_lease(node_key,
             node_bytes_per_second: 100,
             node_byte_burst: 100,
             organization_bytes_per_second: 100,
             organization_byte_burst: 100
           )}
        end,
        max_byte_delay_ms: 100
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert Gentility.reserve_bytes(context, 100, policy) == {:ok, 0}
    assert Gentility.reserve_bytes(context, 50, policy) == {:error, :byte_budget_exhausted}
  end

  @tag :tmp_dir
  test "exports fixed usage windows and durably acknowledges their idempotency key", %{
    tmp_dir: tmp_dir
  } do
    parent = self()
    node_key = node_key(20)

    exporter = fn id, wire ->
      send(parent, {:usage_export, id, wire})
      :ok
    end

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        usage: usage_options(tmp_dir, exporter)
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert Gentility.record_usage(context, 100, :accepted, policy) == :ok
    assert Gentility.record_usage(context, 20, :dropped, policy) == :ok

    Manual.advance(100)
    assert_receive {:usage_export, id, wire}, 2_000
    assert {:ok, batch} = UsageContract.decode(wire, id)
    assert batch.window_start_ms == 1_000
    assert batch.window_end_ms == 1_100
    assert [entry] = batch.entries
    assert entry.node_id == "node_01"
    assert entry.accepted_packets == 1
    assert entry.accepted_bytes == 100
    assert entry.dropped_packets == 1
    assert entry.dropped_bytes == 20

    eventually(fn -> Gentility.stats(controller).usage.spool_batches == 0 end)
    assert Gentility.stats(controller).usage.aggregate_entries == 0
  end

  @tag :tmp_dir
  test "replays the same durable usage id after outage and controller restart", %{
    tmp_dir: tmp_dir
  } do
    parent = self()
    node_key = node_key(21)

    failing_exporter = fn id, wire ->
      send(parent, {:failed_usage_export, id, wire})
      {:error, :unavailable}
    end

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        usage: usage_options(tmp_dir, failing_exporter)
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert Gentility.record_usage(context, 64, :accepted, policy) == :ok
    Manual.advance(100)
    assert_receive {:failed_usage_export, id, wire}, 2_000
    eventually(fn -> Gentility.stats(controller).usage.spool_batches == 1 end)
    refute_receive {:failed_usage_export, _id, _wire}, 25
    assert :ok = stop_supervised(Gentility)

    successful_exporter = fn replay_id, replay_wire ->
      send(parent, {:replayed_usage_export, replay_id, replay_wire})
      :ok
    end

    controller =
      start_controller(
        authority: fn _request -> {:error, :unavailable} end,
        usage: usage_options(tmp_dir, successful_exporter)
      )

    assert_receive {:replayed_usage_export, ^id, ^wire}, 2_000
    eventually(fn -> Gentility.stats(controller).usage.spool_batches == 0 end)
  end

  @tag :tmp_dir
  test "a full durable usage spool stops packet admission without growing state", %{
    tmp_dir: tmp_dir
  } do
    parent = self()
    node_key = node_key(22)

    exporter = fn _id, _wire ->
      send(parent, {:blocked_usage_export, self()})
      receive do: (:release -> :ok)
    end

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        usage: usage_options(tmp_dir, exporter, max_batches: 1)
      )

    policy = Gentility.policy(controller)
    {:ok, context} = Gentility.authorize(request(node_key), policy)
    assert Gentility.record_usage(context, 10, :accepted, policy) == :ok
    Manual.advance(100)
    assert_receive {:blocked_usage_export, _worker}, 2_000

    assert Gentility.record_usage(context, 20, :accepted, policy) == :ok
    Manual.advance(100)
    eventually(fn -> Gentility.stats(controller).usage.blocked? end)
    assert Gentility.stats(controller).usage.spool_batches == 1
    assert Gentility.stats(controller).usage.aggregate_windows == 1
    assert Gentility.reserve_bytes(context, 1, policy) == {:error, :usage_spool_full}

    assert Gentility.record_usage(context, 1, :accepted, policy) ==
             {:error, :usage_spool_full}
  end

  @tag :tmp_dir
  test "spools an oversized usage window as several contract-sized batches", %{tmp_dir: tmp_dir} do
    parent = self()
    entries = UsageContract.max_entries() + 1

    exporter = fn id, wire ->
      send(parent, {:usage_export, id, wire})
      :ok
    end

    controller =
      start_controller(
        authority: fn _request -> {:error, :unavailable} end,
        usage: usage_options(tmp_dir, exporter)
      )

    policy = Gentility.policy(controller)

    for index <- 1..entries do
      assert Gentility.record_usage(usage_context("node_#{index}"), 10, :accepted, policy) == :ok
    end

    Manual.advance(100)

    assert_receive {:usage_export, first_id, first_wire}, 5_000
    assert_receive {:usage_export, second_id, second_wire}, 5_000
    assert first_id != second_id

    assert {:ok, first} = UsageContract.decode(first_wire, first_id)
    assert {:ok, second} = UsageContract.decode(second_wire, second_id)
    assert length(first.entries) == UsageContract.max_entries()
    assert length(second.entries) == 1
    assert first.window_start_ms == second.window_start_ms

    identities =
      (first.entries ++ second.entries) |> Enum.map(& &1.node_id) |> Enum.uniq() |> length()

    assert identities == entries

    eventually(fn -> Gentility.stats(controller).usage.spool_batches == 0 end)
    refute Gentility.stats(controller).usage.blocked?
    assert Gentility.stats(controller).usage.dropped_rows == 0
  end

  @tag :tmp_dir
  test "drops only the entry the contract cannot encode", %{tmp_dir: tmp_dir} do
    parent = self()

    exporter = fn id, wire ->
      send(parent, {:usage_export, id, wire})
      :ok
    end

    controller =
      start_controller(
        authority: fn _request -> {:error, :unavailable} end,
        usage: usage_options(tmp_dir, exporter)
      )

    policy = Gentility.policy(controller)
    assert Gentility.record_usage(usage_context("node_a"), 10, :accepted, policy) == :ok
    assert Gentility.record_usage(usage_context("node_b"), 20, :accepted, policy) == :ok
    assert Gentility.record_usage(usage_context(<<0xFF>>), 30, :accepted, policy) == :ok

    log =
      ExUnit.CaptureLog.capture_log(fn ->
        Manual.advance(100)
        eventually(fn -> Gentility.stats(controller).usage.dropped_rows == 1 end)
      end)

    assert log =~ "usage row dropped"
    refute Gentility.stats(controller).usage.blocked?

    exported = collect_usage_entries()
    assert Enum.map(exported, & &1.node_id) |> Enum.sort() == ["node_a", "node_b"]
    assert Enum.map(exported, & &1.accepted_bytes) |> Enum.sort() == [10, 20]

    eventually(fn -> Gentility.stats(controller).usage.spool_batches == 0 end)
    assert Gentility.stats(controller).usage.aggregate_entries == 0
    assert Gentility.stats(controller).usage.dropped_rows == 1
  end

  @tag :tmp_dir
  test "bisects a window too large for one batch instead of dropping it", %{tmp_dir: tmp_dir} do
    parent = self()
    entries = 10_000
    filler = String.duplicate("i", 506)
    deployment_id = String.duplicate("d", 512)

    exporter = fn id, wire ->
      send(parent, {:usage_export, id, wire})
      :ok
    end

    controller =
      start_controller(
        authority: fn _request -> {:error, :unavailable} end,
        usage: usage_options(tmp_dir, exporter, max_bytes: 64_000_000)
      )

    policy = Gentility.policy(controller)

    for index <- 1..entries do
      node_id = filler <> String.pad_leading(Integer.to_string(index), 6, "0")
      assert byte_size(node_id) == 512
      context = wide_usage_context(node_id, deployment_id)
      assert Gentility.record_usage(context, 10, :accepted, policy) == :ok
    end

    Manual.advance(100)
    eventually(fn -> Gentility.stats(controller).usage.aggregate_entries == 0 end, 400)

    batches = collect_usage_batches(400)
    assert length(batches) > 1
    assert Enum.all?(batches, &(&1.window_start_ms == 1_000))

    exported = Enum.flat_map(batches, & &1.entries)
    assert length(exported) == entries
    assert exported |> Enum.map(& &1.node_id) |> Enum.uniq() |> length() == entries

    stats = Gentility.stats(controller).usage
    assert stats.dropped_rows == 0
    refute stats.blocked?
  end

  @tag :tmp_dir
  test "a stalled usage worker cannot delay revocation or controller telemetry", %{
    tmp_dir: tmp_dir
  } do
    node_key = node_key(23)

    controller =
      start_controller(
        authority: fn _request -> {:ok, signed_lease(node_key)} end,
        close_peer: fn _key -> 0 end,
        usage: usage_options(tmp_dir, fn _id, _wire -> :ok end)
      )

    policy = Gentility.policy(controller)
    :ok = :sys.suspend(policy.usage.server)

    try do
      assert Gentility.revoke(controller, signed_revocation(node_key, 10)) == {:ok, :applied}
      assert Gentility.stats(controller).usage.enabled
    after
      :ok = :sys.resume(policy.usage.server)
    end
  end

  defp start_controller(options) do
    defaults = [
      verification_keys: %{@signing_key_id => @public_key},
      clock: Manual,
      max_lease_ms: 1_000,
      max_future_skew_ms: 0,
      expiry_jitter: fn _lifetime_ms -> 0 end
    ]

    # `expiry_jitter: nil` opts a test into the production jitter.
    {defaults, options} =
      case Keyword.fetch(options, :expiry_jitter) do
        {:ok, nil} ->
          {Keyword.delete(defaults, :expiry_jitter), Keyword.delete(options, :expiry_jitter)}

        _set_or_absent ->
          {defaults, options}
      end

    start_supervised!({Gentility, Keyword.merge(defaults, options)})
  end

  defp signed_lease(node_key, options \\ []) do
    lease = %Lease{
      key_id: @signing_key_id,
      node_key: node_key,
      node_id: "node_01",
      organization_id: "org_01",
      owner_kind: "deployment",
      deployment_id: "dep_01",
      region_id: 17,
      policy_revision: Keyword.get(options, :policy_revision, 9),
      quota_revision: Keyword.get(options, :quota_revision, 3),
      issued_at_ms: Keyword.get(options, :issued_at_ms, 1_000),
      expires_at_ms: Keyword.get(options, :expires_at_ms, 2_000),
      node_connection_limit: Keyword.get(options, :node_connection_limit, 4),
      organization_connection_limit: Keyword.get(options, :organization_connection_limit, 20),
      node_bytes_per_second: Keyword.get(options, :node_bytes_per_second, 10_000),
      node_byte_burst: Keyword.get(options, :node_byte_burst, 20_000),
      organization_bytes_per_second:
        Keyword.get(options, :organization_bytes_per_second, 100_000),
      organization_byte_burst: Keyword.get(options, :organization_byte_burst, 200_000)
    }

    {:ok, wire} = Contract.sign_lease(lease, @private_key)
    wire
  end

  defp expiring_lease(%Request{} = request),
    do: signed_lease(request.node_key, expires_at_ms: request.metadata.expires_at_ms)

  defp keeper_request(node_key, expires_at_ms) do
    request = request(node_key)
    %Request{request | metadata: %{expires_at_ms: expires_at_ms}}
  end

  defp perf_lease(node_key, now_ms) do
    lease = %Lease{
      key_id: @signing_key_id,
      node_key: node_key,
      node_id: "node_01",
      organization_id: "org_01",
      owner_kind: "deployment",
      deployment_id: "dep_01",
      region_id: 17,
      policy_revision: 9,
      quota_revision: 3,
      issued_at_ms: now_ms,
      expires_at_ms: now_ms + 900_000,
      node_connection_limit: 4,
      organization_connection_limit: 1_000_000,
      node_bytes_per_second: 10_000,
      node_byte_burst: 20_000,
      organization_bytes_per_second: 100_000,
      organization_byte_burst: 200_000
    }

    {:ok, wire} = Contract.sign_lease(lease, @private_key)
    wire
  end

  defp closed_keys(keys \\ []) do
    receive do
      {:closed, key} -> closed_keys([key | keys])
    after
      50 -> keys
    end
  end

  defp percentile(samples, percentile) do
    sorted = Enum.sort(samples)
    index = max(ceil(length(sorted) * percentile / 100) - 1, 0)
    Enum.at(sorted, index)
  end

  defp signed_revocation(node_key, revision) do
    revocation = %Revocation{
      key_id: @signing_key_id,
      node_key: node_key,
      policy_revision: revision,
      revoked_at_ms: 1_100,
      reason: "node-disabled"
    }

    {:ok, wire} = Contract.sign_revocation(revocation, @private_key)
    wire
  end

  defp request(node_key) do
    %Request{
      node_key: node_key,
      client_info: %ClientInfo{version: 2, app_name: "gentility"},
      source_ip: {127, 0, 0, 1},
      mesh_peer?: false,
      metadata: %{}
    }
  end

  defp node_key(byte), do: :binary.copy(<<byte>>, 32)

  defp usage_context(node_id), do: wide_usage_context(node_id, "dep_01")

  defp wide_usage_context(node_id, deployment_id) do
    %{
      gentility: %{
        node_key: node_key(0),
        node_id: node_id,
        organization_id: "org_01",
        owner_kind: "deployment",
        deployment_id: deployment_id
      }
    }
  end

  defp collect_usage_entries(timeout \\ 200) do
    timeout |> collect_usage_batches() |> Enum.flat_map(& &1.entries)
  end

  defp collect_usage_batches(timeout, batches \\ []) do
    receive do
      {:usage_export, id, wire} ->
        assert {:ok, batch} = UsageContract.decode(wire, id)
        collect_usage_batches(timeout, batches ++ [batch])
    after
      timeout -> batches
    end
  end

  defp usage_options(tmp_dir, exporter, extra \\ []) do
    Keyword.merge(
      [
        instance_id: "derpex-sin-1",
        region_id: 17,
        spool_path: Path.join(tmp_dir, "usage.spool"),
        exporter: exporter,
        window_ms: 100,
        retry_ms: 10,
        export_timeout_ms: 10_000,
        max_batches: 10,
        max_bytes: 1_000_000
      ],
      extra
    )
  end

  defp connections(count) do
    Enum.map(1..count, fn _index -> spawn(fn -> Process.sleep(:infinity) end) end)
  end

  defp eventually(assertion, attempts \\ 100)
  defp eventually(assertion, 0), do: assert(assertion.())

  defp eventually(assertion, attempts) do
    if assertion.() do
      :ok
    else
      Process.sleep(5)
      eventually(assertion, attempts - 1)
    end
  end
end
