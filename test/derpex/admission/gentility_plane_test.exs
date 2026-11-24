defmodule Derpex.Admission.GentilityPlaneTest do
  # Confinement, the observe switch, and the two lanes, through the controller.
  use ExUnit.Case, async: false

  alias Derpex.Admission.Gentility
  alias Derpex.Admission.Gentility.Confinement
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation
  alias Derpex.Admission.Gentility.Signer
  alias Derpex.Admission.Request
  alias Derpex.ClientInfo
  alias Derpex.Clock.Manual

  @private_key :binary.copy(<<0x10>>, 32)
  @public_key elem(:crypto.generate_key(:eddsa, :ed25519, @private_key), 0)
  @key_id "gentility-test"
  @host {203, 0, 113, 7}
  @elsewhere {198, 51, 100, 1}

  setup do
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    start_supervised!({Manual, system_time: 1_000})
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)
    :ok
  end

  describe "a confined source refuses any other kind, live and cached" do
    test "a machine lease, including a platform organization's, is refused from the host" do
      {:ok, answer} = Agent.start_link(fn -> :lease end)

      controller =
        start_controller(
          authority: fn request ->
            case Agent.get(answer, & &1) do
              :lease -> {:ok, lease(request.node_key, "machine")}
              :down -> {:error, :unavailable}
            end
          end,
          confinement: confined("computer@host1|platform")
        )

      policy = Gentility.policy(controller)
      key = node_key(1)

      assert Gentility.authorize(request(key, @host), policy) == {:error, :confined_source}

      # The lease was verified and cached; only this source is refused it.
      assert Gentility.stats(controller).cache_entries == 1

      assert {:ok, %{gentility: %{source: :live}}} =
               Gentility.authorize(request(key, @elsewhere), policy)

      Agent.update(answer, fn _answer -> :down end)

      assert Gentility.authorize(request(key, @host), policy) == {:error, :confined_source}

      assert {:ok, %{gentility: %{source: :cached}}} =
               Gentility.authorize(request(key, @elsewhere), policy)

      counts = Gentility.stats(controller).authorize_counts
      assert counts[{:denied, :confined_source, :unknown}] == 1
      assert counts[{:denied, :confined_source, :known}] == 1
    end
  end

  describe "confinement admits the listed kinds and nothing else changes" do
    test "listed kinds pass from the host; near-miss kinds do not; other sources see no rule" do
      {:ok, kinds} = Agent.start_link(fn -> %{} end)

      controller =
        start_controller(
          authority: fn request ->
            {:ok, lease(request.node_key, Agent.get(kinds, &Map.fetch!(&1, request.node_key)))}
          end,
          confinement: confined("computer@host1|platform")
        )

      policy = Gentility.policy(controller)

      for {byte, kind, from_host} <- [
            {10, "computer@host1", :admitted},
            {11, "platform", :admitted},
            {12, "computer@host", :refused},
            {13, "computer@host12", :refused},
            {14, "machine", :refused},
            {15, "user", :refused}
          ] do
        key = node_key(byte)
        Agent.update(kinds, &Map.put(&1, key, kind))

        case from_host do
          :admitted ->
            assert {:ok, %{gentility: %{owner_kind: ^kind}}} =
                     Gentility.authorize(request(key, @host), policy)

          :refused ->
            assert Gentility.authorize(request(key, @host), policy) == {:error, :confined_source},
                   "#{kind} was admitted from the confined host"
        end

        assert {:ok, %{gentility: %{owner_kind: ^kind}}} =
                 Gentility.authorize(request(key, @elsewhere), policy)
      end
    end

    test "with no rules, every kind is admitted from every source" do
      controller =
        start_controller(authority: fn request -> {:ok, lease(request.node_key, "machine")} end)

      assert {:ok, _context} =
               Gentility.authorize(request(node_key(16), @host), Gentility.policy(controller))
    end
  end

  describe "observe counts and keeps; enforce refuses and closes" do
    test "a denial: enforce refuses it, observe admits it observed and counts would_deny" do
      for enforce <- [true, false] do
        controller =
          start_controller(
            authority: fn _request -> {:error, {:http, 404}} end,
            enforce: enforce,
            id: {:denial, enforce}
          )

        policy = Gentility.policy(controller)
        key = node_key(20)
        connection = spawn_connection()

        if enforce do
          assert Gentility.authorize(request(key, @elsewhere), policy) ==
                   {:error, :no_cached_lease}

          assert Gentility.stats(controller).authorize_counts ==
                   %{{:denied, :no_cached_lease, :unknown} => 1}
        else
          assert {:ok, %{observed: :no_cached_lease} = context} =
                   Gentility.authorize(request(key, @elsewhere), policy)

          # The kept connection claims nothing, is not paced and records nothing.
          assert Gentility.claim(request(key, @elsewhere), context, connection, policy) ==
                   {:ok, context}

          assert Gentility.reserve_bytes(context, 1_000_000, policy) == {:ok, 0}
          assert Gentility.record_usage(context, 100, :accepted, policy) == :ok
          assert Gentility.stats(controller).active_connections == 0

          assert Gentility.stats(controller).authorize_counts ==
                   %{{:would_deny, :no_cached_lease, :unknown} => 1}
        end
      end
    end

    test "confinement: enforce refuses, observe keeps and counts would_deny confined_source" do
      for enforce <- [true, false] do
        controller =
          start_controller(
            authority: fn request -> {:ok, lease(request.node_key, "user")} end,
            confinement: confined("platform"),
            enforce: enforce,
            id: {:confined, enforce}
          )

        policy = Gentility.policy(controller)
        reply = Gentility.authorize(request(node_key(21), @host), policy)

        if enforce do
          assert reply == {:error, :confined_source}

          assert Gentility.stats(controller).authorize_counts[
                   {:denied, :confined_source, :unknown}
                 ] == 1
        else
          assert reply == {:ok, %{observed: :confined_source}}

          assert Gentility.stats(controller).authorize_counts[
                   {:would_deny, :confined_source, :unknown}
                 ] == 1
        end
      end
    end

    test "a revocation: enforce closes the connection, observe keeps it and counts would_close" do
      for enforce <- [true, false] do
        parent = self()
        key = node_key(22)

        controller =
          start_controller(
            authority: fn request -> {:ok, lease(request.node_key, "machine")} end,
            close_peer: fn closed -> send(parent, {:closed_peer, closed}) end,
            close_connection: fn connection, reason ->
              send(parent, {:closed_connection, connection, reason})
            end,
            enforce: enforce,
            id: {:revocation, enforce}
          )

        policy = Gentility.policy(controller)
        connection = spawn_connection()
        {:ok, context} = Gentility.authorize(request(key, @elsewhere), policy)

        assert {:ok, %{gentility: _lease}} =
                 Gentility.claim(request(key, @elsewhere), context, connection, policy)

        assert Gentility.revoke(controller, revocation(key, 10)) == {:ok, :applied}
        stats = Gentility.stats(controller)

        # The decision is the same either way: the lease is gone.
        assert stats.cache_entries == 0

        if enforce do
          assert_receive {:closed_peer, ^key}
          assert_receive {:closed_connection, ^connection, :revocation}
          assert stats.close_peer_counts == %{revocation: 1}
          assert stats.would_close_counts == %{}
        else
          refute_receive {:closed_peer, _key}
          refute_receive {:closed_connection, _connection, _reason}
          assert stats.close_peer_counts == %{}
          assert stats.would_close_counts == %{revocation: 1}
          assert stats.active_connections == 1

          # A lease the revocation covers is refused on the node's next
          # connection: a would_deny, and that connection is kept too.
          assert Gentility.authorize(request(key, @elsewhere), policy) ==
                   {:ok, %{observed: :lease_revoked}}
        end
      end
    end

    test "an expiry: observe keeps the connection and counts would_close" do
      parent = self()
      key = node_key(23)

      controller =
        start_controller(
          authority: fn request -> {:ok, lease(request.node_key, "machine", 2_000)} end,
          close_peer: fn closed -> send(parent, {:closed_peer, closed}) end,
          close_connection: fn connection, reason ->
            send(parent, {:closed_connection, connection, reason})
          end,
          renewal_retry_ms: 60_000,
          enforce: false
        )

      policy = Gentility.policy(controller)
      connection = spawn_connection()
      {:ok, context} = Gentility.authorize(request(key, @elsewhere), policy)
      {:ok, _claimed} = Gentility.claim(request(key, @elsewhere), context, connection, policy)

      Manual.advance(1_000)
      eventually(fn -> Gentility.stats(controller).would_close_counts == %{expiry: 1} end)
      refute_receive {:closed_peer, _key}
      refute_receive {:closed_connection, _connection, _reason}
    end

    test "a connection limit: enforce refuses the claim, observe keeps it" do
      for enforce <- [true, false] do
        key = node_key(24)

        controller =
          start_controller(
            authority: fn request ->
              {:ok, lease(request.node_key, "machine", 100_000, node_connection_limit: 1)}
            end,
            enforce: enforce,
            id: {:limit, enforce}
          )

        policy = Gentility.policy(controller)
        {:ok, context} = Gentility.authorize(request(key, @elsewhere), policy)

        {:ok, _first} =
          Gentility.claim(request(key, @elsewhere), context, spawn_connection(), policy)

        second = Gentility.claim(request(key, @elsewhere), context, spawn_connection(), policy)
        counts = Gentility.stats(controller).authorize_counts

        if enforce do
          assert second == {:error, :node_connection_limit}
          assert counts[{:denied, :connection_limit, :known}] == 1
        else
          assert second == {:ok, %{observed: :connection_limit}}
          assert counts[{:would_deny, :connection_limit, :known}] == 1
        end
      end
    end

    test "a byte budget: enforce closes a node past its own debt, observe paces it at the cap" do
      for enforce <- [true, false] do
        controller =
          start_controller(
            authority: fn request ->
              {:ok,
               lease(request.node_key, "machine", 100_000,
                 node_bytes_per_second: 100,
                 node_byte_burst: 100,
                 organization_bytes_per_second: 100,
                 organization_byte_burst: 100
               )}
            end,
            max_byte_delay_ms: 100,
            enforce: enforce,
            id: {:bytes, enforce}
          )

        policy = Gentility.policy(controller)
        {:ok, context} = Gentility.authorize(request(node_key(25), @elsewhere), policy)
        assert Gentility.reserve_bytes(context, 100, policy) == {:ok, 0}

        if enforce do
          assert Gentility.reserve_bytes(context, 50, policy) == {:error, :byte_budget_exhausted}
        else
          assert Gentility.reserve_bytes(context, 50, policy) == {:ok, 100_000}
        end
      end
    end

    # Observe must never refuse, overload included.
    test "an overloaded lane: enforce refuses, observe admits without asking and counts it" do
      for enforce <- [true, false] do
        parent = self()

        authority = fn request ->
          send(parent, {:authority_started, self(), request.node_key})
          receive do: (:release -> {:ok, lease(request.node_key, "machine")})
        end

        controller =
          start_controller(
            authority: authority,
            unknown_lane: [max_concurrent_requests: 1, rate: {20, 40}, per_source_rate: {2, 10}],
            enforce: enforce,
            id: {:overload, enforce}
          )

        policy = Gentility.policy(controller)
        first = Task.async(fn -> Gentility.authorize(request(node_key(26), @host), policy) end)
        assert_receive {:authority_started, authority_process, _first_key}

        second = Gentility.authorize(request(node_key(27), @elsewhere), policy)
        refute_received {:authority_started, _process, _second_key}

        send(authority_process, :release)
        assert {:ok, %{gentility: %{source: :live}}} = Task.await(first)
        counts = Gentility.stats(controller).authorize_counts

        if enforce do
          assert second == {:error, :admission_overloaded}
          assert counts[{:denied, :overloaded, :unknown}] == 1
          assert counts[{:would_deny, :overloaded, :unknown}] == nil
        else
          assert second == {:ok, %{observed: :overloaded}}
          assert counts[{:would_deny, :overloaded, :unknown}] == 1
          assert counts[{:denied, :overloaded, :unknown}] == nil
        end
      end
    end
  end

  describe "made-up keys fill only the unknown lane" do
    test "a flood from many sources is shed and counted by lane; a known node still connects" do
      known = node_key(30)

      controller =
        start_controller(
          authority: fn
            %Request{node_key: ^known} -> {:ok, lease(known, "machine")}
            _made_up -> {:error, {:http, 404}}
          end,
          unknown_lane: lane(rate: {20, 40}, per_source_rate: {2, 10})
        )

      policy = Gentility.policy(controller)

      # The known node connected once before the flood, through the unknown lane.
      assert {:ok, _context} = Gentility.authorize(request(known, @elsewhere), policy)

      replies =
        for index <- 1..100 do
          Gentility.authorize(request(made_up_key(index), source(index)), policy)
        end

      # The global burst had 39 tokens left; every other call was shed unasked.
      assert Enum.count(replies, &(&1 == {:error, :no_cached_lease})) == 39
      assert Enum.count(replies, &(&1 == {:error, :admission_overloaded})) == 61

      assert {:ok, %{gentility: %{source: :live}}} =
               Gentility.authorize(request(known, @elsewhere), policy)

      counts = Gentility.stats(controller).authorize_counts
      assert counts[{:live, :ok, :unknown}] == 1
      assert counts[{:live, :ok, :known}] == 1
      assert counts[{:denied, :no_cached_lease, :unknown}] == 39
      assert counts[{:denied, :overloaded, :unknown}] == 61
      assert counts[{:denied, :overloaded, :known}] == nil
    end

    test "one source gets its own burst, then waits; other sources are not held back by it" do
      controller =
        start_controller(
          authority: fn _request -> {:error, {:http, 404}} end,
          unknown_lane: lane(rate: {20, 40}, per_source_rate: {2, 10})
        )

      policy = Gentility.policy(controller)

      replies =
        for index <- 1..12, do: Gentility.authorize(request(made_up_key(index), @host), policy)

      assert Enum.count(replies, &(&1 == {:error, :no_cached_lease})) == 10
      assert Enum.count(replies, &(&1 == {:error, :admission_overloaded})) == 2

      assert Gentility.authorize(request(made_up_key(13), @elsewhere), policy) ==
               {:error, :no_cached_lease}
    end

    test "the unknown lane's calls in flight are bounded apart from the known lane's" do
      parent = self()
      known = node_key(31)

      controller =
        start_controller(
          authority: fn
            %Request{node_key: ^known} ->
              {:ok, lease(known, "machine")}

            request ->
              send(parent, {:authority_started, self(), request.node_key})
              receive do: (:release -> {:error, {:http, 404}})
          end,
          max_concurrent_requests: 1,
          unknown_lane: lane(max_concurrent_requests: 2)
        )

      policy = Gentility.policy(controller)
      assert {:ok, _context} = Gentility.authorize(request(known, @elsewhere), policy)

      stuck =
        for index <- 1..2 do
          Task.async(fn ->
            Gentility.authorize(request(made_up_key(index), source(index)), policy)
          end)
        end

      processes =
        for _index <- 1..2 do
          assert_receive {:authority_started, process, _key}
          process
        end

      assert Gentility.authorize(request(made_up_key(3), source(3)), policy) ==
               {:error, :admission_overloaded}

      assert Gentility.stats(controller).active_unknown_requests == 2

      assert {:ok, %{gentility: %{source: :live}}} =
               Gentility.authorize(request(known, @elsewhere), policy)

      Enum.each(processes, &send(&1, :release))
      Enum.each(stuck, &assert(Task.await(&1) == {:error, :no_cached_lease}))
    end

    test "renewals go on while the unknown lane is shut" do
      parent = self()
      known = node_key(32)

      controller =
        start_controller(
          authority: fn
            %Request{node_key: ^known, metadata: %{renewal: true}} ->
              send(parent, :renewed)
              {:ok, lease(known, "machine", 19_000, issued_at_ms: 9_000)}

            %Request{node_key: ^known} ->
              {:ok, lease(known, "machine", 11_000)}

            _made_up ->
              {:error, {:http, 404}}
          end,
          unknown_lane: lane(rate: {0.001, 5}, per_source_rate: {2, 10})
        )

      policy = Gentility.policy(controller)
      {:ok, context} = Gentility.authorize(request(known, @elsewhere), policy)

      {:ok, _claimed} =
        Gentility.claim(request(known, @elsewhere), context, spawn_connection(), policy)

      for index <- 1..10,
          do: Gentility.authorize(request(made_up_key(index), source(index)), policy)

      assert Gentility.authorize(request(made_up_key(11), source(11)), policy) ==
               {:error, :admission_overloaded}

      Manual.advance(8_000)
      assert_receive :renewed
      eventually(fn -> Gentility.stats(controller).nearest_lease_expiry_seconds == 10 end)

      Manual.advance(3_000)
      assert Gentility.stats(controller).cache_entries == 1

      assert Gentility.authorize(request(made_up_key(12), source(12)), policy) ==
               {:error, :admission_overloaded}
    end

    # A relay back with an empty cache sees every node as unknown, and admits them at the unknown lane's rate.
    test "a cold relay admits the fleet at the lane's rate, then every node is known" do
      {:ok, answered} = Agent.start_link(fn -> 0 end)

      controller =
        start_controller(
          authority: fn request ->
            Agent.update(answered, &(&1 + 1))
            {:ok, lease(request.node_key, "machine")}
          end,
          unknown_lane: lane(rate: {20, 40}, per_source_rate: {2, 10})
        )

      policy = Gentility.policy(controller)
      nodes = for index <- 1..60, do: {node_key_for(index), source(index)}

      first =
        Enum.map(nodes, fn {key, from} -> Gentility.authorize(request(key, from), policy) end)

      assert Enum.count(first, &match?({:ok, %{gentility: %{source: :live}}}, &1)) == 40
      assert Enum.count(first, &(&1 == {:error, :admission_overloaded})) == 20

      # One second later the lane has twenty more tokens: the rest are in.
      Manual.advance(1_000)

      retried =
        for {{key, from}, {:error, :admission_overloaded}} <- Enum.zip(nodes, first) do
          Gentility.authorize(request(key, from), policy)
        end

      assert length(retried) == 20
      assert Enum.all?(retried, &match?({:ok, %{gentility: %{source: :live}}}, &1))

      # Shut the unknown lane; every node now holds a lease and is known.
      for index <- 1..40,
          do: Gentility.authorize(request(made_up_key(index), source(100 + index)), policy)

      reconnects =
        Enum.map(nodes, fn {key, from} -> Gentility.authorize(request(key, from), policy) end)

      assert Enum.all?(reconnects, &match?({:ok, %{gentility: %{source: :live}}}, &1))

      counts = Gentility.stats(controller).authorize_counts
      assert counts[{:live, :ok, :unknown}] == 60
      assert counts[{:denied, :overloaded, :unknown}] == 20 + 40
      assert counts[{:live, :ok, :known}] == 60
      # In a cold start the lane's answers are mostly live: Gentility knows them.
      assert counts[{:denied, :no_cached_lease, :unknown}] == nil
    end

    test "a cold relay admits ten computers behind one address at once, the rest at 2/s" do
      controller =
        start_controller(
          authority: fn request -> {:ok, lease(request.node_key, "computer@host1")} end,
          unknown_lane: lane(rate: {20, 40}, per_source_rate: {2, 10})
        )

      policy = Gentility.policy(controller)
      keys = for index <- 1..15, do: node_key_for(index)

      first = Enum.map(keys, &Gentility.authorize(request(&1, @host), policy))
      assert Enum.count(first, &match?({:ok, _context}, &1)) == 10

      Manual.advance(2_500)

      retried =
        for {key, {:error, :admission_overloaded}} <- Enum.zip(keys, first),
            do: Gentility.authorize(request(key, @host), policy)

      assert length(retried) == 5
      assert Enum.all?(retried, &match?({:ok, _context}, &1))
    end
  end

  test "the lane's rate setting reads rate/burst" do
    alias Derpex.Admission.Gentility.UnknownLane

    assert UnknownLane.parse_rate("20/40") == {:ok, {20.0, 40}}
    assert UnknownLane.parse_rate("0.5/3") == {:ok, {0.5, 3}}

    for text <- ["20", "20/", "/40", "0/40", "-1/40", "20/0", "20/4.5", "a/b", "20/40/1"] do
      assert UnknownLane.parse_rate(text) == {:error, :invalid_rate}, "#{text} was accepted"
    end
  end

  defp start_controller(options) do
    {id, options} = Keyword.pop(options, :id, Gentility)

    defaults = [
      verification_keys: %{@key_id => @public_key},
      clock: Manual,
      max_lease_ms: 900_000,
      max_future_skew_ms: 0,
      expiry_jitter: fn _lifetime_ms -> 0 end
    ]

    start_supervised!(
      Supervisor.child_spec({Gentility, Keyword.merge(defaults, options)}, id: id)
    )
  end

  defp lane(options) do
    Keyword.merge(
      [max_concurrent_requests: 16, rate: {20, 40}, per_source_rate: {2, 10}],
      options
    )
  end

  defp confined(kinds) do
    {:ok, rules} = Confinement.parse("203.0.113.7/32=" <> kinds)
    rules
  end

  defp lease(node_key, owner_kind, expires_at_ms \\ 100_000, options \\ []) do
    lease = %Lease{
      key_id: @key_id,
      node_key: node_key,
      node_id: "node_01",
      organization_id: "org_01",
      owner_kind: owner_kind,
      deployment_id: "staging",
      region_id: 900,
      policy_revision: 9,
      quota_revision: 1,
      issued_at_ms: Keyword.get(options, :issued_at_ms, 1_000),
      expires_at_ms: expires_at_ms,
      node_connection_limit: Keyword.get(options, :node_connection_limit, 8),
      organization_connection_limit: 1_024,
      node_bytes_per_second: Keyword.get(options, :node_bytes_per_second, 0),
      node_byte_burst: Keyword.get(options, :node_byte_burst, 0),
      organization_bytes_per_second: Keyword.get(options, :organization_bytes_per_second, 0),
      organization_byte_burst: Keyword.get(options, :organization_byte_burst, 0)
    }

    {:ok, wire} = Signer.sign_lease(lease, @private_key)
    wire
  end

  defp revocation(node_key, revision) do
    revocation = %Revocation{
      key_id: @key_id,
      node_key: node_key,
      policy_revision: revision,
      revoked_at_ms: 1_100,
      reason: "node_revoked"
    }

    {:ok, wire} = Signer.sign_revocation(revocation, @private_key)
    wire
  end

  defp request(node_key, source) do
    %Request{
      node_key: node_key,
      client_info: %ClientInfo{version: 2, app_name: "gentility"},
      source_ip: source,
      mesh_peer?: false,
      metadata: %{}
    }
  end

  defp node_key(byte), do: :binary.copy(<<byte>>, 32)
  defp node_key_for(index), do: <<1, index::248>>
  defp made_up_key(index), do: <<2, index::248>>
  defp source(index), do: {192, 0, div(index, 256), rem(index, 256)}

  defp spawn_connection, do: spawn(fn -> Process.sleep(:infinity) end)

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
