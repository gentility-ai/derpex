defmodule Derpex.AcceptLimiterTest do
  use ExUnit.Case, async: false

  alias Derpex.AcceptLimiter
  alias Derpex.Clock.Manual

  setup do
    start_supervised!({Manual, monotonic_time: 0})
    previous = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    on_exit(fn -> Application.put_env(:derpex, :clock, previous) end)
  end

  test "shares a bounded burst and refills at the configured accept rate" do
    limiter = start_supervised!({AcceptLimiter, name: nil, config: {1, 2}})

    assert AcceptLimiter.allow?(limiter)
    assert AcceptLimiter.allow?(limiter)
    refute AcceptLimiter.allow?(limiter)
    :ok = Manual.advance(999)
    refute AcceptLimiter.allow?(limiter)
    :ok = Manual.advance(1)
    assert AcceptLimiter.allow?(limiter)
  end

  test "can be disabled or configured as a finite non-refilling burst" do
    limiter = start_supervised!({AcceptLimiter, name: nil, config: {0, 1}})

    assert AcceptLimiter.allow?(limiter)
    refute AcceptLimiter.allow?(limiter)
    :ok = Manual.advance(60_000)
    refute AcceptLimiter.allow?(limiter)
    assert AcceptLimiter.update(limiter, nil) == :ok
    assert AcceptLimiter.allow?(limiter)
  end

  test "applies independent bounded token buckets per source IP" do
    limiter =
      start_supervised!({AcceptLimiter, name: nil, config: [per_ip: {1, 1}, max_tracked_ips: 2]})

    assert AcceptLimiter.claim(limiter, {192, 0, 2, 1}) == :ok
    assert AcceptLimiter.claim(limiter, {192, 0, 2, 1}) == {:error, :ip_rate_limited}
    assert AcceptLimiter.claim(limiter, {192, 0, 2, 2}) == :ok

    :ok = Manual.advance(1_000)
    assert AcceptLimiter.claim(limiter, {192, 0, 2, 1}) == :ok

    assert AcceptLimiter.stats(limiter) == %{
             accept_rate_limited: 0,
             active_connections: 0,
             allowed: 3,
             ip_connection_limited: 0,
             ip_rate_limited: 1,
             ip_untracked: 0,
             max_tracked_ips: 2,
             overflow_limited: 0,
             tracked_ips: 2
           }
  end

  test "admits a new source untracked once every tracked IP holds a connection" do
    limiter =
      start_supervised!(
        {AcceptLimiter, name: nil, config: [per_ip_connections: 1, max_tracked_ips: 2]}
      )

    first = start_claimant(limiter, {203, 0, 113, 1})
    assert_receive {:claim_result, ^first, :ok}

    second = start_claimant(limiter, {203, 0, 113, 2})
    assert_receive {:claim_result, ^second, :ok}

    third = start_claimant(limiter, {203, 0, 113, 3})
    assert_receive {:claim_result, ^third, :ok}

    stats = AcceptLimiter.stats(limiter)
    assert stats.allowed == 3
    assert stats.ip_untracked == 1
    assert stats.overflow_limited == 0
    assert stats.tracked_ips == 2

    Enum.each([first, second, third], &send(&1, :release))
  end

  test "denies untracked sources once the shared overflow bucket is empty" do
    limiter =
      start_supervised!(
        {AcceptLimiter,
         name: nil, config: [per_ip: {0, 1}, per_ip_connections: 1, max_tracked_ips: 1]}
      )

    tracked = start_claimant(limiter, {203, 0, 113, 10})
    assert_receive {:claim_result, ^tracked, :ok}

    first_untracked = start_claimant(limiter, {203, 0, 113, 11})
    assert_receive {:claim_result, ^first_untracked, :ok}

    second_untracked = start_claimant(limiter, {203, 0, 113, 12})
    assert_receive {:claim_result, ^second_untracked, {:error, :overflow_limited}}

    stats = AcceptLimiter.stats(limiter)
    assert stats.allowed == 2
    assert stats.ip_untracked == 1
    assert stats.overflow_limited == 1

    Enum.each([tracked, first_untracked, second_untracked], &send(&1, :stop))
  end

  test "denies untracked sources once the shared overflow connection cap is reached" do
    limiter =
      start_supervised!(
        {AcceptLimiter,
         name: nil,
         config: [per_ip_connections: 1, max_tracked_ips: 1, max_untracked_connections: 1]}
      )

    tracked = start_claimant(limiter, {198, 51, 100, 10})
    assert_receive {:claim_result, ^tracked, :ok}

    untracked = start_claimant(limiter, {198, 51, 100, 11})
    assert_receive {:claim_result, ^untracked, :ok}

    rejected = start_claimant(limiter, {198, 51, 100, 12})
    assert_receive {:claim_result, ^rejected, {:error, :overflow_limited}}

    stats = AcceptLimiter.stats(limiter)
    assert stats.ip_untracked == 1
    assert stats.overflow_limited == 1
    assert stats.active_connections == 2

    # Releasing the shared untracked slot readmits the next untracked source.
    send(untracked, :release)
    eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 1 end)

    readmitted = start_claimant(limiter, {198, 51, 100, 13})
    assert_receive {:claim_result, ^readmitted, :ok}

    Enum.each([tracked, readmitted], &send(&1, :release))
  end

  test "defaults the untracked connection cap to sixteen times the per-IP maximum" do
    limiter =
      start_supervised!(
        {AcceptLimiter, name: nil, config: [per_ip_connections: 2, max_tracked_ips: 1]}
      )

    tracked = start_claimant(limiter, {192, 0, 2, 20})
    assert_receive {:claim_result, ^tracked, :ok}

    admitted =
      Enum.map(1..32, fn index ->
        claimant = start_claimant(limiter, {192, 0, 2, 100 + index})
        assert_receive {:claim_result, ^claimant, :ok}
        claimant
      end)

    rejected = start_claimant(limiter, {192, 0, 2, 200})
    assert_receive {:claim_result, ^rejected, {:error, :overflow_limited}}

    assert AcceptLimiter.stats(limiter).ip_untracked == 32

    Enum.each([tracked | admitted], &send(&1, :stop))
  end

  test "caps concurrent connections and repairs slots after abrupt exits" do
    limiter =
      start_supervised!(
        {AcceptLimiter, name: nil, config: [per_ip_connections: 1, max_tracked_ips: 2]}
      )

    first = start_claimant(limiter, {192, 0, 2, 10})
    assert_receive {:claim_result, ^first, :ok}

    second = start_claimant(limiter, {192, 0, 2, 10})
    assert_receive {:claim_result, ^second, {:error, :ip_connection_limited}}
    send(second, :stop)

    third = start_claimant(limiter, {192, 0, 2, 11})
    assert_receive {:claim_result, ^third, :ok}
    assert AcceptLimiter.stats(limiter).active_connections == 2

    overflow = start_claimant(limiter, {192, 0, 2, 12})
    assert_receive {:claim_result, ^overflow, :ok}
    assert AcceptLimiter.stats(limiter).ip_untracked == 1
    assert AcceptLimiter.stats(limiter).active_connections == 3
    send(overflow, :stop)
    eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 2 end)

    Process.exit(first, :kill)
    eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 1 end)

    replacement = start_claimant(limiter, {192, 0, 2, 10})
    assert_receive {:claim_result, ^replacement, :ok}

    Enum.each([third, replacement], &send(&1, :release))
    eventually(fn -> AcceptLimiter.stats(limiter).active_connections == 0 end)
  end

  test "evicts only inactive least-recently-used IP state at its hard bound" do
    limiter =
      start_supervised!({AcceptLimiter, name: nil, config: [per_ip: {0, 1}, max_tracked_ips: 2]})

    assert AcceptLimiter.claim(limiter, {198, 51, 100, 1}) == :ok
    assert AcceptLimiter.claim(limiter, {198, 51, 100, 2}) == :ok
    assert AcceptLimiter.claim(limiter, {198, 51, 100, 3}) == :ok
    assert AcceptLimiter.stats(limiter).tracked_ips == 2

    # The first source was evicted, so it receives a fresh bounded bucket.
    assert AcceptLimiter.claim(limiter, {198, 51, 100, 1}) == :ok
    assert AcceptLimiter.stats(limiter).tracked_ips == 2
  end

  test "aggregates IPv6 sources by their routed /64 prefix" do
    limiter =
      start_supervised!({AcceptLimiter, name: nil, config: [per_ip: {0, 1}, max_tracked_ips: 8]})

    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 1, 0, 0, 0, 1}) == :ok

    # A second address inside the same /64 shares the first address's bucket.
    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 1, 0xAAAA, 0, 0, 2}) ==
             {:error, :ip_rate_limited}

    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 1, 0xFFFF, 0xFFFF, 0xFFFF, 0xFFFF}) ==
             {:error, :ip_rate_limited}

    # A neighbouring /64 is a separate source.
    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 2, 0, 0, 0, 1}) == :ok

    assert AcceptLimiter.stats(limiter).tracked_ips == 2
  end

  test "shares one connection slot across a single IPv6 /64" do
    limiter =
      start_supervised!(
        {AcceptLimiter, name: nil, config: [per_ip_connections: 1, max_tracked_ips: 8]}
      )

    first = start_claimant(limiter, {0x2001, 0xDB8, 0, 1, 0, 0, 0, 1})
    assert_receive {:claim_result, ^first, :ok}

    sibling = start_claimant(limiter, {0x2001, 0xDB8, 0, 1, 0, 0, 0, 2})
    assert_receive {:claim_result, ^sibling, {:error, :ip_connection_limited}}

    neighbour = start_claimant(limiter, {0x2001, 0xDB8, 0, 2, 0, 0, 0, 1})
    assert_receive {:claim_result, ^neighbour, :ok}

    Enum.each([first, sibling, neighbour], &send(&1, :release))
  end

  test "honours a configured IPv6 aggregation prefix length" do
    limiter =
      start_supervised!(
        {AcceptLimiter, name: nil, config: [per_ip: {0, 1}, max_tracked_ips: 8, ipv6_prefix: 128]}
      )

    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 1, 0, 0, 0, 1}) == :ok
    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 1, 0, 0, 0, 2}) == :ok

    assert AcceptLimiter.claim(limiter, {0x2001, 0xDB8, 0, 1, 0, 0, 0, 1}) ==
             {:error, :ip_rate_limited}

    assert AcceptLimiter.stats(limiter).tracked_ips == 2
  end

  test "unmaps IPv4-mapped IPv6 sources before aggregating" do
    limiter =
      start_supervised!({AcceptLimiter, name: nil, config: [per_ip: {0, 1}, max_tracked_ips: 8]})

    assert AcceptLimiter.claim(limiter, {192, 0, 2, 1}) == :ok

    # ::ffff:192.0.2.1 is the same source as 192.0.2.1.
    assert AcceptLimiter.claim(limiter, {0, 0, 0, 0, 0, 0xFFFF, 0xC000, 0x0201}) ==
             {:error, :ip_rate_limited}

    # Mapped addresses must not collapse into one all-zero /64 with each other.
    assert AcceptLimiter.claim(limiter, {0, 0, 0, 0, 0, 0xFFFF, 0xC633, 0x6401}) == :ok
    assert AcceptLimiter.claim(limiter, {198, 51, 100, 1}) == {:error, :ip_rate_limited}

    assert AcceptLimiter.stats(limiter).tracked_ips == 2
  end

  test "rejects an out-of-range IPv6 aggregation prefix" do
    Process.flag(:trap_exit, true)

    for prefix <- [0, 129, 64.0] do
      assert {:error, {%ArgumentError{}, _stacktrace}} =
               AcceptLimiter.start_link(name: nil, config: [per_ip: {1, 1}, ipv6_prefix: prefix])
    end
  end

  defp start_claimant(limiter, source_ip) do
    parent = self()

    spawn(fn ->
      result = AcceptLimiter.claim(limiter, source_ip)
      send(parent, {:claim_result, self(), result})

      receive do
        :release -> AcceptLimiter.release(limiter)
        :stop -> :ok
      end
    end)
  end

  defp eventually(fun, attempts \\ 100)

  defp eventually(fun, 0), do: assert(fun.())

  defp eventually(fun, attempts) do
    if fun.() do
      :ok
    else
      Process.sleep(5)
      eventually(fun, attempts - 1)
    end
  end
end
