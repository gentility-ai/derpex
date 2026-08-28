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
             ip_tracking_limited: 0,
             max_tracked_ips: 2,
             tracked_ips: 2
           }
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
    assert_receive {:claim_result, ^overflow, {:error, :ip_tracking_limited}}
    send(overflow, :stop)

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
