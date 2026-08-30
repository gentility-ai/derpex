defmodule Derpex.BootstrapDNSTest do
  use ExUnit.Case, async: true

  alias Derpex.BootstrapDNS
  alias Derpex.HTTP1
  alias Derpex.HTTP1.Request

  setup do
    server = start_supervised!({BootstrapDNS, name: nil})
    %{server: server}
  end

  test "serves only the selected unpublished name through the HTTP endpoint", %{server: server} do
    :ok =
      BootstrapDNS.replace(
        server,
        %{"published.example" => ["1.2.3.4"]},
        %{"hidden.example" => ["5.6.7.8"]},
        %{"hidden.example" => 1.0}
      )

    request = %Request{
      method: "GET",
      target: "/bootstrap-dns?q=hidden.example",
      version: "HTTP/1.1",
      headers: [{"host", "derp.example"}]
    }

    assert {:response, response} =
             HTTP1.route(request, :crypto.strong_rand_bytes(32),
               bootstrap_dns: server,
               remote_address: "10.0.0.1:1234"
             )

    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 200 OK"
    assert response =~ "Content-Type: application/json"
    assert response =~ "Connection: close"
    assert response =~ ~s("hidden.example":["5.6.7.8"])
    refute response =~ "published.example"
  end

  test "answers unpublished names without leaking them", %{server: server} do
    published = %{"login.tailscale.com" => ["1.2.3.4"]}
    unpublished = %{"log.tailscale.com" => ["5.6.7.8"]}
    :ok = BootstrapDNS.replace(server, published, unpublished, %{"log.tailscale.com" => 1.0})

    assert BootstrapDNS.lookup(server, "login.tailscale.com", "10.0.0.1:1234") == published

    assert BootstrapDNS.lookup(server, "log.tailscale.com", "10.0.0.1:1234") ==
             unpublished

    refute Map.has_key?(
             BootstrapDNS.lookup(server, "random.example.com", "10.0.0.1:1234"),
             "log.tailscale.com"
           )
  end

  test "treats empty unpublished address lists as misses", %{server: server} do
    published = %{"tailscale.com" => ["10.10.10.10"]}

    :ok =
      BootstrapDNS.replace(
        server,
        published,
        %{"log.tailscale.com" => [], "controlplane.tailscale.com" => ["1.2.3.4"]},
        %{"log.tailscale.com" => 1.0, "controlplane.tailscale.com" => 1.0}
      )

    for query <- ["log.tailscale.com", "login.tailscale.com"] do
      :ok = BootstrapDNS.reset_metrics(server)
      assert BootstrapDNS.lookup(server, query, "10.0.0.1:1234") == published
      assert %{unpublished_hits: 0, unpublished_misses: 1} = BootstrapDNS.metrics(server)
    end

    :ok = BootstrapDNS.reset_metrics(server)

    assert BootstrapDNS.lookup(server, "controlplane.tailscale.com", "10.0.0.1:1234") ==
             %{"controlplane.tailscale.com" => ["1.2.3.4"]}

    assert %{unpublished_hits: 1, unpublished_misses: 0} = BootstrapDNS.metrics(server)
  end

  test "counts distinct queried domains with the upstream defensive cap", %{server: server} do
    :ok = BootstrapDNS.replace(server, %{}, %{}, %{})

    Enum.each(~w[a.io b.io c.io d.io e.io e.io e.io a.io], fn query ->
      BootstrapDNS.lookup(server, query, "10.0.0.1:1234")
    end)

    assert BootstrapDNS.metrics(server).queried_domains == 5

    Enum.each(1..496, fn index ->
      BootstrapDNS.lookup(server, "#{index}.example", "10.0.0.1:1234")
    end)

    assert BootstrapDNS.metrics(server).queried_domains == 0
  end

  test "caps each retained query name so 500 entries cannot hold arbitrary bytes", %{
    server: server
  } do
    long = String.duplicate("a", 300)

    :ok =
      BootstrapDNS.replace(
        server,
        %{},
        %{(long <> ".one") => ["5.6.7.8"]},
        %{(long <> ".one") => 1.0}
      )

    assert BootstrapDNS.lookup(server, long <> ".one", "10.0.0.1:1234") ==
             %{(long <> ".one") => ["5.6.7.8"]}

    assert BootstrapDNS.lookup(server, long <> ".two", "10.0.0.1:1234") == %{}

    # Both names share their first 256 bytes, so only that prefix is retained.
    assert BootstrapDNS.metrics(server).queried_domains == 1

    # A name that already fits the cap is retained whole, so names differing
    # inside the first 256 bytes stay distinct.
    assert BootstrapDNS.lookup(server, String.duplicate("a", 255) <> "b", "10.0.0.1:1234") == %{}
    assert BootstrapDNS.lookup(server, String.duplicate("a", 255) <> "c", "10.0.0.1:1234") == %{}

    assert BootstrapDNS.metrics(server).queried_domains == 3
  end

  test "matches Go's deterministic PCG rollout selection" do
    cases = [
      {"10.0.0.1:1234", 0.0, false},
      {"10.0.0.1:1234", 1.0, true},
      {"", 1.0, true},
      {"", 0.0, false},
      {"", 0.5, false},
      {"1.2.3.4:567", 0.5, true},
      {"1.2.3.5:567", 0.5, true},
      {"1.2.3.6:567", 0.5, false},
      {"1.2.3.7:567", 0.5, true},
      {"1.2.3.8:567", 0.5, false},
      {"1.2.3.9:567", 0.5, true},
      {"1.2.3.10:567", 0.5, true}
    ]

    Enum.each(cases, fn {remote_address, percentage, expected} ->
      assert BootstrapDNS.remote_address_matches_percent(remote_address, percentage) == expected
    end)

    matches =
      Enum.reduce(0..255, 0, fn a, count ->
        Enum.reduce(0..255, count, fn b, count ->
          if BootstrapDNS.remote_address_matches_percent("1.2.#{a}.#{b}:12345", 0.5),
            do: count + 1,
            else: count
        end)
      end)

    ratio = matches / 65_536
    assert ratio >= 0.495 and ratio <= 0.505
  end
end
