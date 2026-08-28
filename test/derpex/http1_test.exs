# Adapted from Tailscale's DERP HTTP handler tests.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.HTTP1Test do
  use ExUnit.Case, async: true

  alias Derpex.HTTP1
  alias Derpex.HTTP1.Request

  @server_public :binary.copy(<<0xAB>>, 32)

  test "returns successful CORS probes on both upstream paths" do
    for path <- ["/derp/probe", "/derp/latency-check"] do
      assert {:response, response} = HTTP1.route(request("GET", path), @server_public)
      assert IO.iodata_to_binary(response) =~ "HTTP/1.1 200 OK\r\n"
      assert IO.iodata_to_binary(response) =~ "Access-Control-Allow-Origin: *\r\n"
    end
  end

  test "emits the exact native DERP 101 response" do
    request = request("GET", "/derp", [{"upgrade", "DERP"}, {"ideal-node", "region-a"}])

    assert {:upgrade, :derp, response, %{ideal_node: "region-a"}} =
             HTTP1.route(request, @server_public)

    assert IO.iodata_to_binary(response) ==
             "HTTP/1.1 101 Switching Protocols\r\n" <>
               "Upgrade: DERP\r\n" <>
               "Connection: Upgrade\r\n" <>
               "Derp-Version: 2\r\n" <>
               "Derp-Public-Key: #{Base.encode16(@server_public, case: :lower)}\r\n\r\n"
  end

  test "suppresses only the HTTP response for fast start" do
    request =
      request("GET", "/derp", [{"upgrade", "derp"}, {"derp-fast-start", "1"}])

    assert HTTP1.route(request, @server_public) ==
             {:upgrade, :derp, nil, %{ideal_node: nil}}
  end

  test "requires an upgrade on other DERP paths" do
    assert {:response, response} = HTTP1.route(request("GET", "/derp/sdf"), @server_public)
    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 426 Upgrade Required\r\n"
    assert response =~ "DERP requires connection upgrade\n"
  end

  test "serves generate_204 with a validated challenge" do
    request = request("GET", "/generate_204", [{"x-tailscale-challenge", "abc-123:_"}])
    assert {:response, response} = HTTP1.route(request, @server_public)
    response = IO.iodata_to_binary(response)
    assert response =~ "HTTP/1.1 204 No Content\r\n"
    assert response =~ "X-Tailscale-Response: response abc-123:_\r\n"

    assert response =~
             "Cache-Control: no-cache, no-store, must-revalidate, no-transform, max-age=0"
  end

  defp request(method, path, headers \\ []) do
    %Request{method: method, target: path, version: "HTTP/1.1", headers: headers}
  end
end
