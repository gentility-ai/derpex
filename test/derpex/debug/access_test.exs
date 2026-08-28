defmodule Derpex.Debug.AccessTest do
  use ExUnit.Case, async: true

  alias Derpex.Debug.Access
  alias Derpex.HTTP1.Request

  test "allows loopback and Tailscale ranges but denies forwarded requests" do
    assert authorized?({127, 0, 0, 1})
    assert authorized?({0, 0, 0, 0, 0, 0, 0, 1})
    assert authorized?({100, 64, 0, 1})
    assert authorized?({100, 127, 255, 254})
    refute authorized?({100, 63, 255, 255})
    refute authorized?({100, 128, 0, 1})
    assert authorized?({0xFD7A, 0x115C, 0xA1E0, 0, 0, 0, 0, 1})
    refute authorized?({0xFD7A, 0x115C, 0xA1E1, 0, 0, 0, 0, 1})

    forwarded = request(headers: [{"x-forwarded-for", "127.0.0.1"}])
    assert Access.authorize(forwarded, remote_ip: {127, 0, 0, 1}) == :unauthorized
  end

  test "supports explicit IP and parsed IPv4 and IPv6 trusted CIDRs" do
    assert {:ok, prefixes} =
             Access.parse_trusted_cidrs("10.0.0.0/8, 2001:db8:1234::/48")

    assert Access.authorize(request(),
             remote_ip: {203, 0, 113, 7},
             allow_ip: "203.0.113.7"
           ) == :authorized

    assert Access.authorize(request(),
             remote_ip: {10, 4, 5, 6},
             trusted_cidrs: prefixes
           ) == :authorized

    assert Access.authorize(request(),
             remote_ip: {0x2001, 0xDB8, 0x1234, 1, 2, 3, 4, 5},
             trusted_cidrs: prefixes
           ) == :authorized

    assert Access.authorize(request(),
             remote_ip: {192, 0, 2, 1},
             trusted_cidrs: prefixes
           ) == :unauthorized

    assert {:error, {"not-a-cidr", :invalid_cidr}} =
             Access.parse_trusted_cidrs("10.0.0.0/8,not-a-cidr")
  end

  test "GET debug key bypasses forwarded and source checks" do
    path =
      Path.join(System.tmp_dir!(), "derpex-debug-key-#{System.unique_integer([:positive])}")

    File.write!(path, "secret-value\n")
    on_exit(fn -> File.rm(path) end)

    keyed =
      request(
        target: "/debug/vars?debugkey=secret-value",
        headers: [{"x-forwarded-for", "198.51.100.4"}]
      )

    assert Access.authorize(keyed, key_path: path, remote_ip: {198, 51, 100, 4}) ==
             :authorized

    wrong = %{keyed | target: "/debug/vars?debugkey=wrong"}
    assert Access.authorize(wrong, key_path: path, remote_ip: {198, 51, 100, 4}) == :unauthorized

    post = %{keyed | method: "POST"}
    assert Access.authorize(post, key_path: path, remote_ip: {198, 51, 100, 4}) == :unauthorized
  end

  defp authorized?(ip), do: Access.authorize(request(), remote_ip: ip) == :authorized

  defp request(options \\ []) do
    %Request{
      method: Keyword.get(options, :method, "GET"),
      target: Keyword.get(options, :target, "/debug/vars"),
      version: "HTTP/1.1",
      headers: Keyword.get(options, :headers, [])
    }
  end
end
