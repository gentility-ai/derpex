defmodule Derpex.ServerInfoTest do
  use ExUnit.Case, async: true

  alias Derpex.ServerInfo

  test "encodes the server's protocol version exactly like Go" do
    assert ServerInfo.encode(%ServerInfo{version: 2}) == ~s({"version":2})
  end

  test "round trips token bucket fields and ignores extensions" do
    json =
      ~s({"version":2,"TokenBucketBytesPerSecond":1000,"TokenBucketBytesBurst":2000,"future":true})

    expected = %ServerInfo{
      version: 2,
      token_bucket_bytes_per_second: 1_000,
      token_bucket_bytes_burst: 2_000
    }

    assert ServerInfo.decode(json) == {:ok, expected}
    assert ServerInfo.decode(ServerInfo.encode(expected)) == {:ok, expected}
  end

  test "uses the last case-insensitive duplicate and validates types" do
    assert ServerInfo.decode(~s({"Version":1,"version":2})) ==
             {:ok, %ServerInfo{version: 2}}

    assert ServerInfo.decode(~s({"version":false})) ==
             {:error, {:invalid_field, :version}}
  end
end
