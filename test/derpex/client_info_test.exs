# Adapted from Tailscale's DERP ClientInfo and app-name tests.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ClientInfoTest do
  use ExUnit.Case, async: true

  alias Derpex.ClientInfo

  @mesh_key "6d529e9d4ef632d22d4a4214cb49da8f1ba1b72697061fb24e312984c35ec8d8"

  test "decodes the upstream ClientInfo vectors" do
    assert ClientInfo.decode("{}") == {:ok, %ClientInfo{}}

    expected = %ClientInfo{version: 5, mesh_key: Base.decode16!(@mesh_key, case: :mixed)}

    assert ClientInfo.decode(~s({"Version":5,"MeshKey":"#{@mesh_key}"})) ==
             {:ok, expected}

    assert ClientInfo.decode(~s({"version":5,"meshKey":"#{@mesh_key}"})) ==
             {:ok, expected}

    assert ClientInfo.decode(~s({"version":5,"meshKey":"abcdefg"})) ==
             {:error, :invalid_mesh_key}

    assert ClientInfo.decode(~s({"meshKey":"#{@mesh_key}ffff"})) ==
             {:error, :invalid_mesh_key}
  end

  test "matches Go's case folding, unknown-field, and last-duplicate behavior" do
    json = ~s({"VERSION":3,"unknown":{"ignored":true},"version":4,"CANACKPINGS":true})

    assert ClientInfo.decode(json) ==
             {:ok, %ClientInfo{version: 4, can_ack_pings: true}}
  end

  test "uses the upstream printable ASCII app-name rule" do
    valid = ["", "some-client", "app with spaces 123!", String.duplicate("x", 32)]
    invalid = [String.duplicate("x", 33), "new\nline", "nul\0", "emoji🐱"]

    assert Enum.all?(valid, &ClientInfo.valid_app_name?/1)
    refute Enum.any?(invalid, &ClientInfo.valid_app_name?/1)
  end

  test "rejects invalid recognized field types and trailing JSON" do
    assert ClientInfo.decode(~s({"version":"2"})) == {:error, {:invalid_field, :version}}
    assert ClientInfo.decode(~s({"AppName":"emoji🐱"})) == {:error, :invalid_app_name}
    assert ClientInfo.decode("{} x") == {:error, :trailing_data}
  end

  test "encodes Go-compatible field names, order, and omission" do
    assert ClientInfo.encode(%ClientInfo{}) == ~s({"CanAckPings":false})

    info = %ClientInfo{
      mesh_key: Base.decode16!(@mesh_key, case: :mixed),
      version: 2,
      can_ack_pings: true,
      is_prober: true,
      app_name: "derpex"
    }

    assert ClientInfo.encode(info) ==
             ~s({"meshKey":"#{@mesh_key}","version":2,"CanAckPings":true,"IsProber":true,"AppName":"derpex"})
  end
end
