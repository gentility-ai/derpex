defmodule Derpex.Admission.Gentility.ContractTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation

  @private_key Base.decode16!(
                 "1010101010101010101010101010101010101010101010101010101010101010",
                 case: :mixed
               )
  @public_key elem(:crypto.generate_key(:eddsa, :ed25519, @private_key), 0)

  test "lease records are deterministic, authenticated, and round-trip every allocation" do
    lease = lease()

    assert {:ok, signed} = Contract.sign_lease(lease, @private_key)
    assert byte_size(signed) == 240

    assert :crypto.hash(:sha256, signed) ==
             Base.decode16!(
               "8FFA3786624F5D5E75B79F6921573B5631C44AC1E50C0F964A3F664E234C6986",
               case: :mixed
             )

    assert Contract.verify_lease(signed, %{"gentility-2026-08" => @public_key}, 1_750) ==
             {:ok, lease}

    assert Contract.decode_lease(signed) == {:ok, lease}
  end

  test "lease verification rejects tampering, unknown keys, bad time windows, and versions" do
    assert {:ok, signed} = Contract.sign_lease(lease(), @private_key)
    <<first, rest::binary>> = signed
    tampered = <<Bitwise.bxor(first, 1), rest::binary>>

    assert Contract.verify_lease(tampered, keys(), 1_750) ==
             {:error, :invalid_lease_encoding}

    assert Contract.verify_lease(signed, %{}, 1_750) ==
             {:error, {:unknown_signing_key, "gentility-2026-08"}}

    assert Contract.verify_lease(signed, keys(), 999, max_future_skew_ms: 0) ==
             {:error, :lease_not_yet_valid}

    assert Contract.verify_lease(signed, keys(), 2_000) == {:error, :lease_expired}

    assert Contract.verify_lease(signed, keys(), 1_750, max_lease_ms: 500) ==
             {:error, :lease_too_long}

    <<"DXAL", _version::16, rest::binary>> = signed
    incompatible = <<"DXAL", 2::16, rest::binary>>

    assert Contract.verify_lease(incompatible, keys(), 1_750) ==
             {:error, {:unsupported_version, 2}}
  end

  test "revocations are deterministic, authenticated, and key-rotation aware" do
    revocation = %Revocation{
      key_id: "gentility-2026-08",
      node_key: :binary.copy(<<0xAB>>, 32),
      policy_revision: 43,
      revoked_at_ms: 1_800,
      reason: "node-disabled"
    }

    assert {:ok, signed} = Contract.sign_revocation(revocation, @private_key)

    assert :crypto.hash(:sha256, signed) ==
             Base.decode16!(
               "524424AFA747902BEE9AA6A43A0A7C9AA52A0BEA07F4208AC1D90872809820B9",
               case: :mixed
             )

    assert Contract.verify_revocation(signed, keys()) == {:ok, revocation}

    prefix_size = byte_size(signed) - 1
    <<prefix::binary-size(^prefix_size), last>> = signed
    tampered = <<prefix::binary, Bitwise.bxor(last, 1)>>
    assert Contract.verify_revocation(tampered, keys()) == {:error, :invalid_signature}
  end

  test "rejects invalid field ranges before signing" do
    invalid = %{lease() | node_key: "short"}
    assert Contract.sign_lease(invalid, @private_key) == {:error, {:invalid_field, :node_key}}

    invalid = %{lease() | expires_at_ms: 1_000}
    assert Contract.sign_lease(invalid, @private_key) == {:error, :invalid_lease_time_range}
  end

  defp lease do
    %Lease{
      key_id: "gentility-2026-08",
      node_key: :binary.copy(<<0xAB>>, 32),
      node_id: "node_01J6",
      organization_id: "org_01J6",
      owner_kind: "deployment",
      deployment_id: "dep_01J6",
      region_id: 17,
      policy_revision: 42,
      quota_revision: 7,
      issued_at_ms: 1_000,
      expires_at_ms: 2_000,
      node_connection_limit: 4,
      organization_connection_limit: 40,
      node_bytes_per_second: 10_000_000,
      node_byte_burst: 20_000_000,
      organization_bytes_per_second: 100_000_000,
      organization_byte_burst: 200_000_000
    }
  end

  defp keys, do: %{"gentility-2026-08" => @public_key}
end
