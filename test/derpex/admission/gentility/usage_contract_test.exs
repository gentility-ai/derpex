defmodule Derpex.Admission.Gentility.UsageContractTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.UsageBatch
  alias Derpex.Admission.Gentility.UsageBatch.Entry
  alias Derpex.Admission.Gentility.UsageContract

  test "canonical sorting produces a stable idempotency key and round-trips counters" do
    batch = batch()
    assert {:ok, {id, wire}} = UsageContract.encode(batch)

    assert Base.encode16(id) ==
             "62035D699A128528CCA4753483221C5740107E889A15307A42D6B50314E3FC8B"

    assert {:ok, decoded} = UsageContract.decode(wire, id)
    assert Enum.map(decoded.entries, & &1.node_id) == ["node-a", "node-b"]
    assert %{accepted_bytes: 200, dropped_bytes: 20} = List.last(decoded.entries)

    assert UsageContract.encode(%{batch | entries: Enum.reverse(batch.entries)}) ==
             {:ok, {id, wire}}
  end

  test "rejects tampering, incompatible versions, duplicate attribution, and invalid windows" do
    assert {:ok, {id, wire}} = UsageContract.encode(batch())
    <<first, rest::binary>> = wire

    assert UsageContract.decode(<<Bitwise.bxor(first, 1), rest::binary>>, id) ==
             {:error, :invalid_usage_batch}

    incompatible_id = :crypto.hash(:sha256, incompatible = incompatible(wire))

    assert UsageContract.decode(incompatible, incompatible_id) ==
             {:error, {:unsupported_version, 2}}

    [entry | _rest] = batch().entries

    assert UsageContract.encode(%{batch() | entries: [entry, entry]}) ==
             {:error, :invalid_usage_batch}

    assert UsageContract.encode(%{batch() | window_end_ms: 60_000}) ==
             {:error, :invalid_usage_batch}
  end

  defp incompatible(<<"DXUB", _version::16, rest::binary>>), do: <<"DXUB", 2::16, rest::binary>>

  defp batch do
    %UsageBatch{
      instance_id: "derpex-sin-1",
      region_id: 17,
      window_start_ms: 60_000,
      window_end_ms: 120_000,
      entries: [
        %Entry{
          node_id: "node-b",
          organization_id: "org-1",
          owner_kind: "deployment",
          deployment_id: "dep-b",
          accepted_packets: 2,
          accepted_bytes: 200,
          dropped_packets: 1,
          dropped_bytes: 20
        },
        %Entry{
          node_id: "node-a",
          organization_id: "org-1",
          owner_kind: "connector",
          deployment_id: "dep-a",
          accepted_packets: 1,
          accepted_bytes: 100,
          dropped_packets: 0,
          dropped_bytes: 0
        }
      ]
    }
  end
end
