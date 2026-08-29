defmodule Derpex.Admission.Gentility.UsageSpoolTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.UsageBatch
  alias Derpex.Admission.Gentility.UsageBatch.Entry
  alias Derpex.Admission.Gentility.UsageContract
  alias Derpex.Admission.Gentility.UsageSpool

  @tag :tmp_dir
  test "durably replays FIFO batches and acknowledges only the head", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "usage.spool")
    first = encoded_batch(0)
    second = encoded_batch(60_000)
    assert {:ok, spool} = UsageSpool.load(path, 2, 10_000)
    assert UsageSpool.peek(spool) == nil
    assert {:ok, spool} = UsageSpool.put(spool, first)
    assert {:ok, spool} = UsageSpool.put(spool, first)
    assert {:ok, spool} = UsageSpool.put(spool, second)
    assert UsageSpool.stats(spool).batches == 2
    assert UsageSpool.peek(spool) == first

    assert {:ok, stat} = File.stat(path)
    assert Bitwise.band(stat.mode, 0o777) == 0o600

    assert {:ok, recovered} = UsageSpool.load(path, 2, 10_000)
    assert UsageSpool.peek(recovered) == first
    assert UsageSpool.ack(recovered, elem(second, 0)) == {:error, :batch_not_at_head}
    assert {:ok, recovered} = UsageSpool.ack(recovered, elem(first, 0))
    assert UsageSpool.peek(recovered) == second
    assert {:ok, recovered} = UsageSpool.ack(recovered, elem(second, 0))
    assert UsageSpool.stats(recovered) == %{batches: 0, bytes: 0}
    assert {:ok, %{batches: []}} = UsageSpool.load(path, 2, 10_000)
  end

  @tag :tmp_dir
  test "hard batch and byte limits preserve the last durable checkpoint", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "usage.spool")
    first = encoded_batch(0)
    second = encoded_batch(60_000)
    assert {:ok, spool} = UsageSpool.load(path, 1, 10_000)
    assert {:ok, spool} = UsageSpool.put(spool, first)
    assert UsageSpool.put(spool, second) == {:error, :spool_batch_limit}
    assert {:ok, recovered} = UsageSpool.load(path, 1, 10_000)
    assert UsageSpool.peek(recovered) == first

    assert {:ok, tiny} = UsageSpool.load(nil, 2, byte_size(elem(second, 1)) - 1)
    assert UsageSpool.put(tiny, second) == {:error, :spool_byte_limit}
  end

  @tag :tmp_dir
  test "corruption and invalid content addresses fail closed", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "usage.spool")
    File.write!(path, "not a spool")
    assert UsageSpool.load(path, 2, 10_000) == {:error, :invalid_spool}

    assert {:ok, spool} = UsageSpool.load(nil, 2, 10_000)
    {_id, wire} = encoded_batch(0)

    assert UsageSpool.put(spool, {:binary.copy(<<0>>, 32), wire}) ==
             {:error, :invalid_usage_batch}
  end

  defp encoded_batch(start_ms) do
    batch = %UsageBatch{
      instance_id: "derpex-sin-1",
      region_id: 17,
      window_start_ms: start_ms,
      window_end_ms: start_ms + 60_000,
      entries: [
        %Entry{
          node_id: "node-a",
          organization_id: "org-1",
          owner_kind: "deployment",
          deployment_id: "dep-a",
          accepted_packets: 1,
          accepted_bytes: 100,
          dropped_packets: 0,
          dropped_bytes: 0
        }
      ]
    }

    {:ok, encoded} = UsageContract.encode(batch)
    encoded
  end

  @tag :tmp_dir
  test "refuses a spool path that is not a regular file", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "usage.spool")
    target = Path.join(tmp_dir, "elsewhere.spool")
    {:ok, spool} = UsageSpool.load(target, 4, 1_000_000)
    {:ok, _spool} = UsageSpool.put(spool, encoded_batch(0))
    :ok = File.ln_s(target, path)

    assert UsageSpool.load(path, 4, 1_000_000) == {:error, :spool_not_a_regular_file}
  end

  @tag :tmp_dir
  test "refuses a spool larger than its configured bounds allow", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "usage.spool")
    :ok = File.write(path, :binary.copy(<<0>>, 4_096))

    assert UsageSpool.load(path, 1, 8) == {:error, :spool_too_large}
  end
end
