defmodule Derpex.Admission.Gentility.EventsTest do
  use ExUnit.Case, async: false

  alias Derpex.Admission.Gentility
  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.Events
  alias Derpex.Admission.Gentility.Revocation
  alias Derpex.Clock.Manual

  @private_key :binary.copy(<<0x23>>, 32)
  @public_key elem(:crypto.generate_key(:eddsa, :ed25519, @private_key), 0)
  @key_id "gentility-events"

  defmodule Adapter do
    @behaviour Derpex.Admission.Gentility.ControlPlane

    @impl true
    def authorize(_request, _options), do: {:error, :unavailable}

    @impl true
    def export_usage(_id, _wire, _options), do: {:error, :unavailable}

    @impl true
    def reconcile(agent), do: take(agent, :reconcile)

    @impl true
    def next_revocation(_cursor, _timeout, agent), do: take(agent, :stream)

    defp take(agent, key) do
      Agent.get_and_update(agent, fn state ->
        case Map.fetch!(state, key) do
          [response | rest] -> {response, Map.put(state, key, rest)}
          [] -> {{:error, :unavailable}, state}
        end
      end)
    end
  end

  defmodule StalledAdapter do
    @behaviour Derpex.Admission.Gentility.ControlPlane
    def authorize(_request, _options), do: {:error, :unavailable}
    def export_usage(_id, _wire, _options), do: {:error, :unavailable}
    def reconcile(function), do: function.()
    def next_revocation(_cursor, _timeout, _options), do: {:error, :unavailable}
  end

  setup do
    previous_clock = Application.fetch_env!(:derpex, :clock)
    Application.put_env(:derpex, :clock, Manual)
    start_supervised!({Manual, system_time: 1_000})
    on_exit(fn -> Application.put_env(:derpex, :clock, previous_clock) end)
    :ok
  end

  test "reconciles first, consumes signed revocations in order, and reconnects after errors" do
    parent = self()
    first_key = node_key(1)
    second_key = node_key(2)
    first = signed_revocation(first_key, 10)
    second = signed_revocation(second_key, 11)

    {:ok, adapter} =
      Agent.start_link(fn ->
        %{
          reconcile: [{:ok, [first], "cursor-1"}, {:ok, [], "cursor-2"}],
          stream: [{:ok, second, "cursor-2"}, {:error, :disconnected}]
        }
      end)

    controller = start_controller(parent)

    events =
      start_supervised!(
        {Events,
         controller: controller,
         adapter: {Adapter, adapter},
         clock: Manual,
         backoff_ms: 100,
         max_backoff_ms: 1_000}
      )

    assert_receive {:closed, ^first_key}, 2_000
    assert_receive {:closed, ^second_key}, 2_000
    eventually(fn -> Events.stats(events).last_error == :adapter_unavailable end)
    assert Events.stats(events).reconciliations == 1
    assert Events.stats(events).revocations == 1

    Manual.advance(100)
    eventually(fn -> Events.stats(events).reconciliations == 2 end)
    assert Events.stats(events).last_error == :adapter_unavailable
  end

  test "invalid reconciliation fails closed and retries without applying any record" do
    parent = self()
    valid = signed_revocation(node_key(3), 10)

    {:ok, adapter} =
      Agent.start_link(fn -> %{reconcile: [{:ok, [valid, "bad"], "cursor"}], stream: []} end)

    controller = start_controller(parent)

    events =
      start_supervised!(
        {Events,
         controller: controller, adapter: {Adapter, adapter}, clock: Manual, backoff_ms: 100}
      )

    eventually(fn -> Events.stats(events).last_error == :invalid_signed_record end)
    refute_receive {:closed, _key}
    assert Gentility.stats(controller).revocations == 0
  end

  test "a stalled transport worker does not block admission-controller calls" do
    parent = self()

    adapter = fn ->
      receive do: (:release -> {:ok, [], "cursor"})
    end

    controller = start_controller(parent)

    events =
      start_supervised!(
        {Events, controller: controller, adapter: {StalledAdapter, adapter}, clock: Manual}
      )

    eventually(fn -> Events.stats(events).reconciling? end)
    assert Gentility.stats(controller).cache_entries == 0
  end

  defp start_controller(parent) do
    start_supervised!(
      {Gentility,
       authority: fn _request -> {:error, :unavailable} end,
       verification_keys: %{@key_id => @public_key},
       clock: Manual,
       close_peer: fn key -> send(parent, {:closed, key}) end}
    )
  end

  defp signed_revocation(node_key, revision) do
    revocation = %Revocation{
      key_id: @key_id,
      node_key: node_key,
      policy_revision: revision,
      revoked_at_ms: 1_000,
      reason: "disabled"
    }

    {:ok, wire} = Contract.sign_revocation(revocation, @private_key)
    wire
  end

  defp node_key(byte), do: :binary.copy(<<byte>>, 32)

  defp eventually(assertion, attempts \\ 100)
  defp eventually(assertion, 0), do: assert(assertion.())

  defp eventually(assertion, attempts) do
    if assertion.() do
      :ok
    else
      Process.sleep(5)
      eventually(assertion, attempts - 1)
    end
  end
end
