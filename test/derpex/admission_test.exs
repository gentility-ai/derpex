defmodule Derpex.AdmissionTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission
  alias Derpex.Admission.Request
  alias Derpex.ClientInfo

  defmodule Policy do
    @behaviour Derpex.Admission

    @impl true
    def authorize(request, expected_key) do
      if request.node_key == expected_key,
        do: {:ok, %{organization: "one"}},
        else: {:error, :denied}
    end
  end

  defmodule AccountingPolicy do
    @behaviour Derpex.Admission

    @impl true
    def authorize(_request, parent), do: {:ok, %{parent: parent}}

    @impl true
    def claim(request, context, connection, parent) do
      send(parent, {:claimed, request.node_key, connection})
      {:ok, Map.put(context, :claimed?, true)}
    end

    @impl true
    def release(connection, parent) do
      send(parent, {:released, connection})
      :ok
    end

    @impl true
    def record_usage(context, bytes, outcome, parent) do
      send(parent, {:usage, context, bytes, outcome})
      :ok
    end
  end

  test "dispatches authenticated request data to configured policy" do
    key = :binary.copy(<<1>>, 32)
    request = request(key)

    assert Admission.authorize({Policy, key}, request) == {:ok, %{organization: "one"}}

    assert Admission.authorize(fn _request -> {:error, :revoked} end, request) ==
             {:error, :revoked}

    assert Admission.authorize(fn _request -> :maybe end, request) ==
             {:error, {:invalid_decision, :maybe}}

    assert Admission.authorize(nil, request) == {:ok, %{}}
  end

  test "trusted mesh peers bypass ordinary policy" do
    request = %{request(:binary.copy(<<2>>, 32)) | mesh_peer?: true}

    assert Admission.authorize(fn _request -> {:error, :must_not_run} end, request) ==
             {:ok, %{mesh_peer?: true}}
  end

  test "dispatches optional connection claims and releases while preserving simple policies" do
    request = request(:binary.copy(<<3>>, 32))

    assert Admission.claim({AccountingPolicy, self()}, request, %{authorized?: true}, self()) ==
             {:ok, %{authorized?: true, claimed?: true}}

    node_key = request.node_key
    assert_receive {:claimed, ^node_key, connection}
    assert connection == self()
    assert Admission.release({AccountingPolicy, self()}, self()) == :ok
    assert_receive {:released, ^connection}

    assert Admission.record_usage(
             {AccountingPolicy, self()},
             %{organization_id: "org-1"},
             64,
             :accepted
           ) == :ok

    assert_receive {:usage, %{organization_id: "org-1"}, 64, :accepted}

    assert Admission.claim(fn _request -> {:ok, %{}} end, request, %{}, self()) == {:ok, %{}}
  end

  defp request(key) do
    %Request{
      node_key: key,
      client_info: %ClientInfo{version: 2},
      source_ip: {127, 0, 0, 1},
      mesh_peer?: false,
      metadata: %{}
    }
  end
end
