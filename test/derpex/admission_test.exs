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
