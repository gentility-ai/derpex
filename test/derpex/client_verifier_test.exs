defmodule Derpex.ClientVerifierTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Request
  alias Derpex.ClientInfo
  alias Derpex.ClientVerifier

  test "normalizes verifier results" do
    request = request(false)

    assert ClientVerifier.verify(fn _request -> :ok end, request) == :ok

    assert ClientVerifier.verify(fn _request -> {:error, :denied} end, request) ==
             {:error, :denied}

    assert ClientVerifier.verify(fn _request -> :maybe end, request) ==
             {:error, {:invalid_verification_result, :maybe}}
  end

  test "trusted mesh peers bypass the configured verifier" do
    parent = self()

    assert ClientVerifier.verify(
             fn _request ->
               send(parent, :verifier_called)
               {:error, :denied}
             end,
             request(true)
           ) == :ok

    refute_receive :verifier_called
  end

  defp request(mesh_peer?) do
    %Request{
      node_key: :binary.copy(<<7>>, 32),
      client_info: %ClientInfo{},
      source_ip: {127, 0, 0, 1},
      mesh_peer?: mesh_peer?,
      metadata: %{}
    }
  end
end
