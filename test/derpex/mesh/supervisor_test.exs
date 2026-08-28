defmodule Derpex.Mesh.SupervisorTest do
  use ExUnit.Case, async: false

  alias Derpex.Crypto
  alias Derpex.Mesh.Client
  alias Derpex.Mesh.Supervisor, as: MeshSupervisor

  test "starts one independently supervised connection per configured peer" do
    {_public_key, private_key} = Crypto.generate_keypair()
    mesh_key = :crypto.strong_rand_bytes(32)

    supervisor =
      start_supervised!(
        {MeshSupervisor,
         {
           [
             [
               url: "http://127.0.0.1:1/derp",
               reconnect_interval: 60_000,
               connect_timeout: 50
             ],
             [
               url: "http://127.0.0.1:2/derp",
               reconnect_interval: 60_000,
               connect_timeout: 50
             ]
           ],
           private_key,
           mesh_key
         }}
      )

    children = Supervisor.which_children(supervisor)
    assert length(children) == 2
    assert Enum.map(children, &elem(&1, 0)) |> Enum.sort() == [{Client, 0}, {Client, 1}]

    Enum.each(children, fn {_id, client, :worker, [Client]} ->
      assert %{connected?: false, disabled?: false} = Client.status(client)
    end)
  end
end
