defmodule Derpex.Mesh.Supervisor do
  @moduledoc "Supervises configured outbound connections to regional DERP peers."

  use Supervisor

  alias Derpex.Mesh.Client
  alias Derpex.Secret

  @spec start_link({[binary() | keyword()], Secret.t(), Secret.t()}) :: Supervisor.on_start()
  def start_link({peers, private_key, mesh_key}) do
    Supervisor.start_link(__MODULE__, {peers, private_key, mesh_key}, name: __MODULE__)
  end

  @impl true
  def init({peers, private_key, mesh_key}) do
    peers
    |> Enum.with_index()
    |> Enum.map(fn {peer, index} ->
      options =
        peer
        |> peer_options()
        |> Keyword.put(:private_key, private_key)
        |> Keyword.put(:mesh_key, mesh_key)

      Supervisor.child_spec({Client, options}, id: {Client, index})
    end)
    |> Supervisor.init(strategy: :one_for_one)
  end

  defp peer_options(url) when is_binary(url), do: [url: url]
  defp peer_options(options) when is_list(options), do: options
end
