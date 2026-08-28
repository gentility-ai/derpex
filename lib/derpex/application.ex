defmodule Derpex.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    with {:ok, children} <- runtime_children() do
      Supervisor.start_link(children, strategy: :one_for_one, name: Derpex.Supervisor)
    end
  end

  defp runtime_children do
    with {:ok, relay_children} <- relay_children() do
      stun_children =
        :derpex
        |> Application.fetch_env!(:stun_listeners)
        |> Enum.with_index()
        |> Enum.map(fn {options, index} ->
          Supervisor.child_spec({Derpex.STUN, options}, id: {Derpex.STUN, index})
        end)

      rate_controller =
        case Application.fetch_env!(:derpex, :rate_config_path) do
          nil -> Derpex.RateController
          path -> {Derpex.RateController, path: path}
        end

      accept_limiter =
        case Application.fetch_env!(:derpex, :accept_limit) do
          nil -> Derpex.AcceptLimiter
          config -> {Derpex.AcceptLimiter, config: config}
        end

      {:ok,
       [Derpex.Router, Derpex.Prober.PacketCache, rate_controller, accept_limiter] ++
         relay_children ++ stun_children}
    end
  end

  defp relay_children do
    listeners = Application.fetch_env!(:derpex, :listeners)
    mesh_peers = Application.fetch_env!(:derpex, :mesh_peers)

    if listeners == [] and mesh_peers == [] do
      {:ok, []}
    else
      identity_path =
        Application.fetch_env!(:derpex, :identity_path) ||
          raise "configure :derpex, :identity_path before enabling listeners or mesh peers"

      with {:ok, {_public_key, private_key}} <-
             Derpex.Identity.load_or_create_keypair(identity_path) do
        {:ok,
         listener_children(listeners, private_key) ++
           mesh_children(
             mesh_peers,
             private_key,
             Application.fetch_env!(:derpex, :mesh_key)
           )}
      end
    end
  end

  defp listener_children([], _private_key), do: []

  defp listener_children(listeners, private_key) do
    [{Derpex.ListenerSupervisor, {listeners, private_key}}]
  end

  defp mesh_children([], _private_key, _mesh_key), do: []

  defp mesh_children(mesh_peers, private_key, <<mesh_key::binary-size(32)>>) do
    [{Derpex.Mesh.Supervisor, {mesh_peers, private_key, mesh_key}}]
  end

  defp mesh_children(_mesh_peers, _private_key, _mesh_key) do
    raise "configure :derpex, :mesh_key before enabling mesh peers"
  end
end
