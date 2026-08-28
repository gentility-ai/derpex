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

      {:ok, [Derpex.Router | relay_children ++ stun_children]}
    end
  end

  defp relay_children do
    case Application.fetch_env!(:derpex, :listeners) do
      [] ->
        {:ok, []}

      listeners ->
        identity_path =
          Application.fetch_env!(:derpex, :identity_path) ||
            raise "configure :derpex, :identity_path before enabling listeners"

        with {:ok, {_public_key, private_key}} <-
               Derpex.Identity.load_or_create_keypair(identity_path) do
          {:ok, [{Derpex.ListenerSupervisor, {listeners, private_key}}]}
        end
    end
  end
end
