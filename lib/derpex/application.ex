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
    case Application.fetch_env!(:derpex, :listeners) do
      [] ->
        {:ok, [Derpex.Router]}

      listeners ->
        identity_path =
          Application.fetch_env!(:derpex, :identity_path) ||
            raise "configure :derpex, :identity_path before enabling listeners"

        with {:ok, {_public_key, private_key}} <-
               Derpex.Identity.load_or_create_keypair(identity_path) do
          {:ok, [Derpex.Router, {Derpex.ListenerSupervisor, {listeners, private_key}}]}
        end
    end
  end
end
