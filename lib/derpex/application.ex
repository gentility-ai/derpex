defmodule Derpex.Application do
  @moduledoc false

  use Application

  @impl true
  def start(_type, _args) do
    with {:ok, children} <- runtime_children() do
      Supervisor.start_link(children, strategy: :rest_for_one, name: Derpex.Supervisor)
    end
  end

  defp runtime_children do
    gentility = Application.fetch_env!(:derpex, :gentility)

    with {:ok, relay_children} <- relay_children(gentility) do
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

      bootstrap_dns =
        {Derpex.BootstrapDNS, Application.fetch_env!(:derpex, :bootstrap_dns)}

      {:ok,
       [
         Derpex.Router,
         Derpex.Mesh.ClientAddressTable,
         Derpex.Prober.PacketCache,
         bootstrap_dns,
         rate_controller,
         accept_limiter,
         {Derpex.Drain, profile: if(is_nil(gentility), do: :baseline, else: :gentility)}
       ] ++
         gentility_controller_children(gentility) ++
         relay_children ++ stun_children ++ gentility_event_children(gentility)}
    end
  end

  defp relay_children(gentility) do
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
         listener_children(listeners, private_key, gentility) ++
           mesh_children(
             mesh_peers,
             private_key,
             Application.fetch_env!(:derpex, :mesh_key)
           )}
      end
    end
  end

  defp listener_children([], _private_key, _gentility), do: []

  defp listener_children(listeners, private_key, gentility) do
    listeners = Enum.map(listeners, &put_gentility_admission(&1, gentility))
    [{Derpex.ListenerSupervisor, {listeners, private_key}}]
  end

  defp put_gentility_admission(listener, nil), do: listener

  defp put_gentility_admission(listener, _gentility) do
    handler_options =
      listener
      |> Keyword.get(:handler_options, [])
      |> Keyword.put(:admission, {:gentility, Derpex.Admission.Gentility})

    Keyword.put(listener, :handler_options, handler_options)
  end

  defp gentility_controller_children(nil), do: []

  defp gentility_controller_children(options) when is_list(options) do
    controller_options = Keyword.delete(options, :events)

    [
      {Derpex.Admission.Gentility,
       Keyword.put(controller_options, :name, Derpex.Admission.Gentility)}
    ]
  end

  defp gentility_controller_children(_invalid),
    do: raise("configure :derpex, :gentility as a keyword list")

  defp gentility_event_children(nil), do: []

  defp gentility_event_children(options) when is_list(options) do
    case Keyword.get(options, :events) do
      nil ->
        []

      event_options when is_list(event_options) ->
        event_options =
          event_options
          |> Keyword.put(:controller, Derpex.Admission.Gentility)
          |> Keyword.put(:name, Derpex.Admission.Gentility.Events)

        [{Derpex.Admission.Gentility.Events, event_options}]

      _invalid ->
        raise "configure :derpex, :gentility events as a keyword list"
    end
  end

  defp gentility_event_children(_invalid),
    do: raise("configure :derpex, :gentility as a keyword list")

  defp mesh_children([], _private_key, _mesh_key), do: []

  defp mesh_children(mesh_peers, private_key, <<mesh_key::binary-size(32)>>) do
    [{Derpex.Mesh.Supervisor, {mesh_peers, private_key, mesh_key}}]
  end

  defp mesh_children(_mesh_peers, _private_key, _mesh_key) do
    raise "configure :derpex, :mesh_key before enabling mesh peers"
  end
end
