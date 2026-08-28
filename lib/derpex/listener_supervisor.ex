defmodule Derpex.ListenerSupervisor do
  @moduledoc "Supervises configured native TCP/TLS listeners."

  use Supervisor

  alias Derpex.Admission.Gentility
  alias Derpex.Certificates
  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.SocketOptions

  @spec start_link({[keyword()], binary()}) :: Supervisor.on_start()
  def start_link({listeners, server_private_key}) do
    Supervisor.start_link(__MODULE__, {listeners, server_private_key}, name: __MODULE__)
  end

  @impl true
  def init({listeners, server_private_key}) do
    listeners
    |> Enum.map(&listener_child(&1, server_private_key))
    |> Supervisor.init(strategy: :one_for_one)
  end

  defp listener_child(options, server_private_key) do
    {socket_options, options} = Keyword.pop(options, :socket_options, [])

    handler_options =
      options
      |> Keyword.get(:handler_options, [])
      |> resolve_admission()
      |> Keyword.put_new(:mesh_write_timeout, SocketOptions.mesh_write_timeout_ms())
      |> Keyword.put(:server_private_key, server_private_key)

    options =
      options
      |> Keyword.put(:handler_module, Handler)
      |> Keyword.put(:handler_options, handler_options)
      |> configure_tls(server_private_key)
      |> configure_socket(socket_options)

    {ThousandIsland, options}
  end

  defp resolve_admission(handler_options) do
    case Keyword.get(handler_options, :admission) do
      {:gentility, server} ->
        policy = Gentility.policy(server)
        Keyword.put(handler_options, :admission, {Gentility, policy})

      _other ->
        handler_options
    end
  end

  defp configure_socket(options, socket_options) do
    :ok = SocketOptions.log_platform_notice(socket_options)

    transport_options =
      options
      |> Keyword.get(:transport_options, [])
      |> SocketOptions.listener_options(socket_options)

    Keyword.put(options, :transport_options, transport_options)
  end

  defp configure_tls(options, server_private_key) do
    if Keyword.get(options, :transport_module) == ThousandIsland.Transports.SSL do
      transport_options = Keyword.get(options, :transport_options, [])

      with certfile when is_binary(certfile) <- Keyword.get(transport_options, :certfile),
           keyfile when is_binary(keyfile) <- Keyword.get(transport_options, :keyfile),
           {:ok, server_public_key} <- Crypto.public_key(server_private_key) do
        loaded = Certificates.transport_options(certfile, keyfile, server_public_key)

        transport_options =
          transport_options
          |> Keyword.delete(:certfile)
          |> Keyword.delete(:keyfile)
          |> Keyword.merge(loaded)

        Keyword.put(options, :transport_options, transport_options)
      else
        _not_file_backed -> options
      end
    else
      options
    end
  end
end
