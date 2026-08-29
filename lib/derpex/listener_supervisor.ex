defmodule Derpex.ListenerSupervisor do
  @moduledoc "Supervises configured native TCP/TLS listeners."

  use Supervisor

  alias Derpex.Admission.Gentility
  alias Derpex.Certificates
  alias Derpex.Certificates.Reloader
  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Listener.Transports
  alias Derpex.SocketOptions

  @spec start_link({[keyword()], binary()}) :: Supervisor.on_start()
  def start_link({listeners, server_private_key}) do
    Supervisor.start_link(__MODULE__, {listeners, server_private_key}, name: __MODULE__)
  end

  @impl true
  def init({listeners, server_private_key}) do
    children =
      listeners
      |> Enum.with_index()
      |> Enum.flat_map(fn {options, index} ->
        listener_children(options, index, server_private_key)
      end)

    Supervisor.init(children, strategy: :one_for_one)
  end

  defp listener_children(options, index, server_private_key) do
    {reload_interval_ms, options} =
      Keyword.pop(options, :certificate_reload_interval_ms, 0)

    case certificate_reloader(options, index, server_private_key, reload_interval_ms) do
      {:ok, reloader, options} ->
        [reloader, listener_child(options, index, server_private_key)]

      :disabled ->
        [listener_child(options, index, server_private_key)]
    end
  end

  defp listener_child(options, index, server_private_key) do
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
      |> configure_transport()

    Supervisor.child_spec({ThousandIsland, options}, id: {ThousandIsland, index})
  end

  defp certificate_reloader(options, index, server_private_key, interval_ms)
       when is_integer(interval_ms) and interval_ms > 0 do
    transport_options = Keyword.get(options, :transport_options, [])

    with true <- Keyword.get(options, :transport_module) == ThousandIsland.Transports.SSL,
         certfile when is_binary(certfile) <- Keyword.get(transport_options, :certfile),
         keyfile when is_binary(keyfile) <- Keyword.get(transport_options, :keyfile),
         {:ok, server_public_key} <- Crypto.public_key(server_private_key) do
      snapshot_key = {__MODULE__, :certificate_snapshot, make_ref()}

      transport_options =
        transport_options
        |> Keyword.put(:sni_fun, Reloader.sni_fun(snapshot_key))
        |> Keyword.put(Transports.SSL.snapshot_option(), snapshot_key)

      options = Keyword.put(options, :transport_options, transport_options)

      reloader =
        Supervisor.child_spec(
          {Reloader,
           snapshot_key: snapshot_key,
           certificate_path: certfile,
           key_path: keyfile,
           server_public_key: server_public_key,
           interval_ms: interval_ms},
          id: {Reloader, index}
        )

      {:ok, reloader, options}
    else
      _not_file_backed_tls -> :disabled
    end
  end

  defp certificate_reloader(_options, _index, _server_private_key, _interval_ms),
    do: :disabled

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

  defp configure_transport(options) do
    case Keyword.get(options, :transport_module, ThousandIsland.Transports.TCP) do
      ThousandIsland.Transports.TCP ->
        Keyword.put(options, :transport_module, Transports.TCP)

      ThousandIsland.Transports.SSL ->
        Keyword.put(options, :transport_module, Transports.SSL)

      _custom_transport ->
        options
    end
  end
end
