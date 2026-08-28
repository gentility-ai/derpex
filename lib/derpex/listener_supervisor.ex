defmodule Derpex.ListenerSupervisor do
  @moduledoc "Supervises configured native TCP/TLS listeners."

  use Supervisor

  alias Derpex.Certificates
  alias Derpex.Crypto
  alias Derpex.Listener.Handler

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
    handler_options =
      options
      |> Keyword.get(:handler_options, [])
      |> Keyword.put(:server_private_key, server_private_key)

    options =
      options
      |> Keyword.put(:handler_module, Handler)
      |> Keyword.put(:handler_options, handler_options)
      |> configure_tls(server_private_key)

    {ThousandIsland, options}
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
