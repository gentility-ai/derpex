defmodule Derpex.ListenerSupervisor do
  @moduledoc """
  Supervises configured native TCP/TLS listeners.

  The server private key and each listener's `:mesh_key` handler option arrive
  as `Derpex.Secret` references. A supervisor retains its start arguments for
  restarts, so wrapping has to happen in the caller that builds this child
  specification, not here.
  """

  use Supervisor

  require Logger

  alias Derpex.Admission.Gentility
  alias Derpex.Certificates
  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Manual
  alias Derpex.Certificates.Reloader
  alias Derpex.Crypto
  alias Derpex.Listener.Handler
  alias Derpex.Listener.Transports
  alias Derpex.MetaCertificate
  alias Derpex.Secret
  alias Derpex.SocketOptions

  @spec start_link({[keyword()], Secret.t()}) :: Supervisor.on_start()
  def start_link({listeners, private_key}) do
    Supervisor.start_link(__MODULE__, {listeners, private_key}, name: __MODULE__)
  end

  @impl true
  def init({listeners, private_key}) do
    children =
      listeners
      |> Enum.with_index()
      |> Enum.flat_map(fn {options, index} ->
        listener_children(options, index, private_key)
      end)

    Supervisor.init(children, strategy: :one_for_one)
  end

  # The public key is derived once here and threaded through the certificate
  # reloader, the TLS options, and the handler options, so no connection pays
  # for a scalar multiplication that only depends on the listener's identity.
  defp listener_children(options, index, private_key) do
    {reload_interval_ms, options} =
      Keyword.pop(options, :certificate_reload_interval_ms, 0)

    public_key = server_public_key!(private_key)

    case certificate_reloader(options, index, public_key, reload_interval_ms) do
      {:ok, reloader, options} ->
        [reloader, listener_child(options, index, private_key, public_key)]

      :disabled ->
        [listener_child(options, index, private_key, public_key)]
    end
  end

  defp listener_child(options, index, private_key, public_key) do
    {socket_options, options} = Keyword.pop(options, :socket_options, [])
    {certificate_manager, options} = Keyword.pop(options, :ip_certificate_manager)

    handler_options =
      options
      |> Keyword.get(:handler_options, [])
      |> resolve_admission()
      |> Keyword.put_new(:mesh_write_timeout, SocketOptions.mesh_write_timeout_ms())
      |> Keyword.put(:server_private_key, private_key)
      |> Keyword.put(:server_public_key, public_key)

    options =
      options
      |> Keyword.put(:handler_module, Handler)
      |> Keyword.put(:handler_options, handler_options)
      |> configure_tls(public_key, certificate_manager)
      |> configure_socket(socket_options)
      |> configure_transport()

    Supervisor.child_spec({ThousandIsland, options}, id: {ThousandIsland, index})
  end

  defp server_public_key!(private_key) do
    case Crypto.public_key(Secret.reveal(private_key)) do
      {:ok, public_key} -> public_key
      {:error, reason} -> raise "invalid DERP server private key: #{inspect(reason)}"
    end
  end

  defp certificate_reloader(options, index, server_public_key, interval_ms)
       when is_integer(interval_ms) and interval_ms > 0 do
    transport_options = Keyword.get(options, :transport_options, [])

    with true <- Keyword.get(options, :transport_module) == ThousandIsland.Transports.SSL,
         certfile when is_binary(certfile) <- Keyword.get(transport_options, :certfile),
         keyfile when is_binary(keyfile) <- Keyword.get(transport_options, :keyfile) do
      snapshot_key = {__MODULE__, :certificate_snapshot, make_ref()}

      transport_options =
        transport_options
        |> put_transport_option(:sni_fun, Reloader.sni_fun(snapshot_key))
        |> put_transport_option(Transports.SSL.snapshot_option(), snapshot_key)

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

  defp certificate_reloader(_options, _index, _server_public_key, _interval_ms),
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

  # `DERPEX_IP_CERT_ISSUER=self` replaces the file-backed certificate with one
  # the manager issues for this listener's own IP address. The manager is
  # started before this supervisor, so the certificate exists by the time the
  # listen socket is opened, and `sni_fun` keeps every named hello answering
  # from the same manager.
  defp configure_tls(options, server_public_key, {manager, hostname}) do
    unless Keyword.get(options, :transport_module) == ThousandIsland.Transports.SSL do
      raise "a managed certificate requires a TLS listener"
    end

    snapshot_key = {__MODULE__, :certificate_snapshot, make_ref()}

    transport_options =
      options
      |> Keyword.get(:transport_options, [])
      |> drop_transport_options([:certfile, :keyfile, :certs_keys, :sni_fun])
      |> Kernel.++(
        managed_certificate_options(manager, hostname, server_public_key, snapshot_key)
      )
      |> put_transport_option(Transports.SSL.snapshot_option(), snapshot_key)

    Keyword.put(options, :transport_options, transport_options)
  end

  defp configure_tls(options, server_public_key, nil) do
    if Keyword.get(options, :transport_module) == ThousandIsland.Transports.SSL do
      transport_options = Keyword.get(options, :transport_options, [])

      with certfile when is_binary(certfile) <- Keyword.get(transport_options, :certfile),
           keyfile when is_binary(keyfile) <- Keyword.get(transport_options, :keyfile) do
        loaded = Certificates.transport_options(certfile, keyfile, server_public_key)

        transport_options =
          drop_transport_options(transport_options, [:certfile, :keyfile, :certs_keys]) ++ loaded

        Keyword.put(options, :transport_options, transport_options)
      else
        _not_file_backed -> options
      end
    else
      options
    end
  end

  # The metacertificate carries only the server node key, so it is generated
  # once here and shared by the bound options and every SNI answer. Generating
  # an RSA key pair per hello would cost more than the DERP handshake it
  # advertises.
  #
  # `:ssl.listen/2` needs a certificate before the first connection exists, so
  # the manager is asked for one and, when it cannot supply one — a certificate
  # authority that is unreachable at boot — the listener still binds with a
  # self-signed certificate for the same name. What clients actually receive is
  # the snapshot the manager publishes on every issuance and renewal, which
  # `Derpex.Listener.Transports.SSL` reads per connection, so an obtained or
  # renewed certificate reaches hellos with and without SNI alike.
  defp managed_certificate_options(manager, hostname, server_public_key, snapshot_key) do
    meta_certificate = MetaCertificate.generate(server_public_key)

    [
      certs_keys: [bound_certificate(manager, hostname, snapshot_key, meta_certificate)],
      sni_fun: IPManager.sni_fun(manager, hostname, meta_certificate)
    ]
  end

  # Nothing here waits on a certificate authority. `publish_to/4` answers from
  # the manager's disk cache, which is the usual case on restart, and otherwise
  # says it is bootstrapping: the socket binds a self-signed placeholder and the
  # manager orders the real certificate in the background, once the listener
  # that answers HTTP-01 challenges is already accepting. Ordering here instead
  # would deadlock the first order against the listener it needs.
  defp bound_certificate(manager, hostname, snapshot_key, meta_certificate) do
    case IPManager.publish_to(manager, snapshot_key, hostname, meta_certificate) do
      {:ok, certs_keys} ->
        certs_keys

      :bootstrap ->
        Logger.warning(
          "DERP listener has no certificate for #{hostname} yet; binding a self-signed " <>
            "placeholder while one is ordered"
        )

        self_signed_certificate(hostname, meta_certificate)
    end
  end

  defp self_signed_certificate(hostname, meta_certificate) do
    case Manual.generate_self_signed(hostname) do
      {:ok, {certificate_der, private_key}} ->
        type = elem(private_key, 0)

        %{
          cert: Certificates.append_meta_certificate([certificate_der], meta_certificate),
          key: {type, :public_key.der_encode(type, private_key)}
        }

      {:error, reason} ->
        raise "could not bind a certificate for #{hostname}: #{inspect(reason)}"
    end
  end

  # `transport_options` reach `:ssl.listen/2` and `:gen_tcp.listen/2`, which
  # accept bare atoms (`:inet6`, `:binary`) and `{:raw, _, _, _}` tuples
  # alongside `{key, value}` pairs. `Keyword` functions raise on those, so
  # rewriting the list has to go through proplist-tolerant helpers.
  defp put_transport_option(options, key, value) do
    drop_transport_options(options, [key]) ++ [{key, value}]
  end

  defp drop_transport_options(options, keys) do
    Enum.reject(options, fn
      {key, _value} -> key in keys
      _other_option -> false
    end)
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
