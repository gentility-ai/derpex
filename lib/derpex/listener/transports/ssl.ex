defmodule Derpex.Listener.Transports.SSL do
  @moduledoc """
  TLS transport that resolves the server certificate per connection.

  When `transport_options` carry a `#{inspect(:derpex_certificate_snapshot)}`
  key the listen socket is opened with `handshake: :hello`, so every accepted
  connection pauses after the ClientHello. `handshake/1` then supplies the
  certificate that `Derpex.Certificates.Reloader` currently publishes through
  `:ssl.handshake_continue/2`. This covers SNI *and* no-SNI hellos alike, which
  `sni_fun` alone cannot do. Listeners without a reloader keep the plain
  upstream handshake and pay nothing.

  The snapshot key is registered in `:persistent_term` under the bound port,
  because Thousand Island hands `handshake/1` only the accepted socket. Reads
  are lock-free and happen once per connection, and only on the paused path.
  """

  @behaviour ThousandIsland.Transport

  alias Derpex.Certificates.Reloader
  alias Derpex.Listener.Transports.Options
  alias ThousandIsland.Transports.SSL, as: Upstream

  @certificate_options [:certs_keys, :keyfile, :key, :sni_hosts, :sni_fun]
  @public_certificate_options [:certs_keys, :certfile, :cert, :sni_hosts, :sni_fun]
  @snapshot_option :derpex_certificate_snapshot

  @doc "The `transport_options` key carrying a certificate-reloader snapshot key."
  @spec snapshot_option() :: atom()
  def snapshot_option, do: @snapshot_option

  @impl true
  def listen(port, user_options) do
    {snapshot_key, user_options} = pop_snapshot_key(user_options)

    options =
      user_options
      |> paused_handshake(snapshot_key)
      |> Options.resolve(
        backlog: 1024,
        nodelay: true,
        send_timeout: 30_000,
        send_timeout_close: true,
        reuseaddr: true
      )

    unless Enum.any?(@certificate_options, &:proplists.is_defined(&1, options)) do
      raise "transport_options must include one of keyfile, key, sni_hosts or sni_fun"
    end

    unless Enum.any?(@public_certificate_options, &:proplists.is_defined(&1, options)) do
      raise "transport_options must include one of certfile, cert, sni_hosts or sni_fun"
    end

    with {:ok, socket} <- :ssl.listen(port, options) do
      register_snapshot(socket, snapshot_key)
    end
  end

  @impl true
  defdelegate accept(socket), to: Upstream

  @impl true
  def handshake(socket) do
    case :ssl.handshake(socket) do
      {:ok, socket, _extensions} -> :ssl.handshake_continue(socket, certificate_options(socket))
      {:ok, socket} -> {:ok, socket}
      {:error, _reason} = error -> error
    end
  end

  @impl true
  defdelegate upgrade(socket, options), to: Upstream
  @impl true
  defdelegate controlling_process(socket, pid), to: Upstream
  @impl true
  defdelegate recv(socket, length, timeout), to: Upstream
  @impl true
  defdelegate send(socket, data), to: Upstream
  @impl true
  defdelegate sendfile(socket, filename, offset, length), to: Upstream
  @impl true
  defdelegate getopts(socket, options), to: Upstream
  @impl true
  defdelegate setopts(socket, options), to: Upstream
  @impl true
  defdelegate shutdown(socket, way), to: Upstream
  @impl true
  defdelegate close(socket), to: Upstream
  @impl true
  defdelegate sockname(socket), to: Upstream
  @impl true
  defdelegate peername(socket), to: Upstream
  @impl true
  defdelegate peercert(socket), to: Upstream
  @impl true
  defdelegate secure?(), to: Upstream
  @impl true
  defdelegate getstat(socket), to: Upstream
  @impl true
  defdelegate negotiated_protocol(socket), to: Upstream
  @impl true
  defdelegate connection_information(socket), to: Upstream

  defp pop_snapshot_key(options) do
    {snapshot_key, reversed} =
      Enum.reduce(options, {nil, []}, fn
        {@snapshot_option, key}, {_previous, rest} -> {key, rest}
        option, {key, rest} -> {key, [option | rest]}
      end)

    {snapshot_key, Enum.reverse(reversed)}
  end

  defp paused_handshake(options, nil), do: options
  defp paused_handshake(options, _snapshot_key), do: [{:handshake, :hello} | options]

  defp register_snapshot(socket, nil), do: {:ok, socket}

  defp register_snapshot(socket, snapshot_key) do
    case :ssl.sockname(socket) do
      {:ok, {_ip, port}} ->
        :persistent_term.put({__MODULE__, :snapshot, port}, snapshot_key)
        {:ok, socket}

      {:error, reason} ->
        _closed = :ssl.close(socket)
        {:error, reason}
    end
  end

  defp certificate_options(socket) do
    with {:ok, {_ip, port}} <- :ssl.sockname(socket),
         snapshot_key when not is_nil(snapshot_key) <-
           :persistent_term.get({__MODULE__, :snapshot, port}, nil),
         [_option | _rest] = options <- Reloader.current_options(snapshot_key) do
      options
    else
      _no_published_snapshot -> []
    end
  end
end
