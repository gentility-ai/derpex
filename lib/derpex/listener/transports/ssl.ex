defmodule Derpex.Listener.Transports.SSL do
  @moduledoc false

  @behaviour ThousandIsland.Transport

  alias Derpex.Listener.Transports.Options
  alias ThousandIsland.Transports.SSL, as: Upstream

  @certificate_options [:certs_keys, :keyfile, :key, :sni_hosts, :sni_fun]
  @public_certificate_options [:certs_keys, :certfile, :cert, :sni_hosts, :sni_fun]

  @impl true
  def listen(port, user_options) do
    options =
      Options.resolve(user_options,
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

    :ssl.listen(port, options)
  end

  @impl true
  defdelegate accept(socket), to: Upstream
  @impl true
  defdelegate handshake(socket), to: Upstream
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
end
