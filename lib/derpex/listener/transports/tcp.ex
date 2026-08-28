defmodule Derpex.Listener.Transports.TCP do
  @moduledoc false

  @behaviour ThousandIsland.Transport

  alias Derpex.Listener.Transports.Options
  alias ThousandIsland.Transports.TCP, as: Upstream

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

    options =
      Enum.sort(options, fn
        _, {:inet_backend, _} -> false
        _, _ -> true
      end)

    :gen_tcp.listen(port, options)
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
