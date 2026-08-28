defmodule Derpex.Transport.ThousandIsland do
  @moduledoc "Thousand Island socket adapter for native TCP and TLS streams."

  @behaviour Derpex.Transport

  alias ThousandIsland.Socket

  @impl true
  defdelegate send(socket, data), to: Socket

  @impl true
  defdelegate close(socket), to: Socket

  @impl true
  defdelegate peername(socket), to: Socket

  @impl true
  def secure?(socket), do: Socket.secure?(socket)
end
