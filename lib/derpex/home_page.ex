defmodule Derpex.HomePage do
  @moduledoc "Renders the DERP server home page."

  @doc "Renders the upstream homepage feature switches."
  @spec render(keyword()) :: binary()
  def render(options \\ []) do
    show_abuse_info? = Keyword.get(options, :show_abuse_info, false)
    disabled? = Keyword.get(options, :disabled, false)
    allow_debug? = Keyword.get(options, :allow_debug, false)

    """
    <html><body>
    <h1>DERP</h1>
    <p>
      This is a <a href="https://tailscale.com/">Tailscale</a> DERP server.
    </p>

    <p>
      It provides STUN, interactive connectivity establishment, and relaying of end-to-end encrypted traffic
      for Tailscale clients.
    </p>

    #{abuse_info(show_abuse_info?)}
    <p>
      Documentation:
    </p>

    <ul>
    #{abuse_links(show_abuse_info?)}
      <li><a href="https://tailscale.com/kb/1232/derp-servers">About DERP</a></li>
      <li><a href="https://pkg.go.dev/tailscale.com/derp">Protocol & Go docs</a></li>
      <li><a href="https://github.com/tailscale/tailscale/tree/main/cmd/derper#derp">How to run a DERP server</a></li>
    </ul>

    #{disabled_status(disabled?)}
    #{debug_link(allow_debug?)}
    </body>
    </html>
    """
  end

  defp abuse_info(false), do: ""

  defp abuse_info(true) do
    """
    <p>
      If you suspect abuse, please contact <a href="mailto:security@tailscale.com">security@tailscale.com</a>.
    </p>
    """
  end

  defp abuse_links(false), do: ""

  defp abuse_links(true) do
    """
      <li><a href="https://tailscale.com/security-policies">Tailscale Security Policies</a></li>
      <li><a href="https://tailscale.com/tailscale-aup">Tailscale Acceptable Use Policies</a></li>
    """
  end

  defp disabled_status(true), do: "<p>Status: <b>disabled</b></p>"
  defp disabled_status(false), do: ""

  defp debug_link(true), do: "<p>Debug info at <a href='/debug/'>/debug/</a>.</p>"
  defp debug_link(false), do: ""
end
