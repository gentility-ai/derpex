import Config

if config_env() == :prod do
  config :logger, level: :info

  listen_port = System.get_env("DERPEX_LISTEN_PORT")

  if listen_port do
    port =
      case Integer.parse(listen_port) do
        {port, ""} when port in 1..65_535 -> port
        _invalid -> raise "DERPEX_LISTEN_PORT must be an integer from 1 through 65535"
      end

    identity_path =
      System.get_env("DERPEX_IDENTITY_PATH") ||
        raise "DERPEX_IDENTITY_PATH is required when a listener is enabled"

    certfile = System.get_env("DERPEX_TLS_CERTFILE")
    keyfile = System.get_env("DERPEX_TLS_KEYFILE")
    clear_http? = System.get_env("DERPEX_CLEAR_HTTP") == "1"

    listener =
      cond do
        certfile && keyfile ->
          [
            port: port,
            transport_module: ThousandIsland.Transports.SSL,
            transport_options: [
              certfile: certfile,
              keyfile: keyfile,
              versions: [:"tlsv1.3"],
              alpn_preferred_protocols: ["http/1.1"],
              send_timeout: 2_000,
              send_timeout_close: true
            ]
          ]

        clear_http? ->
          [
            port: port,
            transport_module: ThousandIsland.Transports.TCP,
            transport_options: [send_timeout: 2_000, send_timeout_close: true]
          ]

        true ->
          raise "set DERPEX_TLS_CERTFILE and DERPEX_TLS_KEYFILE, or explicitly opt into DERPEX_CLEAR_HTTP=1"
      end

    config :derpex,
      identity_path: identity_path,
      listeners: [listener]
  end
end
