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
    mesh_key_text = System.get_env("DERPEX_MESH_KEY")
    stun_port_text = System.get_env("DERPEX_STUN_PORT", "3478")

    mesh_key =
      case mesh_key_text do
        nil ->
          nil

        text ->
          text = String.trim(text)

          case Base.decode16(text, case: :mixed) do
            {:ok, <<mesh_key::binary-size(32)>>} -> mesh_key
            _invalid -> raise "DERPEX_MESH_KEY must be a 64-digit hexadecimal key"
          end
      end

    stun_port =
      case Integer.parse(stun_port_text) do
        {stun_port, ""} when stun_port in 1..65_535 -> stun_port
        _invalid -> raise "DERPEX_STUN_PORT must be an integer from 1 through 65535"
      end

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

    listener =
      if mesh_key do
        Keyword.put(listener, :handler_options, mesh_key: mesh_key)
      else
        listener
      end

    config :derpex,
      identity_path: identity_path,
      listeners: [listener],
      stun_listeners:
        if(System.get_env("DERPEX_STUN") == "0",
          do: [],
          else: [[port: stun_port]]
        )
  end
end
