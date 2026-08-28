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
    disallowed_app_names_text = System.get_env("DERPEX_DISALLOWED_APP_NAMES")
    rate_config_path = System.get_env("DERPEX_RATE_CONFIG")
    accept_limit_text = System.get_env("DERPEX_ACCEPT_CONNECTION_LIMIT")
    accept_burst_text = System.get_env("DERPEX_ACCEPT_CONNECTION_BURST")
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

    accept_limit =
      case {accept_limit_text, accept_burst_text} do
        {nil, nil} ->
          nil

        {limit_text, burst_text} when is_binary(limit_text) and is_binary(burst_text) ->
          with {limit, ""} when limit >= 0 <- Float.parse(limit_text),
               {burst, ""} when burst > 0 <- Integer.parse(burst_text) do
            {limit, burst}
          else
            _invalid ->
              raise "DERPEX_ACCEPT_CONNECTION_LIMIT and DERPEX_ACCEPT_CONNECTION_BURST must be non-negative rate and positive integer burst"
          end

        _incomplete ->
          raise "set both DERPEX_ACCEPT_CONNECTION_LIMIT and DERPEX_ACCEPT_CONNECTION_BURST"
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

    disallowed_app_names =
      case disallowed_app_names_text do
        nil -> []
        "" -> []
        names -> String.split(names, ",", trim: false)
      end

    handler_options =
      []
      |> then(fn options ->
        if mesh_key, do: Keyword.put(options, :mesh_key, mesh_key), else: options
      end)
      |> then(fn options ->
        if disallowed_app_names == [] do
          options
        else
          Keyword.put(options, :disallowed_app_names, disallowed_app_names)
        end
      end)

    listener =
      if handler_options == [],
        do: listener,
        else: Keyword.put(listener, :handler_options, handler_options)

    config :derpex,
      accept_limit: accept_limit,
      identity_path: identity_path,
      listeners: [listener],
      rate_config_path: rate_config_path,
      stun_listeners:
        if(System.get_env("DERPEX_STUN") == "0",
          do: [],
          else: [[port: stun_port]]
        )
  end
end
