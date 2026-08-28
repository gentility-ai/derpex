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
    mesh_with_text = System.get_env("DERPEX_MESH_WITH")
    disallowed_app_names_text = System.get_env("DERPEX_DISALLOWED_APP_NAMES")
    rate_config_path = System.get_env("DERPEX_RATE_CONFIG")
    accept_limit_text = System.get_env("DERPEX_ACCEPT_CONNECTION_LIMIT")
    accept_burst_text = System.get_env("DERPEX_ACCEPT_CONNECTION_BURST")
    gentility_adapter_text = System.get_env("DERPEX_GENTILITY_ADAPTER")

    send_queue_depth_text =
      System.get_env("DERPEX_SEND_QUEUE_DEPTH") ||
        System.get_env("TS_DEBUG_DERP_PER_CLIENT_SEND_QUEUE_DEPTH")

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

    mesh_peers =
      case mesh_with_text do
        nil ->
          []

        text ->
          text
          |> String.split(",", trim: true)
          |> Enum.map(&String.trim/1)
          |> Enum.reject(&(&1 == ""))
          |> Enum.map(fn peer ->
            cond do
              String.starts_with?(peer, ["http://", "https://"]) ->
                [url: peer]

              true ->
                case String.split(peer, "/", parts: 2) do
                  [host] when host != "" ->
                    [url: "https://#{host}/derp"]

                  [host, dial_host] when host != "" and dial_host != "" ->
                    [url: "https://#{host}/derp", dial_host: dial_host]

                  _invalid ->
                    raise "DERPEX_MESH_WITH contains an invalid peer: #{inspect(peer)}"
                end
            end
          end)
      end

    if mesh_peers != [] and is_nil(mesh_key) do
      raise "DERPEX_MESH_KEY is required when DERPEX_MESH_WITH is set"
    end

    send_queue_depth =
      case Derpex.SendQueueConfig.parse(send_queue_depth_text) do
        {:ok, depth} -> depth
        {:error, _reason} -> raise "DERPEX_SEND_QUEUE_DEPTH must be a positive integer"
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

    gentility =
      case gentility_adapter_text do
        nil ->
          nil

        adapter_text ->
          module_name =
            if String.starts_with?(adapter_text, "Elixir."),
              do: adapter_text,
              else: "Elixir." <> adapter_text

          adapter =
            try do
              String.to_existing_atom(module_name)
            rescue
              ArgumentError ->
                raise "DERPEX_GENTILITY_ADAPTER must name a module included in the release"
            end

          unless Code.ensure_loaded?(adapter) do
            raise "DERPEX_GENTILITY_ADAPTER must name a module included in the release"
          end

          verification_keys_text =
            System.get_env("DERPEX_GENTILITY_VERIFY_KEYS") ||
              raise "DERPEX_GENTILITY_VERIFY_KEYS is required with DERPEX_GENTILITY_ADAPTER"

          verification_keys =
            verification_keys_text
            |> String.split(",", trim: true)
            |> Enum.map(fn entry ->
              case String.split(entry, ":", parts: 2) do
                [key_id, encoded] when key_id != "" and byte_size(key_id) <= 64 ->
                  decoded =
                    case Base.decode64(encoded) do
                      {:ok, key} -> {:ok, key}
                      :error -> Base.url_decode64(encoded, padding: false)
                    end

                  case decoded do
                    {:ok, <<key::binary-size(32)>>} -> {key_id, key}
                    _invalid -> raise "DERPEX_GENTILITY_VERIFY_KEYS contains an invalid key"
                  end

                _invalid ->
                  raise "DERPEX_GENTILITY_VERIFY_KEYS must contain key-id:base64 pairs"
              end
            end)
            |> Map.new()

          if map_size(verification_keys) == 0 or map_size(verification_keys) > 16 do
            raise "DERPEX_GENTILITY_VERIFY_KEYS must contain between one and sixteen keys"
          end

          cache_path =
            System.get_env("DERPEX_GENTILITY_CACHE_PATH") ||
              raise "DERPEX_GENTILITY_CACHE_PATH is required with DERPEX_GENTILITY_ADAPTER"

          spool_path =
            System.get_env("DERPEX_GENTILITY_USAGE_SPOOL_PATH") ||
              raise "DERPEX_GENTILITY_USAGE_SPOOL_PATH is required with DERPEX_GENTILITY_ADAPTER"

          instance_id =
            System.get_env("DERPEX_GENTILITY_INSTANCE_ID") ||
              raise "DERPEX_GENTILITY_INSTANCE_ID is required with DERPEX_GENTILITY_ADAPTER"

          region_text =
            System.get_env("DERPEX_GENTILITY_REGION_ID") ||
              raise "DERPEX_GENTILITY_REGION_ID is required with DERPEX_GENTILITY_ADAPTER"

          region_id =
            case Integer.parse(region_text) do
              {value, ""} when value in 0..0xFFFF_FFFF -> value
              _invalid -> raise "DERPEX_GENTILITY_REGION_ID must be an unsigned 32-bit integer"
            end

          events =
            if System.get_env("DERPEX_GENTILITY_EVENTS") == "0",
              do: nil,
              else: [adapter: adapter]

          [
            authority: adapter,
            verification_keys: verification_keys,
            cache_path: cache_path,
            usage: [
              instance_id: instance_id,
              region_id: region_id,
              spool_path: spool_path,
              exporter: adapter
            ],
            events: events
          ]
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
      [send_queue_depth: send_queue_depth]
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
      gentility: gentility,
      identity_path: identity_path,
      listeners: [listener],
      mesh_key: mesh_key,
      mesh_peers: mesh_peers,
      rate_config_path: rate_config_path,
      stun_listeners:
        if(System.get_env("DERPEX_STUN") == "0",
          do: [],
          else: [[port: stun_port]]
        )
  end
end
