import Config

config :derpex,
  accept_limit: nil,
  bootstrap_dns: [],
  clock: Derpex.Clock.System,
  identity_path: nil,
  listeners: [],
  mesh_key: nil,
  mesh_peers: [],
  rate_config_path: nil,
  stun_listeners: [],
  native_base_url:
    System.get_env(
      "DERPEX_NATIVE_BASE_URL",
      "https://github.com/jtippett/derpex/releases/download"
    )
