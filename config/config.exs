import Config

config :derpex,
  accept_limit: nil,
  bootstrap_dns: [],
  clock: Derpex.Clock.System,
  gentility: nil,
  identity_path: nil,
  listeners: [],
  mesh_key: nil,
  mesh_peers: [],
  rate_config_path: nil,
  shutdown: [deadline_ms: 30_000, poll_ms: 25],
  stun_listeners: [],
  native_base_url:
    System.get_env(
      "DERPEX_NATIVE_BASE_URL",
      "https://github.com/jtippett/derpex/releases/download"
    )
