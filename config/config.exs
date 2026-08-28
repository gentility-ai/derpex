import Config

config :derpex,
  clock: Derpex.Clock.System,
  identity_path: nil,
  listeners: [],
  native_base_url:
    System.get_env(
      "DERPEX_NATIVE_BASE_URL",
      "https://github.com/jtippett/derpex/releases/download"
    )
