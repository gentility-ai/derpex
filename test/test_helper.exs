# System tests are opted into by `mix test.system`; the interop suites need the
# pinned upstream checkouts. All three stay excluded unless explicitly asked
# for, so a plain `mix test` is the fast unit and property suite.
exclude =
  [:system]
  |> then(fn tags ->
    if System.get_env("DERPEX_GO_INTEROP") == "1", do: tags, else: [:go_interop | tags]
  end)
  |> then(fn tags ->
    if System.get_env("DERPEX_RUST_INTEROP") == "1", do: tags, else: [:rust_interop | tags]
  end)

ExUnit.start(exclude: exclude)
