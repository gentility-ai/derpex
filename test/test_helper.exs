exclude =
  []
  |> then(fn tags ->
    if System.get_env("DERPEX_GO_INTEROP") == "1", do: tags, else: [:go_interop | tags]
  end)
  |> then(fn tags ->
    if System.get_env("DERPEX_RUST_INTEROP") == "1", do: tags, else: [:rust_interop | tags]
  end)

ExUnit.start(exclude: exclude)
