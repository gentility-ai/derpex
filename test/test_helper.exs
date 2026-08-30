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

# `test/property/**` runs on every `mix test`; nightly builds widen the search
# with PROPERTY_RUNS (StreamData's per-property run count, 100 by default).
property_runs =
  case Integer.parse(System.get_env("PROPERTY_RUNS", "100")) do
    {runs, ""} when runs > 0 -> runs
    _other -> raise "PROPERTY_RUNS must be a positive integer"
  end

Application.put_env(:stream_data, :max_runs, property_runs)

ExUnit.start(exclude: exclude)
