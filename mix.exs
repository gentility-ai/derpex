defmodule Derpex.MixProject do
  use Mix.Project

  @version "0.1.0-rc.2"
  @source_url "https://github.com/jtippett/derpex"

  # Kept byte-identical to the "Smoke relay benchmark harness" step in
  # .github/workflows/ci.yml; test/release_gate_test.exs compares the two.
  @benchmark_smoke "--packets 2000 --sizes 64,1200 --slow-packets 2000 --slow-delay-ms 50 " <>
                     "--fail-on queue_replacements=0 " <>
                     "--fail-on memory_delta_bytes=1048576 " <>
                     "--fail-on latency_p99_us=25000"

  def project do
    [
      app: :derpex,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      aliases: aliases(),
      releases: releases(),
      description: "A protocol-compatible DERP server for the Gentility overlay",
      source_url: @source_url
    ]
  end

  def application do
    [
      mod: {Derpex.Application, []},
      extra_applications: [:crypto, :logger, :public_key, :ssl]
    ]
  end

  def cli do
    [
      preferred_envs: [
        "artifact.check": :prod,
        bench: :dev,
        quality: :test,
        "test.diff": :test,
        "test.interop": :test,
        "test.system": :test,
        "test.all": :test,
        "release.check": :test
      ]
    ]
  end

  defp deps do
    [
      {:rustler, "~> 0.38.0", optional: true, runtime: false},
      {:rustler_precompiled, "~> 0.9.0", runtime: false},
      {:thousand_island, "~> 1.5.0"},
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false},
      {:stream_data, "~> 1.4.0", only: :test}
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_environment), do: ["lib"]

  defp aliases do
    [
      "artifact.check": [
        "release derpex --overwrite",
        "run --no-start scripts/verify_runtime.exs _build/prod/rel/derpex"
      ],
      bench: ["run bench/relay.exs"],
      "test.diff": ["test --include go_interop test/interop/differential_test.exs"],
      "test.interop": [
        "test --include go_interop --include rust_interop test/interop"
      ],
      quality: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "run --no-start scripts/dependency_closure.exs",
        "credo --strict",
        "cmd bash -n scripts/runtime_smoke.sh",
        "cmd rustfmt --check --edition 2024 interop/rust/client_smoke.rs",
        "cmd cargo fmt --manifest-path native/derpex_crypto/Cargo.toml -- --check",
        "cmd cargo clippy --manifest-path native/derpex_crypto/Cargo.toml --all-targets -- -D warnings"
      ],
      "test.system": ["test test/system --include system"],
      "test.all": [
        "test --include system --include go_interop --include rust_interop"
      ],
      # The local form of the release gate, so it runs what CI runs. The Rust
      # crate's own suite and the benchmark thresholds were workflow-only, which
      # made a pull request the first place a developer met them.
      "release.check": [
        "quality",
        "test.all",
        "cmd cargo test --locked --manifest-path native/derpex_crypto/Cargo.toml --all-targets",
        "cmd env MIX_ENV=dev mix bench -- " <> @benchmark_smoke,
        "cmd env MIX_ENV=prod mix artifact.check"
      ]
    ]
  end

  defp releases do
    [
      derpex: [
        include_executables_for: [:unix],
        strip_beams: Mix.env() == :prod,
        steps: [:assemble, &strip_build_only_release_files/1]
      ]
    ]
  end

  defp strip_build_only_release_files(release) do
    release.path
    |> Path.join("lib/rustler-*/priv/templates")
    |> Path.wildcard()
    |> Enum.each(&File.rm_rf!/1)

    release
  end
end
