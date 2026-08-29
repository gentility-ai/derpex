defmodule Derpex.MixProject do
  use Mix.Project

  @version "0.1.0-dev"
  @source_url "https://github.com/jtippett/derpex"

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
      {:credo, "~> 1.7", only: [:dev, :test], runtime: false}
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
        "credo --strict",
        "cmd bash -n scripts/runtime_smoke.sh",
        "cmd rustfmt --check --edition 2024 interop/rust/client_smoke.rs",
        "cmd cargo fmt --manifest-path native/derpex_crypto/Cargo.toml -- --check",
        "cmd cargo clippy --manifest-path native/derpex_crypto/Cargo.toml --all-targets -- -D warnings"
      ],
      "test.system": [&test_system/1],
      "test.all": ["test --include go_interop --include rust_interop"],
      "release.check": [
        "quality",
        "test.all",
        "cmd env MIX_ENV=prod mix artifact.check"
      ]
    ]
  end

  @system_test_root "test/system"

  # `mix test` refuses a directory holding no `*_test.exs`, so the system suite
  # reports an empty run instead of failing the release gate before the first
  # system test lands.
  defp test_system(arguments) do
    case Path.wildcard(Path.join(@system_test_root, "**/*_test.exs")) do
      [] ->
        Mix.shell().info("mix test.system: no #{@system_test_root}/**/*_test.exs yet")

      _files ->
        Mix.Task.run("test", [@system_test_root | arguments])
    end
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
