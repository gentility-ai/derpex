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
        quality: :test,
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
      quality: [
        "format --check-formatted",
        "compile --warnings-as-errors",
        "credo --strict",
        "cmd cargo fmt --manifest-path native/derpex_crypto/Cargo.toml -- --check",
        "cmd cargo clippy --manifest-path native/derpex_crypto/Cargo.toml --all-targets -- -D warnings",
        "test"
      ],
      "test.all": ["test"],
      "release.check": ["quality", "test.all"]
    ]
  end

  defp releases do
    [
      derpex: [
        include_executables_for: [:unix],
        strip_beams: Mix.env() == :prod
      ]
    ]
  end
end
