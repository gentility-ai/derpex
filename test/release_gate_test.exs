defmodule Derpex.ReleaseGateTest do
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @ci Path.join(@root, ".github/workflows/ci.yml")
  @release Path.join(@root, ".github/workflows/release.yml")
  @nightly Path.join(@root, ".github/workflows/nightly.yml")
  @test_helper Path.join(@root, "test/test_helper.exs")
  @manifest_step "Require a published checksum manifest on a stable tag"
  @manifest "checksum-Elixir.Derpex.Crypto.Native.exs"

  describe "mix aliases" do
    setup do
      {:ok, aliases: Mix.Project.config()[:aliases]}
    end

    test "quality is a fast pre-commit gate that never runs the suite", %{aliases: aliases} do
      steps = Keyword.fetch!(aliases, :quality)

      refute "test" in steps
      refute Enum.any?(steps, &String.starts_with?(&1, "test "))
      assert "format --check-formatted" in steps
      assert "compile --warnings-as-errors" in steps
      assert "credo --strict" in steps
    end

    test "test.all opts every tagged gate back in", %{aliases: aliases} do
      assert ["test --include system --include go_interop --include rust_interop"] =
               Keyword.fetch!(aliases, :"test.all")
    end

    test "test.system runs the system suite directory", %{aliases: aliases} do
      assert ["test test/system --include system"] = Keyword.fetch!(aliases, :"test.system")
      assert Path.wildcard(Path.join(@root, "test/system/**/*_test.exs")) != []
    end

    test "release.check is quality plus test.all plus artifact.check", %{aliases: aliases} do
      steps = Keyword.fetch!(aliases, :"release.check")

      assert "quality" in steps
      assert "test.all" in steps
      assert Enum.any?(steps, &(&1 =~ "artifact.check"))
      assert Enum.any?(steps, &(&1 =~ "MIX_ENV=prod"))
    end

    test "release.check runs the Rust crate's own suite as CI does", %{aliases: aliases} do
      step =
        aliases
        |> Keyword.fetch!(:"release.check")
        |> Enum.find(&(&1 =~ "cargo test"))

      assert step, "release.check does not run cargo test"
      assert step =~ "--locked"
      assert step =~ "--manifest-path native/derpex_crypto/Cargo.toml"

      workflow = Map.fetch!(jobs(@ci), "quality")
      assert workflow =~ String.replace_prefix(step, "cmd ", "")
    end

    test "release.check enforces the benchmark thresholds CI enforces", %{aliases: aliases} do
      step =
        aliases
        |> Keyword.fetch!(:"release.check")
        |> Enum.find(&(&1 =~ "mix bench"))

      assert step, "release.check does not run the benchmark"

      thresholds = fail_on(step)
      refute thresholds == [], "the benchmark step sets no --fail-on threshold"

      assert thresholds == fail_on(Map.fetch!(jobs(@ci), "quality")),
             "release.check and the CI benchmark smoke disagree on --fail-on thresholds"
    end
  end

  describe "nightly workflow" do
    setup do
      {:ok, nightly: File.read!(@nightly), job: Map.fetch!(jobs(@nightly), "deep")}
    end

    test "runs on a schedule rather than on pushes", %{nightly: nightly} do
      assert nightly =~ ~r/^  schedule:$/m
      assert nightly =~ ~r/^    - cron: "[^"]+"$/m
      refute nightly =~ ~r/^  (push|pull_request):$/m
    end

    test "widens the property search well past a pull request's", %{job: job} do
      assert job =~ ~r/PROPERTY_RUNS: "5000"/
      assert job =~ ~r/run: mix test test\/property$/m
    end

    test "runs the benchmark against the same thresholds CI uses", %{job: job} do
      assert fail_on(job) == fail_on(Map.fetch!(jobs(@ci), "quality"))
    end

    test "runs the system suite", %{job: job} do
      assert job =~ ~r/run: mix test\.system$/m
    end
  end

  describe "the system suite" do
    test "sits outside a plain mix test" do
      assert :system in ExUnit.configuration()[:exclude]
      assert File.read!(@test_helper) =~ "[:system]"
    end

    test "carries the tag on every file so it stays excluded" do
      for file <- Path.wildcard(Path.join(@root, "test/system/**/*_test.exs")) do
        assert File.read!(file) =~ "@moduletag :system", "#{file} is missing @moduletag :system"
      end
    end
  end

  describe "continuous integration workflow" do
    test "is callable as a reusable workflow" do
      assert File.read!(@ci) =~ ~r/^  workflow_call:$/m
    end

    test "leaves release tags to the release workflow gate" do
      assert File.read!(@ci) =~ ~r/^    tags-ignore:\n      - "v\*"$/m
    end

    test "still runs the unit suite now that quality does not" do
      quality = Map.fetch!(jobs(@ci), "quality")

      assert quality =~ ~r/^        run: mix test$/m
    end
  end

  describe "release workflow" do
    test "gate job calls the full continuous integration workflow" do
      gate = Map.fetch!(jobs(@release), "gate")

      assert gate =~ "uses: ./.github/workflows/ci.yml"
      assert needs(gate) == []
    end

    test "every building and publishing job depends on the gate" do
      jobs = jobs(@release)

      gated = Map.drop(jobs, ["gate", "version"])
      assert map_size(gated) >= 5

      for {name, body} <- gated do
        assert "gate" in needs(body), "release job #{name} does not depend on the gate"
      end
    end
  end

  describe "the empty-checksum-manifest gate" do
    setup do
      {:ok, script: step_script(Map.fetch!(jobs(@release), "version"), @manifest_step)}
    end

    test "refuses an empty manifest on a stable tag", %{script: script} do
      assert {status, output} = run_gate(script, "refs/tags/v1.4.0", "1.4.0", "%{}\n")

      assert status != 0
      assert output =~ "checksum-Elixir.Derpex.Crypto.Native.exs"
    end

    test "accepts an empty manifest on a prerelease tag", %{script: script} do
      assert {0, output} = run_gate(script, "refs/tags/v1.4.0-rc.1", "1.4.0-rc.1", "%{}\n")

      assert output =~ "source"
    end

    test "accepts a populated manifest on a stable tag", %{script: script} do
      manifest =
        ~s(%{\n  "libderpex_crypto-v1.4.0-nif-2.15-x86_64-unknown-linux-gnu.so.tar.gz" =>\n    "sha256:abc"\n})

      assert {0, _output} = run_gate(script, "refs/tags/v1.4.0", "1.4.0", manifest)
    end

    test "leaves a manual dispatch off a tag ungated", %{script: script} do
      assert {0, _output} = run_gate(script, "refs/heads/main", "1.4.0", "%{}\n")
    end
  end

  describe "the workflow parser" do
    test "reads scalar, inline, and block dependency lists" do
      path =
        Path.join(System.tmp_dir!(), "derpex-needs-#{System.unique_integer([:positive])}.yml")

      on_exit(fn -> File.rm_rf!(path) end)

      File.write!(path, """
      jobs:
        gate:
          name: Gate
        scalar:
          needs: gate
        inline:
          needs: [gate, version]
        block:
          needs:
            - gate
            - version
          runs-on: ubuntu-24.04
      """)

      parsed = jobs(path)

      assert needs(parsed["gate"]) == []
      assert needs(parsed["scalar"]) == ["gate"]
      assert needs(parsed["inline"]) == ["gate", "version"]
      assert needs(parsed["block"]) == ["gate", "version"]
    end
  end

  # Every `--fail-on NAME=VALUE` in a block of text, sorted, so a Mix alias and
  # a workflow step can be compared without depending on their argument order
  # or on how each one wraps its lines.
  defp fail_on(text) do
    ~r/--fail-on\s+([a-z_]+=\d+)/
    |> Regex.scan(text)
    |> Enum.map(&List.last/1)
    |> Enum.sort()
  end

  # Runs one workflow step's shell body the way Actions does (`bash -e`), in a
  # scratch directory holding the manifest under test, so the gate is exercised
  # rather than merely grepped for.
  defp run_gate(script, github_ref, version, manifest) do
    directory = Path.join(System.tmp_dir!(), "derpex-gate-#{System.unique_integer([:positive])}")
    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)

    File.write!(Path.join(directory, @manifest), manifest)
    File.write!(Path.join(directory, "step.sh"), script)

    {output, status} =
      System.cmd("bash", ["-e", "step.sh"],
        cd: directory,
        stderr_to_stdout: true,
        env: [{"GITHUB_REF", github_ref}, {"VERSION", version}]
      )

    {status, output}
  end

  # Extracts a named step's `run: |` body from a job, dedented so it runs
  # standalone. Requires the step to interpolate nothing: `${{ }}` belongs in
  # the step's `env:` block so the body stays executable outside Actions.
  defp step_script(job, name) do
    lines =
      job
      |> String.split("\n")
      |> Enum.drop_while(&(String.trim(&1) != "- name: " <> name))
      |> Enum.drop(1)
      |> Enum.take_while(&(not String.starts_with?(String.trim(&1), "- name:")))
      |> Enum.drop_while(&(String.trim(&1) != "run: |"))
      |> Enum.drop(1)

    assert lines != [], "the version job has no `run: |` step named #{inspect(name)}"

    refute Enum.any?(lines, &String.contains?(&1, "${{")),
           "step #{inspect(name)} interpolates in its body, so it cannot be run or tested alone"

    dedent(lines)
  end

  defp dedent(lines) do
    indent =
      lines
      |> Enum.reject(&(String.trim(&1) == ""))
      |> Enum.map(&(byte_size(&1) - byte_size(String.trim_leading(&1))))
      |> Enum.min()

    Enum.map_join(lines, "\n", &String.slice(&1, indent..-1//1))
  end

  # `jobs/1` and `needs/1` are deliberately minimal: they read job names and
  # their dependencies out of these two workflow files rather than being a
  # general YAML parser, so the suite needs no YAML dependency. They assume the
  # repository's two-space job indentation and normal `mix format`-style YAML.
  defp jobs(path) do
    path
    |> File.read!()
    |> String.split("\n")
    |> Enum.drop_while(&(&1 != "jobs:"))
    |> Enum.reduce({nil, %{}}, fn line, {current, acc} ->
      case Regex.run(~r/^  ([a-zA-Z0-9_-]+):$/, line) do
        [_, name] -> {name, Map.put(acc, name, [])}
        nil when is_binary(current) -> {current, Map.update!(acc, current, &[line | &1])}
        nil -> {current, acc}
      end
    end)
    |> then(fn {_current, acc} ->
      Map.new(acc, fn {name, lines} -> {name, lines |> Enum.reverse() |> Enum.join("\n")} end)
    end)
  end

  # Accepts `needs: version`, `needs: [gate, version]`, and the block form
  # where each dependency sits on its own `      - name` line.
  defp needs(body) do
    body
    |> String.split("\n")
    |> Enum.split_while(&(not String.starts_with?(&1, "    needs:")))
    |> case do
      {_before, []} ->
        []

      {_before, [line | rest]} ->
        case line |> String.replace_prefix("    needs:", "") |> String.trim() do
          "" -> block_items(rest)
          inline -> inline |> String.trim("[") |> String.trim("]") |> split_names()
        end
    end
  end

  defp block_items(lines) do
    lines
    |> Enum.take_while(&(String.trim_leading(&1) =~ ~r/^- \S/))
    |> Enum.map(&block_item/1)
  end

  defp block_item(line) do
    line |> String.trim_leading() |> String.replace_prefix("- ", "") |> String.trim()
  end

  defp split_names(value) do
    value |> String.split(",") |> Enum.map(&String.trim/1) |> Enum.reject(&(&1 == ""))
  end
end
