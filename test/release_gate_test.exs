defmodule Derpex.ReleaseGateTest do
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @ci Path.join(@root, ".github/workflows/ci.yml")
  @release Path.join(@root, ".github/workflows/release.yml")
  @test_helper Path.join(@root, "test/test_helper.exs")

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
