defmodule Derpex.ReleaseGateTest do
  use ExUnit.Case, async: true

  @root Path.expand("..", __DIR__)
  @ci Path.join(@root, ".github/workflows/ci.yml")
  @release Path.join(@root, ".github/workflows/release.yml")

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
      assert ["test --include go_interop --include rust_interop"] =
               Keyword.fetch!(aliases, :"test.all")
    end

    test "test.system runs the system suite directory", %{aliases: aliases} do
      assert [runner] = Keyword.fetch!(aliases, :"test.system")
      assert is_function(runner, 1)
      assert File.dir?(Path.join(@root, "test/system"))
    end

    test "release.check is quality plus test.all plus artifact.check", %{aliases: aliases} do
      steps = Keyword.fetch!(aliases, :"release.check")

      assert "quality" in steps
      assert "test.all" in steps
      assert Enum.any?(steps, &(&1 =~ "artifact.check"))
      assert Enum.any?(steps, &(&1 =~ "MIX_ENV=prod"))
    end
  end

  describe "continuous integration workflow" do
    test "is callable as a reusable workflow" do
      assert File.read!(@ci) =~ ~r/^  workflow_call:$/m
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

  defp needs(body) do
    case Regex.run(~r/^    needs:\s*(.+)$/m, body) do
      nil ->
        []

      [_, value] ->
        value
        |> String.trim()
        |> String.trim_leading("[")
        |> String.trim_trailing("]")
        |> String.split(",")
        |> Enum.map(&String.trim/1)
    end
  end
end
