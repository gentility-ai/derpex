# Holds the release's runtime application closure to an explicit allowlist.
#
# The pinned Go `TestDeps` asserts that `cmd/derper`'s dependency graph never
# grows a package it has no business linking. This is the same assertion for
# the DERPEX release: the set of OTP applications the running relay loads is
# fixed, so a new dependency — or a build-only one that quietly becomes a
# runtime one — fails `mix quality` instead of reaching a production image.
#
# Run as: mix run --no-start scripts/dependency_closure.exs
defmodule Derpex.DependencyClosure do
  @moduledoc false

  # Every OTP application the release is allowed to load at runtime.
  @allowed MapSet.new([
             :asn1,
             :compiler,
             :crypto,
             :derpex,
             :elixir,
             :kernel,
             :logger,
             :public_key,
             :ssl,
             :stdlib,
             :telemetry,
             :thousand_island
           ])

  def main do
    closure = Enum.reduce(roots(), MapSet.new([:derpex]), &close/2)
    unexpected = closure |> MapSet.difference(@allowed) |> Enum.sort()
    unused = @allowed |> MapSet.difference(closure) |> Enum.sort()

    cond do
      unexpected != [] ->
        abort(
          "the release would load applications outside the allowlist: " <>
            "#{Enum.join(unexpected, ", ")}. Add them to scripts/dependency_closure.exs " <>
            "only with a reason to ship them."
        )

      unused != [] ->
        abort(
          "the allowlist in scripts/dependency_closure.exs names applications the " <>
            "release no longer loads: #{Enum.join(unused, ", ")}. Remove them."
        )

      true ->
        IO.puts("runtime application closure: #{closure |> Enum.sort() |> Enum.join(", ")}")
    end
  end

  # `derpex.app` lists whatever the current MIX_ENV pulled in, so a test-only
  # dependency would be read as a runtime one. The roots therefore come from
  # the project definition: the declared extra applications plus the
  # dependencies that are neither `runtime: false` nor restricted to dev/test.
  defp roots do
    project = Mix.Project.get!()
    extra = Keyword.get(project.application(), :extra_applications, [])
    dependencies = Enum.filter(Mix.Project.config()[:deps], &runtime_dependency?/1)

    [:kernel, :stdlib, :elixir] ++ extra ++ Enum.map(dependencies, &elem(&1, 0))
  end

  defp runtime_dependency?(dependency) do
    # A dependency is `{app, requirement}`, `{app, options}` or
    # `{app, requirement, options}`; only the trailing list is options.
    options =
      case dependency |> Tuple.to_list() |> List.last() do
        options when is_list(options) -> options
        _requirement -> []
      end

    Keyword.get(options, :runtime, true) != false and
      environments(Keyword.get(options, :only))
  end

  defp environments(nil), do: true
  defp environments(only), do: :prod in List.wrap(only)

  defp close(application, seen) do
    if MapSet.member?(seen, application) do
      seen
    else
      _loaded = Application.load(application)
      seen = MapSet.put(seen, application)

      Enum.reduce(dependencies(application), seen, &close/2)
    end
  end

  defp dependencies(application) do
    (Application.spec(application, :applications) || []) ++
      (Application.spec(application, :included_applications) || [])
  end

  defp abort(message) do
    IO.puts(:stderr, message)
    System.halt(1)
  end
end

Derpex.DependencyClosure.main()
