defmodule Derpex.RuntimeVerifier do
  @forbidden_directories ~w(_build deps interop native test)
  @forbidden_executables ~w(cargo go gofmt rustc rustup)
  @forbidden_extensions ~w(.go .rs)

  def main([root]) do
    root = Path.expand(root)

    unless File.dir?(root) do
      abort("runtime root does not exist: #{root}")
    end

    reject_directories!(root)
    reject_files!(root)
    require_release!(root)
    IO.puts("runtime boundary verified: #{root}")
  end

  def main(_args), do: abort("usage: elixir scripts/verify_runtime.exs RELEASE_ROOT")

  defp reject_directories!(root) do
    present =
      Enum.filter(@forbidden_directories, fn directory ->
        File.exists?(Path.join(root, directory))
      end)

    if present != [], do: abort("forbidden runtime directories: #{Enum.join(present, ", ")}")
  end

  defp reject_files!(root) do
    forbidden =
      root
      |> Path.join("**/*")
      |> Path.wildcard(match_dot: true)
      |> Enum.filter(&File.regular?/1)
      |> Enum.filter(fn path ->
        Path.basename(path) in @forbidden_executables or
          Path.extname(path) in @forbidden_extensions
      end)

    if forbidden != [] do
      abort("forbidden runtime files:\n#{Enum.map_join(forbidden, "\n", &"  #{&1}")}")
    end
  end

  defp require_release!(root) do
    executable = Path.join([root, "bin", "derpex"])
    nif_pattern = Path.join([root, "lib", "derpex-*", "priv", "native", "derpex_crypto.so"])

    unless File.regular?(executable), do: abort("release executable is missing: #{executable}")
    unless Path.wildcard(nif_pattern) != [], do: abort("precompiled crypto NIF is missing")
  end

  defp abort(message) do
    IO.puts(:stderr, message)
    System.halt(1)
  end
end

Derpex.RuntimeVerifier.main(System.argv())
