defmodule Derpex.NativeManifest do
  @targets ~w(
    aarch64-apple-darwin
    x86_64-apple-darwin
    aarch64-unknown-linux-gnu
    x86_64-unknown-linux-gnu
  )

  def main(args) do
    {options, positional, invalid} =
      OptionParser.parse(args, strict: [output: :string], aliases: [o: :output])

    case {positional, invalid, options[:output]} do
      {[version, directory], [], output} when is_binary(output) ->
        entries = entries!(version, directory)
        File.write!(output, encode(entries))
        IO.puts("wrote #{output}")

      _other ->
        abort("usage: elixir scripts/native_manifest.exs VERSION DIRECTORY --output PATH")
    end
  end

  defp entries!(version, directory) do
    expected =
      Map.new(@targets, fn target ->
        filename = "libderpex_crypto-v#{version}-nif-2.15-#{target}.so.tar.gz"
        {filename, Path.join(directory, filename)}
      end)

    missing = Enum.reject(expected, fn {_filename, path} -> File.regular?(path) end)

    if missing != [] do
      abort("missing native archives: #{Enum.map_join(missing, ", ", &elem(&1, 0))}")
    end

    expected
    |> Enum.map(fn {filename, path} ->
      digest = sha256(path)
      {filename, "sha256:" <> digest}
    end)
    |> Enum.sort()
  end

  defp sha256(path) do
    context =
      path
      |> File.stream!(1_048_576, [])
      |> Enum.reduce(:crypto.hash_init(:sha256), &:crypto.hash_update(&2, &1))

    context
    |> :crypto.hash_final()
    |> Base.encode16(case: :lower)
  end

  defp encode(entries) do
    body =
      Enum.map_join(entries, ",\n", fn {filename, digest} ->
        "  #{inspect(filename)} => #{inspect(digest)}"
      end)

    "%{\n#{body},\n}\n"
  end

  defp abort(message) do
    IO.puts(:stderr, message)
    System.halt(1)
  end
end

Derpex.NativeManifest.main(System.argv())
