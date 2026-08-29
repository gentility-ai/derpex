defmodule Derpex.AtomicFileTest do
  use ExUnit.Case, async: true

  alias Derpex.AtomicFile

  @tag :tmp_dir
  test "creates a private parent directory and a 0600 file with no leftovers", %{
    tmp_dir: tmp_dir
  } do
    path = Path.join([tmp_dir, "nested", "secret.key"])

    assert AtomicFile.write(path, "payload") == :ok
    assert File.read!(path) == "payload"
    assert file_mode(path) == 0o600
    assert file_mode(Path.dirname(path)) == 0o700
    assert temporary_files(Path.dirname(path)) == []
  end

  @tag :tmp_dir
  test "honours an explicit file mode for public artifacts", %{tmp_dir: tmp_dir} do
    path = Path.join([tmp_dir, "certificates", "server.crt"])

    assert AtomicFile.write(path, "-----BEGIN CERTIFICATE-----", mode: 0o644) == :ok
    assert file_mode(path) == 0o644
    assert file_mode(Path.dirname(path)) == 0o700
    assert temporary_files(Path.dirname(path)) == []
  end

  @tag :tmp_dir
  test "replaces an existing file atomically and restores its mode", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "secret.key")

    :ok = File.write(path, "old")
    :ok = File.chmod(path, 0o644)

    assert AtomicFile.write(path, "new") == :ok
    assert File.read!(path) == "new"
    assert file_mode(path) == 0o600
    assert temporary_files(tmp_dir) == []
  end

  @tag :tmp_dir
  test "leaves no temporary file behind when the destination is a directory", %{
    tmp_dir: tmp_dir
  } do
    path = Path.join(tmp_dir, "occupied")
    :ok = File.mkdir_p(path)

    assert {:error, _reason} = AtomicFile.write(path, "payload")
    assert temporary_files(tmp_dir) == []
  end

  @tag :tmp_dir
  test "never tightens a directory it did not create", %{tmp_dir: tmp_dir} do
    shared = Path.join(tmp_dir, "shared")
    :ok = File.mkdir_p(shared)
    :ok = File.chmod(shared, 0o755)

    assert AtomicFile.write(Path.join(shared, "secret.key"), "payload") == :ok
    assert file_mode(shared) == 0o755
    assert file_mode(Path.join(shared, "secret.key")) == 0o600

    created = Path.join(shared, "issued")
    assert AtomicFile.write(Path.join(created, "secret.key"), "payload") == :ok
    assert file_mode(created) == 0o700
    assert file_mode(shared) == 0o755
  end

  @tag :tmp_dir
  test "reports directory failures distinctly from open failures", %{tmp_dir: tmp_dir} do
    blocker = Path.join(tmp_dir, "blocker")
    :ok = File.write(blocker, "not a directory")

    assert {:error, {:mkdir, _reason}} =
             AtomicFile.write(Path.join([blocker, "nested", "secret.key"]), "payload")
  end

  @tag :tmp_dir
  test "picks an unused temporary name and removes only its own", %{tmp_dir: tmp_dir} do
    path = Path.join(tmp_dir, "secret.key")
    foreign = path <> ".tmp.1.AAAAAAAAAAA"
    :ok = File.write(foreign, "someone else's temporary file")

    assert AtomicFile.write(path, "payload") == :ok
    assert File.read!(path) == "payload"
    assert File.read!(foreign) == "someone else's temporary file"
    assert temporary_files(tmp_dir) == [Path.basename(foreign)]
  end

  @tag :tmp_dir
  test "concurrent writers converge on one file with no leftovers", %{tmp_dir: tmp_dir} do
    path = Path.join([tmp_dir, "concurrent", "secret.key"])

    results =
      1..25
      |> Task.async_stream(fn index -> AtomicFile.write(path, "payload-#{index}") end,
        max_concurrency: 25,
        ordered: false
      )
      |> Enum.map(fn {:ok, result} -> result end)

    assert Enum.uniq(results) == [:ok]
    assert File.read!(path) =~ "payload-"
    assert file_mode(path) == 0o600
    assert temporary_files(Path.dirname(path)) == []
  end

  defp file_mode(path) do
    {:ok, stat} = File.stat(path)
    Bitwise.band(stat.mode, 0o777)
  end

  defp temporary_files(directory) do
    directory
    |> File.ls!()
    |> Enum.filter(&String.contains?(&1, ".tmp."))
  end
end
