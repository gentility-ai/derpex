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
