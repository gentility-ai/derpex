defmodule Derpex.UpstreamCoverageTest do
  use ExUnit.Case, async: true

  @root Path.expand("../..", __DIR__)
  @coverage Path.join(@root, "interop/COVERAGE.md")
  @dispositions ~w(ported black-box differential implementation-specific pending)
  @cited ~w(ported black-box differential implementation-specific)
  @path_pattern ~r{(?:test|bench|scripts|interop|lib|native|\.github)/[A-Za-z0-9_./-]*[A-Za-z0-9_]}

  test "every row uses one of the five dispositions" do
    for row <- rows() do
      assert row.disposition in @dispositions,
             "#{row.name} has unknown disposition #{inspect(row.disposition)}"
    end
  end

  test "every non-pending row cites a repository path that exists" do
    for %{disposition: disposition} = row <- rows(), disposition in @cited do
      citations = citations(row.note)

      refute citations == [],
             "#{row.name} (#{disposition}) cites no repository path: #{row.note}"

      for citation <- citations do
        assert File.exists?(Path.join(@root, citation)),
               "#{row.name} cites #{citation}, which does not exist"
      end
    end
  end

  test "every ported, black-box, and differential row cites a DERPEX test file" do
    for %{disposition: disposition} = row <- rows(),
        disposition in ~w(ported black-box differential) do
      tests = Enum.filter(citations(row.note), &test_file?/1)

      refute tests == [],
             "#{row.name} (#{disposition}) cites no test/**.exs file: #{row.note}"
    end
  end

  test "a black-box row cites only unchanged-client interoperability tests" do
    for %{disposition: "black-box"} = row <- rows() do
      tests = Enum.filter(citations(row.note), &test_file?/1)

      assert Enum.all?(tests, &String.starts_with?(&1, "test/interop/")),
             "#{row.name} is black-box but cites #{inspect(tests)}"
    end
  end

  test "a differential row cites the trace comparison" do
    for %{disposition: "differential"} = row <- rows() do
      assert "test/interop/differential_test.exs" in citations(row.note),
             "#{row.name} is differential but does not cite the trace comparison"
    end
  end

  test "the ACME-dependent IP certificate rows are pending" do
    pending =
      rows() |> Enum.filter(&(&1.disposition == "pending")) |> Enum.map(& &1.name) |> Enum.sort()

    assert pending == ["TestIPCertManager", "TestIPCertManagerNextProvider"]
  end

  test "the send-freeze row points at the system test that ports it" do
    row = Enum.find(rows(), &(&1.name == "TestSendFreeze"))
    assert "test/system/send_freeze_test.exs" in citations(row.note)
  end

  test "the summary counts match the rows" do
    rows = rows()
    body = File.read!(@coverage)

    for {label, disposition} <- [
          {"Total", nil},
          {"Ported", "ported"},
          {"Black-box", "black-box"},
          {"Differential", "differential"},
          {"Pending (release-blocking)", "pending"},
          {"Implementation-specific", "implementation-specific"}
        ] do
      expected =
        if disposition,
          do: Enum.count(rows, &(&1.disposition == disposition)),
          else: length(rows)

      assert body =~ "| #{label} | #{expected} |", "#{label} count is not #{expected}"
    end
  end

  defp test_file?(path),
    do: String.starts_with?(path, "test/") and String.ends_with?(path, ".exs")

  defp citations(note) do
    @path_pattern |> Regex.scan(note) |> Enum.map(&hd/1) |> Enum.uniq()
  end

  defp rows do
    @coverage
    |> File.read!()
    |> String.split("\n")
    |> Enum.flat_map(fn line ->
      case String.split(line, "|", trim: true) do
        [_area, name, _source, disposition, note] ->
          [
            %{
              name: unquote_cell(name),
              disposition: unquote_cell(disposition),
              note: String.trim(note)
            }
          ]

        _not_a_row ->
          []
      end
    end)
    |> Enum.reject(&(&1.name in ["Upstream test", "---"]))
  end

  defp unquote_cell(cell), do: cell |> String.trim() |> String.trim("`")
end
