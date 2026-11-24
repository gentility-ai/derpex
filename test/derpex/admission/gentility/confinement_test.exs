defmodule Derpex.Admission.Gentility.ConfinementTest do
  use ExUnit.Case, async: true

  alias Derpex.Admission.Gentility.Confinement

  @host {203, 0, 113, 7}

  describe "parse/1" do
    test "reads prefixes and their kinds, and an unset setting confines nothing" do
      assert Confinement.parse(nil) == {:ok, []}
      assert Confinement.parse("") == {:ok, []}

      assert {:ok,
              [{{{203, 0, 113, 7}, 32}, kinds}, {{{0x2001, 0xDB8, 0, 0, 0, 0, 0, 0}, 64}, v6}]} =
               Confinement.parse("203.0.113.7/32=computer@sin-1|platform;2001:db8::/64=platform")

      assert kinds == MapSet.new(["computer@sin-1", "platform"])
      assert v6 == MapSet.new(["platform"])
    end

    test "accepts every kind Gentility issues" do
      assert {:ok, _rules} =
               Confinement.parse("10.0.0.0/8=platform|machine|user|runtime|computer@r-1")
    end

    # One refused shape per test case, and the bound accepted.
    test "a runner id of 1 to 55 lowercase letters, digits and hyphens is accepted" do
      id = String.duplicate("a", 54) <> "9"
      assert byte_size(id) == 55
      assert {:ok, [{_prefix, kinds}]} = Confinement.parse("203.0.113.7/32=computer@" <> id)
      assert MapSet.member?(kinds, "computer@" <> id)
      assert byte_size("computer@" <> id) == 64
    end

    for {shape, id} <- [
          uppercase: "Host1",
          underscore: "ry_zen",
          dot: "ry.zen",
          space: "ry zen",
          equals: "ry=zen",
          at_sign: "ry@zen",
          empty: "",
          fifty_six_bytes: String.duplicate("a", 56)
        ] do
      test "a runner id with #{shape} is refused" do
        assert {:error, {_entry, :invalid_kind}} =
                 Confinement.parse("203.0.113.7/32=computer@" <> unquote(id))
      end
    end

    # A separator inside a runner id splits the entry before the id is read,
    # so what is left is a fragment that is not a kind, and is refused.
    test "a runner id with a pipe is refused" do
      assert {:error, {_entry, :invalid_kind}} =
               Confinement.parse("203.0.113.7/32=computer@ho|st1")
    end

    test "a runner id with a semicolon is refused" do
      assert {:error, {"st1", :invalid_entry}} =
               Confinement.parse("203.0.113.7/32=computer@ho;st1")
    end

    test "refuses malformed entries" do
      for {setting, reason} <- [
            {"203.0.113.7/32", :invalid_entry},
            {"203.0.113.7/32=", :invalid_kind},
            {"203.0.113.7=platform", :invalid_prefix},
            {"203.0.113.7/33=platform", :invalid_prefix},
            {"203.0.113.0/16=platform", :invalid_prefix},
            {"example.com/32=platform", :invalid_prefix},
            {"203.0.113.7/32=platform|", :invalid_kind},
            {"203.0.113.7/32=deployment", :invalid_kind},
            {"203.0.113.7/32=Platform", :invalid_kind},
            {"203.0.113.7/32= platform", :invalid_kind},
            {"203.0.113.7/32=platform|platform", :duplicate_kind},
            {"203.0.113.7/32=platform;", :invalid_entry},
            {"203.0.113.7/32=platform;203.0.113.7/32=user", :duplicate_prefix}
          ] do
        assert {:error, {_entry, ^reason}} = Confinement.parse(setting),
               "#{inspect(setting)} was not refused with #{reason}"
      end
    end
  end

  describe "check/3" do
    setup do
      {:ok, rules} = Confinement.parse("203.0.113.7/32=computer@host1|platform")
      {:ok, rules: rules}
    end

    test "from a confined source, a listed kind passes", %{rules: rules} do
      assert Confinement.check(rules, @host, "computer@host1") == :ok
      assert Confinement.check(rules, @host, "platform") == :ok
    end

    test "the kind is compared whole, never split or prefixed", %{rules: rules} do
      for kind <- ["computer@host", "computer@host12", "computer@", "computer", "machine", "user"] do
        assert Confinement.check(rules, @host, kind) == {:error, :confined_source},
               "#{kind} passed"
      end
    end

    test "any other source is unaffected", %{rules: rules} do
      assert Confinement.check(rules, {203, 0, 113, 8}, "machine") == :ok
      assert Confinement.check(rules, {0x2001, 0xDB8, 0, 0, 0, 0, 0, 1}, "machine") == :ok
    end

    test "an IPv4-mapped address is its IPv4 source", %{rules: rules} do
      mapped = {0, 0, 0, 0, 0, 0xFFFF, 0xCB00, 0x7107}
      assert Confinement.check(rules, mapped, "machine") == {:error, :confined_source}
      assert Confinement.check(rules, mapped, "platform") == :ok
    end

    test "a renewal has no source and is never confined", %{rules: rules} do
      assert Confinement.check(rules, nil, "machine") == :ok
    end

    test "a source in several prefixes must match each" do
      {:ok, rules} = Confinement.parse("203.0.113.0/24=platform|machine;203.0.113.7/32=platform")

      assert Confinement.check(rules, @host, "platform") == :ok
      assert Confinement.check(rules, @host, "machine") == {:error, :confined_source}
      assert Confinement.check(rules, {203, 0, 113, 8}, "machine") == :ok
    end
  end
end
