defmodule Derpex.TLSVersionTest do
  use ExUnit.Case, async: true

  alias Derpex.TLSVersion

  @runtime Path.expand("../../config/runtime.exs", __DIR__)

  test "defaults to TLS 1.3 only when the environment says nothing" do
    assert TLSVersion.default() == "1.3"
    assert TLSVersion.parse(nil) == {:ok, [:"tlsv1.3"]}
    assert TLSVersion.parse("") == {:ok, [:"tlsv1.3"]}
    assert TLSVersion.parse("   ") == {:ok, [:"tlsv1.3"]}
  end

  test "a 1.2 minimum lowers the floor rather than pinning the version" do
    assert TLSVersion.parse("1.2") == {:ok, [:"tlsv1.2", :"tlsv1.3"]}
    assert TLSVersion.parse(" 1.2 ") == {:ok, [:"tlsv1.2", :"tlsv1.3"]}
    assert TLSVersion.parse("1.3") == {:ok, [:"tlsv1.3"]}
  end

  test "refuses anything else rather than silently defaulting" do
    for value <- ["1.1", "1", "tlsv1.3", "1.4", "TLS1.2", "1.2.0", "0", "true"] do
      assert TLSVersion.parse(value) == {:error, :invalid_tls_min_version},
             "#{inspect(value)} was accepted"
    end

    assert TLSVersion.parse(:"1.2") == {:error, :invalid_tls_min_version}
    assert TLSVersion.parse(12) == {:error, :invalid_tls_min_version}
  end

  test "parse! raises with the accepted values named" do
    assert TLSVersion.parse!("1.2") == [:"tlsv1.2", :"tlsv1.3"]

    message = assert_raise(ArgumentError, fn -> TLSVersion.parse!("1.1") end).message
    assert message =~ "DERPEX_TLS_MIN_VERSION"
    assert message =~ ~s("1.2")
    assert message =~ ~s("1.3")
  end

  # The setting is only parity-restoring if it reaches both directions, so the
  # production configuration has to hand the same versions to the TLS listener
  # and to every mesh peer the client dials.
  test "the production configuration applies one floor to listeners and mesh dials" do
    runtime = File.read!(@runtime)

    assert runtime =~ ~S|Derpex.TLSVersion.parse(System.get_env("DERPEX_TLS_MIN_VERSION"))|
    refute runtime =~ ~S|versions: [:"tlsv1.3"]|

    assert length(String.split(runtime, "versions: tls_versions,")) - 1 == 2,
           "both TLS listener branches must take the configured floor"

    assert length(String.split(runtime, "tls_options: [versions: tls_versions]")) - 1 == 3,
           "every mesh peer shape must dial with the configured floor"
  end
end
