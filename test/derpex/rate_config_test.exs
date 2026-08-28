defmodule Derpex.RateConfigTest do
  use ExUnit.Case, async: true

  alias Derpex.RateConfig

  test "loads upstream JSON shapes and uses the last case-insensitive duplicate" do
    assert load(~s({"PerClientRateLimitBytesPerSec":1,"PerClientRateBurstBytes":2})) ==
             {:ok,
              %RateConfig{
                per_client_rate_limit_bytes_per_second: 1,
                per_client_rate_burst_bytes: 2
              }}

    assert load(
             ~s({"perclientratelimitbytespersec":1,"PerClientRateLimitBytesPerSec":3,"ignored":true})
           ) ==
             {:ok,
              %RateConfig{
                per_client_rate_limit_bytes_per_second: 3,
                per_client_rate_burst_bytes: 0
              }}

    assert load("{}") == {:ok, %RateConfig{}}
    assert RateConfig.load("") == {:error, :empty_rate_config_path}
    assert {:error, :enoent} = RateConfig.load("/tmp/derpex-rate-config-does-not-exist")
    assert {:error, _reason} = load("not json")

    assert {:error, {:invalid_field, :per_client_rate_limit_bytes_per_second}} =
             load(~s({"PerClientRateLimitBytesPerSec":-1}))
  end

  test "disables on zero rate and clamps an enabled burst to one maximum packet body" do
    assert RateConfig.normalize(%RateConfig{per_client_rate_burst_bytes: 100}) ==
             %RateConfig{}

    config = %RateConfig{
      per_client_rate_limit_bytes_per_second: 1_250_000,
      per_client_rate_burst_bytes: 10
    }

    assert RateConfig.normalize(config) == %{
             config
             | per_client_rate_burst_bytes: RateConfig.minimum_burst()
           }
  end

  defp load(contents) do
    path = Path.join(System.tmp_dir!(), "derpex-rate-#{System.unique_integer([:positive])}.json")
    File.write!(path, contents)
    on_exit(fn -> File.rm(path) end)
    RateConfig.load(path)
  end
end
