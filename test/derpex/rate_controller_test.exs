defmodule Derpex.RateControllerTest do
  use ExUnit.Case, async: true

  alias Derpex.RateConfig
  alias Derpex.RateController

  test "updates every ordinary subscriber, exempts mesh, and can disable live" do
    controller = start_supervised!({RateController, name: nil})
    assert RateController.subscribe(controller, self(), false) == %RateConfig{}

    parent = self()

    duplicate =
      spawn(fn ->
        initial = RateController.subscribe(controller, self(), false)
        send(parent, {:duplicate_ready, initial})

        receive do
          message -> send(parent, {:duplicate_received, message})
        end
      end)

    assert_receive {:duplicate_ready, %RateConfig{}}

    mesh =
      spawn(fn ->
        receive do
          message -> send(parent, {:mesh_received, message})
        end
      end)

    assert RateController.subscribe(controller, mesh, true) == %RateConfig{}

    configured = %RateConfig{
      per_client_rate_limit_bytes_per_second: 1_250_000,
      per_client_rate_burst_bytes: 10
    }

    applied = RateController.update(controller, configured)
    assert applied.per_client_rate_burst_bytes == RateConfig.minimum_burst()
    assert_receive {RateController, :updated, ^applied}
    assert_receive {:duplicate_received, {RateController, :updated, ^applied}}
    refute_receive {:mesh_received, _message}, 25

    assert RateController.update(controller, %RateConfig{per_client_rate_burst_bytes: 99}) ==
             %RateConfig{}

    assert_receive {RateController, :updated, %RateConfig{}}
    if Process.alive?(duplicate), do: Process.exit(duplicate, :kill)
    if Process.alive?(mesh), do: Process.exit(mesh, :kill)
  end

  test "loads and applies a rate configuration file" do
    controller = start_supervised!({RateController, name: nil})
    path = Path.join(System.tmp_dir!(), "derpex-rate-#{System.unique_integer([:positive])}.json")

    File.write!(
      path,
      ~s({"PerClientRateLimitBytesPerSec":1250000,"PerClientRateBurstBytes":2500000})
    )

    on_exit(fn -> File.rm(path) end)

    assert {:ok,
            %RateConfig{
              per_client_rate_limit_bytes_per_second: 1_250_000,
              per_client_rate_burst_bytes: 2_500_000
            }} = RateController.load_and_apply(controller, path)

    File.write!(path, "{}")
    assert RateController.load_and_apply(controller, path) == {:ok, %RateConfig{}}
  end
end
