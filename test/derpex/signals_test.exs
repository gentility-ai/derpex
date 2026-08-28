defmodule Derpex.SignalsTest do
  use ExUnit.Case, async: false

  alias Derpex.RateConfig
  alias Derpex.RateController
  alias Derpex.SignalHandler
  alias Derpex.Signals

  @valid ~s({"PerClientRateLimitBytesPerSec":1250000,"PerClientRateBurstBytes":2500000})

  @tag :tmp_dir
  test "SIGHUP reloads the configured file through OTP's signal event server", %{tmp_dir: dir} do
    path = Path.join(dir, "rate.json")
    File.write!(path, @valid)
    controller = start_supervised!({RateController, name: nil})

    signals =
      start_supervised!({Signals, name: nil, rate_config_path: path, rate_controller: controller})

    assert %RateConfig{} = RateController.subscribe(controller, self(), false)

    :ok = :gen_event.notify(:erl_signal_server, :sighup)

    assert_receive {RateController, :updated,
                    %RateConfig{
                      per_client_rate_limit_bytes_per_second: 1_250_000,
                      per_client_rate_burst_bytes: 2_500_000
                    }},
                   1_000

    eventually(fn -> Signals.stats(signals).reloads == 1 end)
  end

  @tag :tmp_dir
  test "a failed reload retains the last applied configuration", %{tmp_dir: dir} do
    path = Path.join(dir, "rate.json")
    File.write!(path, @valid)
    controller = start_supervised!({RateController, name: nil})

    signals =
      start_supervised!(
        {Signals, name: nil, install: false, rate_config_path: path, rate_controller: controller}
      )

    assert {:ok, configured} = Signals.reload(signals)
    File.write!(path, "not json")
    assert {:error, _reason} = Signals.reload(signals)
    assert RateController.subscribe(controller, self(), false) == configured
    assert %{reloads: 1, failures: 1, last_error: last_error} = Signals.stats(signals)
    refute is_nil(last_error)
  end

  test "the event handler ignores unrelated runtime signals" do
    assert {:ok, target} = SignalHandler.init(self())
    assert {:ok, ^target} = SignalHandler.handle_event(:sigwinch, target)
    refute_receive {Signals, :sighup}
    assert {:ok, ^target} = SignalHandler.handle_event(:sighup, target)
    assert_receive {Signals, :sighup}
  end

  defp eventually(assertion, attempts \\ 100)
  defp eventually(assertion, 0), do: assert(assertion.())

  defp eventually(assertion, attempts) do
    if assertion.() do
      :ok
    else
      Process.sleep(5)
      eventually(assertion, attempts - 1)
    end
  end
end
