defmodule Derpex.System.SignalsTest do
  @moduledoc """
  Signals the relay the way an operator does: with real OS signals.

  `test/derpex/signals_test.exs` drives the reload through
  `:gen_event.notify(:erl_signal_server, :sighup)`, which proves the handler
  wiring but never leaves the test VM. This suite boots the relay in its own OS
  process, records that process's pid from the port it was spawned on, and
  sends `kill -HUP` and `kill -TERM` to that pid and no other. Only signals
  addressed to a pid this test spawned are ever sent.
  """

  use ExUnit.Case, async: false

  @moduletag :system
  @moduletag timeout: 180_000

  # Lives under test/support so `mix test` never mistakes it for a test file.
  @boot_script "test/support/system/relay_boot.exs"
  @ready_pattern ~r/DERPEX-SYSTEM-READY pid=(\d+) port=(\d+)/
  @initial_config ~s({"PerClientRateLimitBytesPerSec":1250000,"PerClientRateBurstBytes":2500000})
  @reloaded_config ~s({"PerClientRateLimitBytesPerSec":2500000,"PerClientRateBurstBytes":5000000})

  @tag :tmp_dir
  test "SIGHUP reloads the rate configuration and SIGTERM shuts the relay down", %{
    tmp_dir: tmp_dir
  } do
    rate_config_path = Path.join(tmp_dir, "rate.json")
    key_directory = Path.join(tmp_dir, "keys")
    identity_path = Path.join(key_directory, "derp.key")
    File.write!(rate_config_path, @initial_config)

    port = start_relay(identity_path, rate_config_path)
    {os_pid, listen_port, output} = await_ready(port)

    # The pid the harness signals is the pid the relay itself reports, so the
    # signal cannot land on some unrelated process.
    assert {:os_pid, os_pid} == Port.info(port, :os_pid)
    assert_listening(listen_port)
    assert File.regular?(identity_path)

    File.write!(rate_config_path, @reloaded_config)
    signal(os_pid, "HUP")

    output = await_output(port, "SIGHUP received; reloading DERP rate configuration", output)
    output = await_output(port, "DERP rate configuration reloaded successfully", output)

    # A second signal re-reads the file instead of replaying a cached copy,
    # which is what makes the first reload evidence of new values being applied.
    File.write!(rate_config_path, "not json")
    signal(os_pid, "HUP")
    output = await_output(port, "DERP rate configuration reload failed", output)

    signal(os_pid, "TERM")
    output = await_output(port, "SIGTERM received", output)
    assert await_exit(port, output) == 0

    # Nothing is left behind: no listener, no half-written key file.
    assert refuses_connections?(listen_port)
    assert File.regular?(identity_path)
    assert Path.wildcard(Path.join(key_directory, "*.tmp.*")) == []
    assert Path.wildcard(Path.join(tmp_dir, "**/*.tmp.*")) == []
  end

  defp start_relay(identity_path, rate_config_path) do
    elixir = System.find_executable("elixir") || flunk("elixir is not on PATH")

    port =
      Port.open({:spawn_executable, elixir}, [
        :binary,
        :exit_status,
        :hide,
        :stderr_to_stdout,
        args: ["-S", "mix", "run", "--no-start", "--no-halt", @boot_script],
        cd: File.cwd!(),
        env: [
          {~c"MIX_ENV", ~c"test"},
          {~c"DERPEX_SYSTEM_IDENTITY_PATH", String.to_charlist(identity_path)},
          {~c"DERPEX_SYSTEM_RATE_CONFIG", String.to_charlist(rate_config_path)}
        ]
      ])

    {:os_pid, os_pid} = Port.info(port, :os_pid)
    on_exit(fn -> stop_relay(os_pid) end)
    port
  end

  # Only ever aimed at the pid this test spawned, and only if that pid is still
  # alive when the test ends early.
  defp stop_relay(os_pid) do
    pid_text = Integer.to_string(os_pid)

    case System.cmd("kill", ["-0", pid_text], stderr_to_stdout: true) do
      {_output, 0} -> System.cmd("kill", ["-KILL", pid_text], stderr_to_stdout: true)
      _already_gone -> :ok
    end

    :ok
  end

  defp signal(os_pid, name) do
    assert {_output, 0} =
             System.cmd("kill", ["-#{name}", Integer.to_string(os_pid)], stderr_to_stdout: true)

    :ok
  end

  defp await_ready(port) do
    output = await_match(port, @ready_pattern, "", deadline(120_000))
    [_line, os_pid, listen_port] = Regex.run(@ready_pattern, output)
    {String.to_integer(os_pid), String.to_integer(listen_port), output}
  end

  defp await_output(port, pattern, output, timeout \\ 60_000) do
    await_match(port, pattern, output, deadline(timeout))
  end

  defp await_match(port, pattern, output, deadline) do
    if matches?(output, pattern) do
      output
    else
      receive do
        {^port, {:data, data}} ->
          await_match(port, pattern, output <> data, deadline)

        {^port, {:exit_status, status}} ->
          flunk("""
          the relay exited with status #{status} while waiting for #{inspect(pattern)}
          #{output}
          """)
      after
        remaining(deadline) ->
          flunk("""
          timed out waiting for #{inspect(pattern)}
          #{output}
          """)
      end
    end
  end

  defp await_exit(port, output, timeout \\ 60_000) do
    await_exit_status(port, output, deadline(timeout))
  end

  defp await_exit_status(port, output, deadline) do
    receive do
      {^port, {:data, data}} -> await_exit_status(port, output <> data, deadline)
      {^port, {:exit_status, status}} -> status
    after
      remaining(deadline) ->
        flunk("""
        the relay never exited after SIGTERM
        #{output}
        """)
    end
  end

  defp matches?(output, %Regex{} = pattern), do: Regex.match?(pattern, output)
  defp matches?(output, pattern) when is_binary(pattern), do: String.contains?(output, pattern)

  defp deadline(timeout), do: System.monotonic_time(:millisecond) + timeout

  defp remaining(deadline),
    do: max(deadline - System.monotonic_time(:millisecond), 0)

  defp assert_listening(listen_port) do
    assert {:ok, socket} =
             :gen_tcp.connect({127, 0, 0, 1}, listen_port, [:binary, active: false], 5_000)

    :ok = :gen_tcp.close(socket)
  end

  defp refuses_connections?(listen_port) do
    case :gen_tcp.connect({127, 0, 0, 1}, listen_port, [:binary, active: false], 1_000) do
      {:error, _reason} ->
        true

      {:ok, socket} ->
        :ok = :gen_tcp.close(socket)
        false
    end
  end
end
