defmodule Derpex.SocketOptionsTest do
  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias Derpex.SocketOptions
  alias ThousandIsland.Socket
  alias ThousandIsland.Transports.TCP

  test "adds the pinned Linux listener options" do
    options = SocketOptions.listener_options([], os_settings())

    assert named_options(options, [:keepalive, :send_timeout, :send_timeout_close]) == [
             keepalive: true,
             send_timeout: 2_000,
             send_timeout_close: true
           ]

    assert [
             {:raw, 6, 4, <<600::native-unsigned-integer-size(32)>>},
             {:raw, 6, 18, <<15_000::native-unsigned-integer-size(32)>>}
           ] = SocketOptions.raw_options(600_000, 15_000, {:unix, :linux})
  end

  test "rounds the Darwin keepalive duration up and omits TCP_USER_TIMEOUT" do
    assert [
             {:raw, 6, 16, <<2::native-unsigned-integer-size(32)>>}
           ] = SocketOptions.raw_options(1_001, 15_000, {:unix, :darwin})
  end

  test "preserves explicit named and raw options" do
    keepidle = {:raw, 6, 4, <<77::native-unsigned-integer-size(32)>>}

    options =
      SocketOptions.listener_options(
        [keepalive: false, send_timeout: 91, send_timeout_close: false] ++ [keepidle],
        os_settings()
      )

    assert named_options(options, [:keepalive, :send_timeout, :send_timeout_close]) == [
             keepalive: false,
             send_timeout: 91,
             send_timeout_close: false
           ]

    assert Enum.count(options, fn
             {:raw, 6, 4, _value} -> true
             _other -> false
           end) == 1

    assert keepidle in options
  end

  test "zero ordinary write timeout disables the send deadline" do
    options = SocketOptions.listener_options([], write_timeout_ms: 0)
    assert options[:send_timeout] == :infinity
  end

  test "logs the unsupported TCP_USER_TIMEOUT boundary" do
    log =
      capture_log(fn ->
        assert :ok = SocketOptions.log_platform_notice([], {:unix, :darwin})
      end)

    assert log =~ "TCP_USER_TIMEOUT is unavailable"
    assert log =~ "darwin"
  end

  test "switches a live accepted socket to the privileged mesh write timeout" do
    {:ok, listener} =
      :gen_tcp.listen(0, [:binary, packet: :raw, active: false, ip: {127, 0, 0, 1}])

    {:ok, {{127, 0, 0, 1}, port}} = :inet.sockname(listener)
    {:ok, client} = :gen_tcp.connect({127, 0, 0, 1}, port, [:binary, active: false])
    {:ok, accepted} = :gen_tcp.accept(listener)

    on_exit(fn ->
      :gen_tcp.close(accepted)
      :gen_tcp.close(client)
      :gen_tcp.close(listener)
    end)

    socket = %Socket{
      socket: accepted,
      transport_module: TCP,
      read_timeout: 1_000,
      silent_terminate_on_error: false,
      span: nil
    }

    assert :ok = SocketOptions.configure_mesh_write_timeout(socket)

    assert {:ok, [send_timeout: 30_000, send_timeout_close: true]} =
             :inet.getopts(accepted, [:send_timeout, :send_timeout_close])
  end

  defp os_settings do
    [keepalive_ms: 600_000, user_timeout_ms: 15_000, write_timeout_ms: 2_000]
  end

  defp named_options(options, names) do
    Enum.filter(options, fn
      {name, _value} -> name in names
      _other -> false
    end)
  end
end
