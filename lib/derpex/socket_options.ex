defmodule Derpex.SocketOptions do
  @moduledoc """
  Pinned TCP socket settings for DERP listeners and trusted mesh peers.

  `TCP_USER_TIMEOUT` is only available on Linux. TCP keepalive idle time uses
  the platform socket option exposed by Linux and Darwin; other platforms
  retain the requested `SO_KEEPALIVE` setting without changing their system
  idle duration.
  """

  require Logger

  alias ThousandIsland.Socket

  @default_keepalive_ms 10 * 60 * 1_000
  @default_user_timeout_ms 15_000
  @default_write_timeout_ms 2_000
  @mesh_write_timeout_ms 30_000

  @ipproto_tcp 6
  @linux_tcp_keepidle 4
  @linux_tcp_user_timeout 18
  @darwin_tcp_keepalive 16

  @type settings :: [
          keepalive_ms: pos_integer(),
          user_timeout_ms: non_neg_integer(),
          write_timeout_ms: non_neg_integer()
        ]

  @doc "Adds the pinned listener defaults without replacing explicit options."
  @spec listener_options(list(), settings()) :: list()
  def listener_options(options, settings \\ []) when is_list(options) and is_list(settings) do
    keepalive_ms = positive_setting!(settings, :keepalive_ms, @default_keepalive_ms)
    user_timeout_ms = non_negative_setting!(settings, :user_timeout_ms, @default_user_timeout_ms)

    write_timeout_ms =
      non_negative_setting!(settings, :write_timeout_ms, @default_write_timeout_ms)

    options
    |> put_new_named(:keepalive, true)
    |> put_new_named(:send_timeout, timeout_value(write_timeout_ms))
    |> put_new_named(:send_timeout_close, true)
    |> append_new_raw(raw_options(keepalive_ms, user_timeout_ms))
  end

  @doc "Returns the privileged write timeout used after mesh authentication."
  @spec mesh_write_timeout_ms() :: pos_integer()
  def mesh_write_timeout_ms, do: @mesh_write_timeout_ms

  @doc "Switches an authenticated trusted socket to the pinned mesh write timeout."
  @spec configure_mesh_write_timeout(Socket.t(), non_neg_integer()) ::
          :ok | {:error, term()}
  def configure_mesh_write_timeout(socket, timeout_ms \\ @mesh_write_timeout_ms)
      when is_integer(timeout_ms) and timeout_ms >= 0 do
    Socket.setopts(socket,
      send_timeout: timeout_value(timeout_ms),
      send_timeout_close: true
    )
  end

  @doc false
  @spec raw_options(pos_integer(), non_neg_integer(), {:unix, atom()} | term()) :: list()
  def raw_options(keepalive_ms, user_timeout_ms, os_type \\ :os.type())

  def raw_options(keepalive_ms, user_timeout_ms, {:unix, :linux}) do
    [
      raw_integer(@linux_tcp_keepidle, milliseconds_to_seconds(keepalive_ms)),
      raw_integer(@linux_tcp_user_timeout, user_timeout_ms)
    ]
  end

  def raw_options(keepalive_ms, _user_timeout_ms, {:unix, :darwin}) do
    [raw_integer(@darwin_tcp_keepalive, milliseconds_to_seconds(keepalive_ms))]
  end

  def raw_options(_keepalive_ms, _user_timeout_ms, _os_type), do: []

  @doc false
  @spec log_platform_notice(settings(), {:unix, atom()} | term()) :: :ok
  def log_platform_notice(settings \\ [], os_type \\ :os.type()) do
    user_timeout_ms = non_negative_setting!(settings, :user_timeout_ms, @default_user_timeout_ms)

    if user_timeout_ms > 0 and os_type != {:unix, :linux} do
      Logger.notice(
        "TCP_USER_TIMEOUT is unavailable on #{inspect(os_type)}; continuing without it"
      )
    end

    :ok
  end

  defp positive_setting!(settings, name, default) do
    case Keyword.get(settings, name, default) do
      value when is_integer(value) and value > 0 -> value
      _invalid -> raise ArgumentError, "#{name} must be a positive integer"
    end
  end

  defp non_negative_setting!(settings, name, default) do
    case Keyword.get(settings, name, default) do
      value when is_integer(value) and value >= 0 -> value
      _invalid -> raise ArgumentError, "#{name} must be a non-negative integer"
    end
  end

  defp timeout_value(0), do: :infinity
  defp timeout_value(milliseconds), do: milliseconds

  defp milliseconds_to_seconds(milliseconds), do: div(milliseconds + 999, 1_000)

  defp raw_integer(option, value) do
    {:raw, @ipproto_tcp, option, <<value::native-unsigned-integer-size(32)>>}
  end

  defp put_new_named(options, name, value) do
    if Enum.any?(options, &named_option?(&1, name)), do: options, else: options ++ [{name, value}]
  end

  defp named_option?({name, _value}, name), do: true
  defp named_option?(name, name), do: true
  defp named_option?(_option, _name), do: false

  defp append_new_raw(options, defaults) do
    Enum.reduce(defaults, options, fn {:raw, level, option, _value} = default, options ->
      if Enum.any?(options, &raw_option?(&1, level, option)),
        do: options,
        else: options ++ [default]
    end)
  end

  defp raw_option?({:raw, level, option, _value}, level, option), do: true
  defp raw_option?(_candidate, _level, _option), do: false
end
