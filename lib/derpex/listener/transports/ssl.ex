defmodule Derpex.Listener.Transports.SSL do
  @moduledoc """
  TLS transport that resolves the server certificate per connection.

  When `transport_options` carry a `#{inspect(:derpex_certificate_snapshot)}`
  key the listen socket is opened with `handshake: :hello`, so every accepted
  connection pauses after the ClientHello. `handshake/1` then supplies the
  certificate that `Derpex.Certificates.Reloader` currently publishes through
  `:ssl.handshake_continue/2`. This covers SNI *and* no-SNI hellos alike, which
  `sni_fun` alone cannot do. Listeners without a reloader keep the plain
  upstream handshake and pay nothing.

  Thousand Island hands `handshake/1` only the accepted socket, so the snapshot
  key is registered in `:persistent_term` under the listen socket's bound
  `{ip, port}`. A connection accepted on a wildcard listener reports its own
  concrete local address, so lookups fall back to the `0.0.0.0` and `::`
  registrations for the same port. Reads are lock-free, happen once per
  connection, and only on the paused path.
  """

  @behaviour ThousandIsland.Transport

  import Bitwise, only: [<<<: 2]

  require Logger

  alias Derpex.Certificates.Reloader
  alias Derpex.Clock
  alias Derpex.Listener.Transports.Options
  alias ThousandIsland.Transports.SSL, as: Upstream

  @certificate_options [:certs_keys, :keyfile, :key, :sni_hosts, :sni_fun]
  @public_certificate_options [:certs_keys, :certfile, :cert, :sni_hosts, :sni_fun]
  @snapshot_option :derpex_certificate_snapshot

  # Mirrors the DERP handshake deadline in `Derpex.Connection`. Both legs of a
  # paused handshake are bounded, so a client that opens a socket and then stops
  # talking cannot pin a connection process open indefinitely.
  @handshake_timeout_ms 10_000

  @wildcards [{0, 0, 0, 0}, {0, 0, 0, 0, 0, 0, 0, 0}]
  @fallback_warning_key {__MODULE__, :boot_certificate_fallback}
  @fallback_warning_interval_ms 30_000
  @never -(1 <<< 60)

  @doc "The `transport_options` key carrying a certificate-reloader snapshot key."
  @spec snapshot_option() :: atom()
  def snapshot_option, do: @snapshot_option

  @doc "Returns how often a listener fell back to its boot certificate."
  @spec boot_certificate_fallbacks() :: non_neg_integer()
  def boot_certificate_fallbacks do
    case :persistent_term.get(@fallback_warning_key, nil) do
      nil -> 0
      throttle -> :atomics.get(throttle, 3)
    end
  end

  @impl true
  def listen(port, user_options) do
    {snapshot_key, user_options} = pop_snapshot_key(user_options)

    options =
      user_options
      |> paused_handshake(snapshot_key)
      |> Options.resolve(
        backlog: 1024,
        nodelay: true,
        send_timeout: 30_000,
        send_timeout_close: true,
        reuseaddr: true
      )

    unless Enum.any?(@certificate_options, &:proplists.is_defined(&1, options)) do
      raise "transport_options must include one of keyfile, key, sni_hosts or sni_fun"
    end

    unless Enum.any?(@public_certificate_options, &:proplists.is_defined(&1, options)) do
      raise "transport_options must include one of certfile, cert, sni_hosts or sni_fun"
    end

    with {:ok, socket} <- :ssl.listen(port, options) do
      register_snapshot(socket, snapshot_key)
    end
  end

  @impl true
  defdelegate accept(socket), to: Upstream

  @impl true
  def handshake(socket) do
    case :ssl.handshake(socket, @handshake_timeout_ms) do
      {:ok, socket, _extensions} -> continue_handshake(socket)
      {:ok, socket} -> {:ok, socket}
      {:error, _reason} = error -> error
    end
  end

  @impl true
  defdelegate upgrade(socket, options), to: Upstream
  @impl true
  defdelegate controlling_process(socket, pid), to: Upstream
  @impl true
  defdelegate recv(socket, length, timeout), to: Upstream
  @impl true
  defdelegate send(socket, data), to: Upstream
  @impl true
  defdelegate sendfile(socket, filename, offset, length), to: Upstream
  @impl true
  defdelegate getopts(socket, options), to: Upstream
  @impl true
  defdelegate setopts(socket, options), to: Upstream
  @impl true
  defdelegate shutdown(socket, way), to: Upstream
  @impl true
  def close(socket) do
    :ok = erase_snapshot(socket)
    Upstream.close(socket)
  end

  @impl true
  defdelegate sockname(socket), to: Upstream
  @impl true
  defdelegate peername(socket), to: Upstream
  @impl true
  defdelegate peercert(socket), to: Upstream
  @impl true
  defdelegate secure?(), to: Upstream
  @impl true
  defdelegate getstat(socket), to: Upstream
  @impl true
  defdelegate negotiated_protocol(socket), to: Upstream
  @impl true
  defdelegate connection_information(socket), to: Upstream

  defp pop_snapshot_key(options) do
    {snapshot_key, reversed} =
      Enum.reduce(options, {nil, []}, fn
        {@snapshot_option, key}, {_previous, rest} -> {key, rest}
        option, {key, rest} -> {key, [option | rest]}
      end)

    {snapshot_key, Enum.reverse(reversed)}
  end

  defp paused_handshake(options, nil), do: options
  defp paused_handshake(options, _snapshot_key), do: [{:handshake, :hello} | options]

  defp register_snapshot(socket, nil), do: {:ok, socket}

  defp register_snapshot(socket, snapshot_key) do
    case :ssl.sockname(socket) do
      {:ok, address} ->
        :ok = claim_registration(address, snapshot_key, socket)
        {:ok, socket}

      {:error, reason} ->
        _closed = :ssl.close(socket)
        {:error, reason}
    end
  end

  # A second listener on the same address must not silently steal the first
  # one's certificate rotation. A registration left behind by a listener whose
  # reloader has already gone is stale and may be replaced; a live one is a
  # genuine conflict and refuses the bind.
  defp claim_registration(address, snapshot_key, socket) do
    key = registration_key(address)

    case :persistent_term.get(key, nil) do
      nil ->
        :persistent_term.put(key, {snapshot_key, socket})

      {^snapshot_key, _previous_socket} ->
        :persistent_term.put(key, {snapshot_key, socket})

      {previous_key, _previous_socket} ->
        replace_registration(key, previous_key, snapshot_key, socket, address)
    end
  end

  defp replace_registration(key, previous_key, snapshot_key, socket, address) do
    if Reloader.current_options(previous_key) == :undefined do
      :persistent_term.put(key, {snapshot_key, socket})
    else
      raise "a live TLS certificate snapshot is already registered for #{inspect(address)}; " <>
              "two listeners cannot share one bound address"
    end
  end

  defp erase_snapshot(socket) do
    with {:ok, address} <- :ssl.sockname(socket),
         key = registration_key(address),
         {_snapshot_key, ^socket} <- :persistent_term.get(key, nil) do
      _erased = :persistent_term.erase(key)
      :ok
    else
      _not_a_registered_listen_socket -> :ok
    end
  end

  defp registration_key(address), do: {__MODULE__, :snapshot, address}

  defp continue_handshake(socket) do
    :ssl.handshake_continue(socket, certificate_options(socket), @handshake_timeout_ms)
  end

  defp certificate_options(socket) do
    with {:ok, {ip, port}} <- :ssl.sockname(socket),
         snapshot_key when not is_nil(snapshot_key) <- lookup_snapshot_key(ip, port),
         [_option | _rest] = options <- Reloader.current_options(snapshot_key) do
      options
    else
      _no_published_snapshot ->
        warn_boot_certificate_fallback()
        []
    end
  end

  defp lookup_snapshot_key(ip, port) do
    [ip | @wildcards]
    |> Enum.uniq()
    |> Enum.find_value(fn candidate ->
      case :persistent_term.get(registration_key({candidate, port}), nil) do
        {snapshot_key, _socket} -> snapshot_key
        nil -> nil
      end
    end)
  end

  # Serving the certificate the relay booted with is not fatal, but it means a
  # rotation is not reaching clients, so it must be visible without letting a
  # connection flood turn the log into the outage.
  defp warn_boot_certificate_fallback do
    throttle = fallback_throttle()
    :atomics.add(throttle, 3, 1)
    previous = :atomics.get(throttle, 1)
    now = Clock.monotonic_time(:millisecond)

    if now - previous >= @fallback_warning_interval_ms and
         :atomics.compare_exchange(throttle, 1, previous, now) == :ok do
      Logger.warning(fallback_message(:atomics.exchange(throttle, 2, 0)))
    else
      :atomics.add(throttle, 2, 1)
    end

    :ok
  end

  defp fallback_message(0) do
    "DERP TLS handshake found no published certificate snapshot; serving the boot certificate"
  end

  defp fallback_message(suppressed) do
    fallback_message(0) <> " (#{suppressed} identical warnings suppressed)"
  end

  defp fallback_throttle do
    case :persistent_term.get(@fallback_warning_key, nil) do
      nil ->
        throttle = :atomics.new(3, signed: true)
        :atomics.put(throttle, 1, @never)
        :persistent_term.put(@fallback_warning_key, throttle)
        :persistent_term.get(@fallback_warning_key)

      throttle ->
        throttle
    end
  end
end
