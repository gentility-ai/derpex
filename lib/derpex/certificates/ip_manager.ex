# This module implements the observable state machine of cmd/derper's IP certificate manager.
# Copyright (c) 2026 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Certificates.IPManager do
  @moduledoc """
  Caches and serves per-destination-IP certificates from an injected issuer.

  Addresses are canonicalized before anything else: an IPv4-mapped IPv6 local
  address or SNI is unmapped, as Go's `netip.Addr.Unmap` does, so one address
  is one cache entry, one file pair, and one certificate SAN however a client
  or a socket spells it.

  ## When issuance happens

  A handshake is answered from the certificate in hand while the clock places
  it inside its validity window, and only issues when there is nothing valid to
  serve. Renewal — upstream `certNeedsRenewal`, once less than a third of the
  lifetime remains — runs on an hourly tick instead, so no client ever waits on
  an issuance that a background task could have done. A failed issuance backs
  off from one minute to thirty, doubling each time, and nothing is attempted
  again until that deadline; a certificate already in hand keeps being served
  throughout.

  The only issuer DERPEX ships is `self_signed_issuer/2`, reachable through
  `DERPEX_IP_CERT_ISSUER=self`. The ACME issuer this manager was modelled on
  is pending; PLAN.md section 2.3 records that. `:next_provider` exists for the
  same reason and has no production caller: delegating a DNS name needs the
  hostname provider that only an ACME client can supply.
  """

  use GenServer

  require Logger

  alias Derpex.AtomicFile
  alias Derpex.Certificates
  alias Derpex.Certificates.Manual
  alias Derpex.Clock

  @short_lived_profile "shortlived"
  @challenge_prefix "/.well-known/acme-challenge/"
  @certificate_mode 0o644
  @key_mode 0o600

  # Upstream `startFlightLocked`: one minute after the first failure, doubling
  # to a thirty-minute ceiling, and `renewLoop`, which wakes hourly.
  @initial_retry_delay_ms 60_000
  @maximum_retry_delay_ms 30 * 60_000
  @renew_interval_ms 60 * 60_000

  @type certificate :: %{certificate_der: binary(), private_key: tuple()}
  @type issuer :: (binary(), binary() -> {:ok, certificate()} | {:error, term()})
  @type next_provider :: (binary() -> {:ok, term()} | {:error, term()})
  @type certs_keys :: %{cert: [binary()], key: {atom(), binary()}}

  def start_link(options) do
    GenServer.start_link(__MODULE__, options, Keyword.take(options, [:name]))
  end

  @doc "Returns a certificate for the connection's local IP and optional SNI."
  @spec certificate(GenServer.server(), binary(), binary()) ::
          {:ok, certificate() | term()} | {:error, term()}
  def certificate(manager, local_ip, server_name \\ "") do
    GenServer.call(manager, {:certificate, local_ip, server_name}, :infinity)
  end

  @doc """
  Returns one OTP `certs_keys` entry, with `meta_certificate` appended.

  The DER encoding of the private key is done once, when the certificate is
  issued or loaded, so answering a hello is a map lookup and a list append.
  """
  @spec certs_keys(GenServer.server(), binary(), binary(), binary()) ::
          {:ok, certs_keys()} | {:error, term()}
  def certs_keys(manager, local_ip, server_name, meta_certificate)
      when is_binary(meta_certificate) do
    case GenServer.call(manager, {:certs_keys, local_ip, server_name}, :infinity) do
      {:ok, %{cert: chain, key: key}} ->
        {:ok, %{cert: Certificates.append_meta_certificate(chain, meta_certificate), key: key}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  @doc "Installs one active HTTP-01 response."
  @spec put_challenge(GenServer.server(), binary(), binary()) :: :ok
  def put_challenge(manager, path, response) do
    GenServer.call(manager, {:put_challenge, path, response})
  end

  @doc "Deletes one active HTTP-01 response."
  @spec delete_challenge(GenServer.server(), binary()) :: :ok
  def delete_challenge(manager, path), do: GenServer.call(manager, {:delete_challenge, path})

  @doc "Returns a challenge response, not-found, or fallback decision."
  @spec http_response(GenServer.server(), binary()) ::
          {:ok, binary()} | :not_found | :fallback
  def http_response(manager, path), do: GenServer.call(manager, {:http_response, path})

  @doc "The ACME profile required for short-lived IP certificates."
  @spec profile() :: binary()
  def profile, do: @short_lived_profile

  @doc """
  Issues a persistent self-signed certificate for `ip`.

  This is the only issuer DERPEX ships. It contacts no certificate authority,
  so `DERPEX_IP_CERT_ISSUER=self` never depends on the ACME client that
  PLAN.md section 2.3 records as pending.
  """
  @spec self_signed_issuer(binary(), binary()) :: {:ok, certificate()} | {:error, term()}
  def self_signed_issuer(ip, _profile) do
    with {:ok, {certificate_der, private_key}} <- Manual.generate_ip(ip) do
      {:ok, %{certificate_der: certificate_der, private_key: private_key}}
    end
  end

  @doc """
  Returns an OTP SNI callback backed by this manager.

  OTP consults `sni_fun` only for a hello that carries a `server_name`, so a
  no-SNI hello keeps the certificate the listener bound for `local_ip`.

  A name this manager will not answer for returns `:unrecognized`, which closes
  the connection with an `unrecognized_name` alert. Returning `:undefined`
  would mean "use the listen options" (`ssl_gen_statem`), which would serve the
  listener's own certificate to a name that was just refused — a silent
  mismatch instead of a refusal.
  """
  @spec sni_fun(GenServer.server(), binary(), binary()) ::
          (charlist() -> keyword() | :unrecognized)
  def sni_fun(manager, local_ip, meta_certificate) when is_binary(meta_certificate) do
    fn server_name ->
      case certs_keys(manager, local_ip, IO.chardata_to_string(server_name), meta_certificate) do
        {:ok, certs_keys} -> [certs_keys: [certs_keys]]
        {:error, _refused} -> :unrecognized
      end
    end
  end

  @impl true
  def init(options) do
    directory = Keyword.fetch!(options, :directory)
    issuer = Keyword.fetch!(options, :issuer)
    :ok = AtomicFile.ensure_directory(directory)

    state = %{
      directory: directory,
      issuer: issuer,
      next_provider: Keyword.get(options, :next_provider),
      renew_interval_ms: Keyword.get(options, :renew_interval_ms, @renew_interval_ms),
      entries: %{},
      flights: %{},
      challenges: %{}
    }

    {:ok, schedule_renewal(state)}
  end

  @impl true
  def handle_call({:certificate, local_ip, server_name}, from, state) do
    answer(state, local_ip, server_name, from, :certificate)
  end

  def handle_call({:certs_keys, local_ip, server_name}, from, state) do
    answer(state, local_ip, server_name, from, :certs_keys)
  end

  def handle_call({:put_challenge, path, response}, _from, state) do
    {:reply, :ok, put_in(state, [:challenges, path], response)}
  end

  def handle_call({:delete_challenge, path}, _from, state) do
    {:reply, :ok, %{state | challenges: Map.delete(state.challenges, path)}}
  end

  def handle_call({:http_response, path}, _from, state) do
    response =
      if String.starts_with?(path, @challenge_prefix) do
        case Map.fetch(state.challenges, path) do
          {:ok, body} -> {:ok, body}
          :error -> :not_found
        end
      else
        :fallback
      end

    {:reply, response, state}
  end

  # Upstream `renewLoop`: every hour, start an issuance for each held
  # certificate that is inside its last third and not already being replaced.
  @impl true
  def handle_info(:renew_certificates, state) do
    state =
      Enum.reduce(state.entries, state, fn {ip, entry}, state ->
        if renewable?(entry), do: start_flight(state, ip, entry), else: state
      end)

    {:noreply, schedule_renewal(state)}
  end

  # An issuance runs in its own process, so a certificate authority that takes
  # minutes cannot stall a handshake for a different address, and the issuer
  # can call back into this manager to publish an HTTP-01 challenge while the
  # request that started it is still outstanding.
  def handle_info({:flight, ip, result}, state) do
    {:noreply, finish_flight(state, ip, result)}
  end

  def handle_info({:DOWN, reference, :process, _pid, reason}, state) do
    case Map.pop(state.flights, reference) do
      {nil, _flights} ->
        {:noreply, state}

      {ip, flights} ->
        state = %{state | flights: flights}
        {:noreply, finish_flight(state, ip, {:error, {:issuance, {:flight_failed, reason}}})}
    end
  end

  defp schedule_renewal(state) do
    _timer = Clock.send_after(self(), :renew_certificates, state.renew_interval_ms)
    state
  end

  defp renewable?(entry) do
    not is_nil(entry.certificate) and is_nil(entry.flight) and needs_renewal?(entry) and
      not backing_off?(entry)
  end

  defp answer(state, local_ip, server_name, from, projection) do
    case resolve(state, local_ip, server_name) do
      {:ok, result, state} -> {:reply, project(result, projection), state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
      {:wait, ip, state} -> {:noreply, add_waiter(state, ip, from, projection)}
    end
  end

  defp project({:managed, entry}, :certificate), do: {:ok, entry.certificate}
  defp project({:managed, entry}, :certs_keys), do: {:ok, entry.tls}
  defp project({:delegated, certificate}, :certificate), do: {:ok, certificate}

  defp project({:delegated, _certificate}, :certs_keys),
    do: {:error, :next_provider_certificate_not_supported}

  defp add_waiter(state, ip, from, projection) do
    update_in(state.entries[ip].flight.waiters, &[{from, projection} | &1])
  end

  defp start_flight(state, ip, entry) do
    manager = self()
    directory = state.directory
    issuer = state.issuer

    {_pid, reference} =
      spawn_monitor(fn ->
        send(manager, {:flight, ip, flight_result(directory, issuer, ip)})
      end)

    state = put_entry(state, ip, %{entry | flight: %{reference: reference, waiters: []}})
    %{state | flights: Map.put(state.flights, reference, ip)}
  end

  defp flight_result(directory, issuer, ip) do
    case load_or_issue(directory, issuer, ip) do
      {:ok, entry} -> {:ok, entry}
      {:error, reason} -> {:error, reason}
    end
  end

  defp finish_flight(state, ip, result) do
    entry = Map.get(state.entries, ip, new_entry())
    flight = entry.flight || %{reference: nil, waiters: []}
    state = release_monitor(state, flight.reference)

    {entry, reply} =
      case result do
        {:ok, fresh} ->
          {%{fresh | flight: nil}, {:managed, fresh}}

        {:error, reason} ->
          deferred = defer(%{entry | flight: nil})
          log_deferral(ip, reason, deferred)
          {deferred, {:error, reason}}
      end

    Enum.each(flight.waiters, fn {from, projection} ->
      GenServer.reply(from, reply(reply, projection))
    end)

    put_entry(state, ip, entry)
  end

  defp reply({:error, reason}, _projection), do: {:error, reason}
  defp reply(result, projection), do: project(result, projection)

  defp release_monitor(state, nil), do: state

  defp release_monitor(state, reference) do
    _flushed = Process.demonitor(reference, [:flush])
    %{state | flights: Map.delete(state.flights, reference)}
  end

  defp log_deferral(ip, reason, deferred) do
    Logger.warning(
      "DERP IP certificate issuance for #{ip} failed: #{inspect(reason)}; " <>
        "next attempt in #{div(deferred.next_attempt_ms - now_ms(), 1_000)}s"
    )
  end

  defp resolve(state, local_ip, server_name) do
    case parse_ip(local_ip) do
      {:ok, local_address} ->
        route_server_name(state, local_address, server_name)

      :error ->
        {:error, :unable_to_determine_local_ip, state}
    end
  end

  defp route_server_name(state, local_address, "") do
    certificate_for_ip(state, canonical(local_address))
  end

  defp route_server_name(state, local_address, server_name) do
    case parse_ip(server_name) do
      {:ok, ^local_address} ->
        certificate_for_ip(state, canonical(local_address))

      {:ok, _different_address} ->
        {:error, {:sni_ip_mismatch, server_name, canonical(local_address)}, state}

      :error ->
        next_certificate(state, server_name)
    end
  end

  defp next_certificate(%{next_provider: nil} = state, server_name) do
    {:error, {:no_certificate_for_hostname, server_name}, state}
  end

  defp next_certificate(state, server_name) do
    case state.next_provider.(server_name) do
      {:ok, certificate} -> {:ok, {:delegated, certificate}, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  # Upstream `certForIP`: serve an unexpired certificate, join an issuance
  # already running, refuse while a failed one is still backing off, and
  # otherwise start one.
  defp certificate_for_ip(state, ip) do
    entry = Map.get(state.entries, ip, new_entry())

    cond do
      holds_valid_certificate?(entry) ->
        {:ok, {:managed, entry}, state}

      not is_nil(entry.flight) ->
        {:wait, ip, state}

      backing_off?(entry) ->
        {:error, {:issuance_deferred, entry.next_attempt_ms}, state}

      true ->
        {:wait, ip, start_flight(state, ip, entry)}
    end
  end

  # Upstream doubles the delay after each failure and clamps it at thirty
  # minutes, resetting both fields once an issuance succeeds.
  defp defer(entry) do
    delay =
      if entry.retry_delay_ms == 0, do: @initial_retry_delay_ms, else: entry.retry_delay_ms

    %{
      entry
      | next_attempt_ms: now_ms() + delay,
        retry_delay_ms: min(delay * 2, @maximum_retry_delay_ms)
    }
  end

  defp backing_off?(entry), do: now_ms() < entry.next_attempt_ms

  defp holds_valid_certificate?(%{certificate: nil}), do: false
  defp holds_valid_certificate?(entry), do: valid_now?(entry)

  defp new_entry do
    %{
      certificate: nil,
      tls: nil,
      flight: nil,
      not_before: 0,
      not_after: 0,
      next_attempt_ms: 0,
      retry_delay_ms: 0
    }
  end

  # Runs in the flight process, so it takes the values it needs rather than the
  # manager's state.
  defp load_or_issue(directory, issuer, ip) do
    case load_cached(directory, ip) do
      {:ok, entry} -> {:ok, entry}
      {:error, _cache_reason} -> issue(directory, issuer, ip)
    end
  end

  defp issue(directory, issuer, ip) do
    case issuer.(ip, @short_lived_profile) do
      {:ok, %{certificate_der: certificate_der, private_key: private_key} = certificate} ->
        with :ok <- Manual.verify_certificate(certificate_der, ip),
             {:ok, entry} <- valid_entry(certificate),
             :ok <- write_cached(directory, ip, certificate_der, private_key) do
          {:ok, entry}
        else
          {:error, reason} -> {:error, {:issuance, reason}}
        end

      {:error, reason} ->
        {:error, {:issuance, reason}}
    end
  end

  defp put_entry(state, ip, entry) do
    %{state | entries: Map.put(state.entries, ip, entry)}
  end

  defp load_cached(directory, ip) do
    {certificate_path, key_path} = certificate_paths(directory, ip)

    with [{:Certificate, certificate_der, :not_encrypted} | _rest] <-
           certificate_path |> File.read!() |> :public_key.pem_decode(),
         [key_entry | _rest] <- key_path |> File.read!() |> :public_key.pem_decode(),
         private_key <- :public_key.pem_entry_decode(key_entry),
         true <- Certificates.private_key_matches?(certificate_der, private_key),
         :ok <- Manual.verify_certificate(certificate_der, ip),
         {:ok, entry} <-
           valid_entry(%{certificate_der: certificate_der, private_key: private_key}),
         false <- needs_renewal?(entry) do
      {:ok, entry}
    else
      _invalid -> {:error, :invalid_cache}
    end
  rescue
    _error -> {:error, :cache_miss}
  end

  # `Derpex.Clock` is the only time source: renewal and expiry are observable
  # server behavior, so they have to be steerable from a test clock.
  defp valid_entry(certificate) do
    case validity(certificate.certificate_der) do
      {:ok, {not_before, not_after}} ->
        entry = %{
          new_entry()
          | certificate: certificate,
            tls: certs_keys_entry(certificate),
            not_before: not_before,
            not_after: not_after
        }

        if valid_now?(entry) do
          {:ok, entry}
        else
          {:error, {:certificate_not_valid_now, not_before, not_after}}
        end

      :error ->
        {:error, :unreadable_certificate_validity}
    end
  end

  defp certs_keys_entry(%{certificate_der: certificate_der, private_key: private_key}) do
    type = elem(private_key, 0)
    %{cert: [certificate_der], key: {type, :public_key.der_encode(type, private_key)}}
  end

  defp valid_now?(entry) do
    now = Clock.system_time(:second)
    now >= entry.not_before and now <= entry.not_after
  end

  # Upstream `certNeedsRenewal`: renew once less than a third of the lifetime
  # remains, so a six-day LetsEncrypt short-lived certificate is replaced after
  # roughly four.
  defp needs_renewal?(entry) do
    now = Clock.system_time(:second)
    entry.not_after - now < div(entry.not_after - entry.not_before, 3)
  end

  defp now_ms, do: Clock.system_time(:millisecond)

  defp validity(certificate_der) do
    {:Validity, not_before, not_after} =
      certificate_der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(5)

    {:ok, {unix_seconds!(not_before), unix_seconds!(not_after)}}
  rescue
    _unreadable -> :error
  end

  # RFC 5280: a two-digit `utcTime` year of 50 or more is 19xx, otherwise 20xx.
  defp unix_seconds!({:utcTime, characters}) do
    <<year::binary-size(2), rest::binary>> = IO.chardata_to_string(characters)
    century = if String.to_integer(year) >= 50, do: "19", else: "20"
    unix_seconds!(century <> year <> rest)
  end

  defp unix_seconds!({:generalTime, characters}) do
    unix_seconds!(IO.chardata_to_string(characters))
  end

  defp unix_seconds!(
         <<year::binary-size(4), month::binary-size(2), day::binary-size(2), hour::binary-size(2),
           minute::binary-size(2), second::binary-size(2), "Z">>
       ) do
    {:ok, datetime, 0} =
      DateTime.from_iso8601("#{year}-#{month}-#{day}T#{hour}:#{minute}:#{second}Z")

    DateTime.to_unix(datetime)
  end

  defp write_cached(directory, ip, certificate_der, private_key) do
    {certificate_path, key_path} = certificate_paths(directory, ip)
    certificate_pem = :public_key.pem_encode([{:Certificate, certificate_der, :not_encrypted}])
    key_type = elem(private_key, 0)

    key_pem =
      private_key
      |> then(&:public_key.pem_entry_encode(key_type, &1))
      |> List.wrap()
      |> :public_key.pem_encode()

    with :ok <- AtomicFile.write(certificate_path, certificate_pem, mode: @certificate_mode) do
      AtomicFile.write(key_path, key_pem, mode: @key_mode)
    end
  end

  defp certificate_paths(directory, ip) do
    base = String.replace(ip, ":", ".")
    {Path.join(directory, base <> ".crt"), Path.join(directory, base <> ".key")}
  end

  defp parse_ip(ip) do
    case :inet.parse_address(String.to_charlist(ip)) do
      {:ok, address} -> {:ok, normalize_ip(address)}
      {:error, _reason} -> :error
    end
  end

  # Go compares `sniIP.Unmap()` with the connection's unmapped local address
  # and orders certificates for the unmapped form, so `::ffff:203.0.113.7` and
  # `203.0.113.7` are one address here too.
  defp normalize_ip({0, 0, 0, 0, 0, 0xFFFF, high, low}) do
    <<a, b, c, d>> = <<high::16, low::16>>
    {a, b, c, d}
  end

  defp normalize_ip(address), do: address

  defp canonical(address), do: address |> :inet.ntoa() |> IO.chardata_to_string()
end
