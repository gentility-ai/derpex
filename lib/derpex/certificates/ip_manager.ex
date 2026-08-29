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

  Two issuers exist. `Derpex.ACME.Client` orders from a certificate authority
  and is what `DERPEX_CERT_MODE=letsencrypt` and `gcp` use; `self_signed_issuer/2`
  issues locally and is what `DERPEX_IP_CERT_ISSUER=self` uses.

  `:next_provider` is the seam upstream uses to hand a DNS hello to a separate
  autocert manager. DERPEX has no second provider to delegate to, because this
  manager orders hostname certificates itself when it is configured with
  `:hostnames`, so the option has no production caller and exists for the
  delegation test alone.
  """

  use GenServer

  import Bitwise, only: [<<<: 2]

  require Logger

  alias Derpex.AtomicFile
  alias Derpex.Certificates
  alias Derpex.Certificates.Manual
  alias Derpex.Clock
  alias Derpex.Secret

  @short_lived_profile "shortlived"
  @challenge_prefix "/.well-known/acme-challenge/"
  @certificate_mode 0o644
  @key_mode 0o600

  # Upstream `startFlightLocked`: one minute after the first failure, doubling
  # to a thirty-minute ceiling, and `renewLoop`, which wakes hourly.
  @initial_retry_delay_ms 60_000
  @maximum_retry_delay_ms 30 * 60_000
  @renew_interval_ms 60 * 60_000
  @bootstrap_report_interval_ms 60_000
  @bootstrap_key {__MODULE__, :bootstrap_subjects}
  @never -(1 <<< 60)

  @type certificate :: %{
          :certificate_der => binary(),
          :private_key => tuple(),
          optional(:chain) => [binary()]
        }

  @typedoc """
  What `certificate/3` returns.

  The private key an issuer supplied is deliberately absent: it is needed to
  serve TLS and for nothing else, so it is encoded once at issuance, wrapped,
  and handed only to `:ssl`. Nothing that asks this manager for a certificate
  is given the key that goes with it.
  """
  @type served :: %{:certificate_der => binary(), optional(:chain) => [binary()]}
  @type issuer :: (binary(), binary() -> {:ok, certificate()} | {:error, term()})
  @type next_provider :: (binary() -> {:ok, term()} | {:error, term()})
  @type certs_keys :: %{cert: [binary()], key: {atom(), binary()}}

  def start_link(options) do
    GenServer.start_link(__MODULE__, options, Keyword.take(options, [:name]))
  end

  @doc "Returns a certificate for the connection's local IP and optional SNI."
  @spec certificate(GenServer.server(), binary(), binary()) ::
          {:ok, served() | term()} | {:error, term()}
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

  @doc """
  Publishes this manager's certificate for one subject into a listener snapshot.

  A listen socket binds one certificate and cannot be told about a renewal, so
  the listener reads the current one per connection out of `:persistent_term`.
  The listener supervisor calls this once, after the manager has started and
  before the socket is opened.

  Returns `{:ok, certs_keys}` when a certificate is already in hand — the
  common case on restart, read from the disk cache — and `:bootstrap` when
  there is not one yet. In the second case the listener binds a self-signed
  placeholder and this manager orders the real certificate in the background,
  publishing it into the snapshot when it arrives. Nothing here blocks on a
  certificate authority: the listener that answers HTTP-01 challenges may not
  have accepted its first connection yet.
  """
  @spec publish_to(GenServer.server(), term(), binary(), binary()) ::
          {:ok, certs_keys()} | :bootstrap
  def publish_to(manager, snapshot_key, subject, meta_certificate) do
    GenServer.call(manager, {:publish_to, snapshot_key, subject, meta_certificate}, :infinity)
  end

  @doc """
  Orders a certificate for `subject` if there is not already one in hand.

  Called after the listeners are accepting, because an HTTP-01 challenge is
  only answerable once the plaintext listener is bound.
  """
  @spec ensure(GenServer.server(), binary()) :: :ok
  def ensure(manager, subject) do
    send(manager_pid(manager), {:ensure, canonical_subject(subject)})
    :ok
  end

  defp manager_pid(manager) when is_pid(manager), do: manager
  defp manager_pid(manager), do: GenServer.whereis(manager) || manager

  @doc "Subjects whose listener is serving a self-signed placeholder."
  @spec bootstrap_subjects() :: MapSet.t(binary())
  def bootstrap_subjects, do: :persistent_term.get(@bootstrap_key, MapSet.new())

  @doc "Whether any listener is serving a placeholder instead of its certificate."
  @spec bootstrap_certificate_active?() :: boolean()
  def bootstrap_certificate_active?, do: MapSet.size(bootstrap_subjects()) > 0

  @doc false
  @spec mark_bootstrap(binary()) :: :ok
  def mark_bootstrap(subject) do
    :persistent_term.put(
      @bootstrap_key,
      MapSet.put(bootstrap_subjects(), canonical_subject(subject))
    )
  end

  defp clear_bootstrap(subject) do
    subjects = bootstrap_subjects()

    if MapSet.member?(subjects, subject) do
      :persistent_term.put(@bootstrap_key, MapSet.delete(subjects, subject))
    end

    :ok
  end

  defp canonical_subject(subject) do
    case :inet.parse_address(String.to_charlist(subject)) do
      {:ok, address} -> address |> normalize_ip() |> canonical()
      {:error, _reason} -> String.downcase(subject, :ascii)
    end
  end

  @doc "Returns a challenge response, not-found, or fallback decision."
  @spec http_response(GenServer.server(), binary()) ::
          {:ok, binary()} | :not_found | :fallback
  def http_response(manager, path), do: GenServer.call(manager, {:http_response, path})

  @doc "The ACME profile required for short-lived IP certificates."
  @spec profile() :: binary()
  def profile, do: @short_lived_profile

  # The shortlived profile is a requirement of IP address certificates, not of
  # certificates in general, so a DNS hostname is ordered without one.
  defp profile_for(subject) do
    case :inet.parse_address(String.to_charlist(subject)) do
      {:ok, _address} -> @short_lived_profile
      {:error, _reason} -> nil
    end
  end

  defp hostnames(names) do
    Enum.map(List.wrap(names), &String.downcase(&1, :ascii))
  end

  @doc """
  Issues a persistent self-signed certificate for `ip`.

  It contacts no certificate authority, so `DERPEX_IP_CERT_ISSUER=self` works
  on a relay that no authority can reach — and, because it is instant, it is
  also what a listener binds as a placeholder while a real order is running.
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
    # Exits are trapped so `terminate/2` runs on shutdown: a manager that is
    # stopping is no longer serving a placeholder, and the readiness probe has
    # to stop saying that it is.
    Process.flag(:trap_exit, true)
    directory = Keyword.fetch!(options, :directory)
    issuer = Keyword.fetch!(options, :issuer)
    :ok = AtomicFile.ensure_directory(directory)

    state = %{
      directory: directory,
      issuer: issuer,
      next_provider: Keyword.get(options, :next_provider),
      hostnames: hostnames(Keyword.get(options, :hostnames, [])),
      snapshot: Keyword.get(options, :snapshot),
      renew_interval_ms: Keyword.get(options, :renew_interval_ms, @renew_interval_ms),
      entries: %{},
      flights: %{},
      bootstrap_reports: %{},
      challenges: %{}
    }

    {:ok, schedule_renewal(state)}
  end

  # `:sys.get_state/1`, `:observer`, and every crash report route through this,
  # and this process holds one private key per certificate plus the key
  # authorizations it is publishing. None of that is replaced by a summary
  # elsewhere, so it is replaced here, once, for all of them.
  @impl true
  def format_status(status) do
    Map.update(status, :state, nil, &redact/1)
  end

  defp redact(%{entries: entries, challenges: challenges} = state) do
    %{
      state
      | entries: Map.new(entries, fn {subject, entry} -> {subject, redact_entry(entry)} end),
        challenges:
          Map.new(challenges, fn {path, {_response, owner}} -> {path, {:redacted, owner}} end)
    }
    |> Map.put(:issuer, :redacted)
    |> Map.put(:next_provider, :redacted)
  end

  defp redact(state), do: state

  defp redact_entry(entry), do: Map.replace(entry, :tls, redact_tls(entry.tls))

  defp redact_tls(nil), do: nil
  defp redact_tls(tls), do: Map.put(tls, :key, :redacted)

  # A manager that is gone is not serving a placeholder, so its subject leaves
  # the set the readiness probe and the gauge read.
  @impl true
  def terminate(_reason, %{snapshot: {_key, subject, _meta}}), do: clear_bootstrap(subject)
  def terminate(_reason, _state), do: :ok

  @impl true
  def handle_call({:certificate, local_ip, server_name}, from, state) do
    answer(state, local_ip, server_name, from, :certificate)
  end

  def handle_call({:certs_keys, local_ip, server_name}, from, state) do
    answer(state, local_ip, server_name, from, :certs_keys)
  end

  def handle_call({:publish_to, key, subject, meta_certificate}, _from, state) do
    subject = canonical_subject(subject)
    state = %{state | snapshot: {key, subject, meta_certificate}}
    state = load_cached_entry(state, subject)

    case Map.get(state.entries, subject) do
      %{tls: %{} = tls} = entry ->
        publish_snapshot(state, subject, entry)
        :ok = clear_bootstrap(subject)
        {:reply, {:ok, with_meta_certificate(tls, meta_certificate)}, state}

      _no_certificate_yet ->
        # No order is started here. `init/1` of the listener supervisor runs
        # before any listener has bound, so an order begun now would publish a
        # challenge nothing can answer. `ensure/2` is called once the listeners
        # are accepting.
        :ok = mark_bootstrap(subject)
        {:reply, :bootstrap, state}
    end
  end

  def handle_call({:put_challenge, path, response}, {owner, _tag}, state) do
    {:reply, :ok, put_in(state, [:challenges, path], {response, owner})}
  end

  def handle_call({:delete_challenge, path}, _from, state) do
    {:reply, :ok, %{state | challenges: Map.delete(state.challenges, path)}}
  end

  def handle_call({:http_response, path}, _from, state) do
    response =
      if String.starts_with?(path, @challenge_prefix) do
        case Map.fetch(state.challenges, path) do
          {:ok, {body, _owner}} -> {:ok, body}
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
  def handle_info({:ensure, subject}, state) do
    entry = Map.get(state.entries, subject, new_entry())

    if holds_valid_certificate?(entry) or not is_nil(entry.flight) or backing_off?(entry) do
      {:noreply, state}
    else
      {:noreply, start_flight(state, subject, entry)}
    end
  end

  def handle_info({:flight, ip, result}, state) do
    {:noreply, finish_flight(state, ip, result)}
  end

  def handle_info({:EXIT, _pid, _reason}, state), do: {:noreply, state}

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

  # The tick renews what is close to expiry and retries what never arrived: a
  # listener still serving a placeholder because the authority was unreachable
  # has to be brought out of it without a restart.
  defp renewable?(entry) do
    is_nil(entry.flight) and not backing_off?(entry) and
      (is_nil(entry.certificate) or needs_renewal?(entry))
  end

  defp answer(state, local_ip, server_name, from, projection) do
    case resolve(state, local_ip, server_name) do
      {:ok, result, state} -> {:reply, project(result, projection), state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
      {:wait, ip, state} -> {:noreply, add_waiter(state, ip, from, projection)}
    end
  end

  defp project({:managed, entry}, :certificate), do: {:ok, entry.certificate}
  defp project({:managed, entry}, :certs_keys), do: {:ok, revealed(entry.tls)}
  defp project({:delegated, certificate}, :certificate), do: {:ok, certificate}

  defp project({:delegated, _certificate}, :certs_keys),
    do: {:error, :next_provider_certificate_not_supported}

  defp add_waiter(state, ip, from, projection) do
    update_in(state.entries[ip].flight.waiters, &[{from, projection} | &1])
  end

  # The flight is linked as well as monitored: a manager that goes down takes
  # its outstanding orders with it rather than leaving one running against a
  # certificate authority with nowhere to deliver. Exits are trapped, so the
  # link never propagates a failure into this process.
  defp start_flight(state, ip, entry) do
    manager = self()
    directory = state.directory
    issuer = state.issuer

    pid =
      spawn_link(fn ->
        send(manager, {:flight, ip, flight_result(directory, issuer, ip)})
      end)

    reference = Process.monitor(pid)
    flight = %{reference: reference, pid: pid, waiters: []}
    state = put_entry(state, ip, %{entry | flight: flight})
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
    flight = entry.flight || %{reference: nil, pid: nil, waiters: []}
    state = state |> release_monitor(flight.reference) |> reclaim_challenges(flight.pid)

    {entry, reply} =
      case result do
        {:ok, fresh} ->
          {%{fresh | flight: nil}, {:managed, fresh}}

        {:error, reason} ->
          deferred = defer(%{entry | flight: nil})
          {deferred, {:error, reason}}
      end

    state =
      case result do
        {:ok, _fresh} -> state
        {:error, reason} -> log_deferral(state, ip, reason, entry)
      end

    # The entry is committed before anyone is told about it: a caller that is
    # released first could otherwise observe the manager without the
    # certificate it was just handed.
    state = put_entry(state, ip, entry)

    Enum.each(flight.waiters, fn {from, projection} ->
      GenServer.reply(from, reply(reply, projection))
    end)

    state
  end

  defp reply({:error, reason}, _projection), do: {:error, reason}
  defp reply(result, projection), do: project(result, projection)

  # An order removes its own challenge when it finishes, but an order that died
  # cannot, and a token left answering is a credential left lying around.
  defp reclaim_challenges(state, nil), do: state

  defp reclaim_challenges(state, pid) do
    challenges =
      Map.reject(state.challenges, fn {_path, {_response, owner}} -> owner == pid end)

    %{state | challenges: challenges}
  end

  defp release_monitor(state, nil), do: state

  defp release_monitor(state, reference) do
    _flushed = Process.demonitor(reference, [:flush])
    %{state | flights: Map.delete(state.flights, reference)}
  end

  # A listener still serving a placeholder is an outage in waiting, so it is
  # reported at error rather than warning — throttled, because the retry that
  # produces it is on a timer and must not turn the log into the incident.
  defp log_deferral(state, ip, reason, deferred) do
    seconds = div(deferred.next_attempt_ms - now_ms(), 1_000)

    message =
      "DERP certificate issuance for #{ip} failed: #{inspect(reason)}; " <>
        "next attempt in #{seconds}s"

    if MapSet.member?(bootstrap_subjects(), ip) do
      report_bootstrap(state, ip, message)
    else
      Logger.warning(message)
      state
    end
  end

  defp report_bootstrap(state, ip, message) do
    now = Clock.monotonic_time(:millisecond)
    last = Map.get(state.bootstrap_reports, ip, @never)

    if now - last >= @bootstrap_report_interval_ms do
      Logger.error(
        message <>
          "; the listener is serving a self-signed placeholder for #{ip} and is not ready"
      )

      %{state | bootstrap_reports: Map.put(state.bootstrap_reports, ip, now)}
    else
      state
    end
  end

  defp resolve(state, local, server_name) do
    case parse_ip(local) do
      {:ok, local_address} -> route_server_name(state, local_address, server_name)
      :error -> route_hostname(state, local, server_name)
    end
  end

  defp route_server_name(state, local_address, "") do
    certificate_for_subject(state, canonical(local_address))
  end

  defp route_server_name(state, local_address, server_name) do
    case parse_ip(server_name) do
      {:ok, ^local_address} ->
        certificate_for_subject(state, canonical(local_address))

      {:ok, _different_address} ->
        {:error, {:sni_ip_mismatch, server_name, canonical(local_address)}, state}

      :error ->
        hostname_certificate(state, server_name)
    end
  end

  # A listener bound for a DNS hostname rather than a bare address: the
  # certificate is ordered for the name it was configured with, and a hello
  # naming anything else is refused rather than answered with it.
  defp route_hostname(state, hostname, "") do
    if configured?(state, hostname) do
      certificate_for_subject(state, String.downcase(hostname, :ascii))
    else
      {:error, :unable_to_determine_local_ip, state}
    end
  end

  defp route_hostname(state, hostname, server_name) do
    if configured?(state, hostname) and matches?(hostname, server_name) do
      certificate_for_subject(state, String.downcase(hostname, :ascii))
    else
      hostname_certificate(state, server_name)
    end
  end

  defp hostname_certificate(state, server_name) do
    if configured?(state, server_name) do
      certificate_for_subject(state, String.downcase(server_name, :ascii))
    else
      next_certificate(state, server_name)
    end
  end

  defp configured?(state, hostname) do
    String.downcase(hostname, :ascii) in state.hostnames
  end

  defp matches?(hostname, server_name) do
    String.downcase(hostname, :ascii) == String.downcase(server_name, :ascii)
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
  defp certificate_for_subject(state, ip) do
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
    case issuer.(ip, profile_for(ip)) do
      {:ok, %{certificate_der: certificate_der, private_key: private_key} = certificate} ->
        with :ok <- Manual.verify_certificate(certificate_der, ip),
             {:ok, entry} <- valid_entry(certificate),
             :ok <- write_cached(directory, ip, chain(certificate), private_key) do
          {:ok, entry}
        else
          {:error, reason} -> {:error, {:issuance, reason}}
        end

      {:error, reason} ->
        {:error, {:issuance, reason}}
    end
  end

  defp put_entry(state, ip, entry) do
    publish_snapshot(state, ip, entry)
    %{state | entries: Map.put(state.entries, ip, entry)}
  end

  # A listen socket binds one certificate and cannot be told about a renewal,
  # so the listener reads the current one per connection out of a
  # `:persistent_term` snapshot — the same mechanism a rotated file-backed
  # certificate uses. Without this a renewed certificate would reach clients
  # that send SNI and never reach those that do not.
  defp publish_snapshot(%{snapshot: nil}, _ip, _entry), do: :ok

  defp publish_snapshot(%{snapshot: {key, subject, meta_certificate}}, ip, entry) do
    if ip == subject and not is_nil(entry.tls) do
      :persistent_term.put(key, [with_meta_certificate(entry.tls, meta_certificate)])
      :ok = clear_bootstrap(subject)
    end

    :ok
  end

  # Revealed only on the way out, to `:ssl`, which needs the bytes.
  defp revealed(%{key: {type, key}} = tls), do: %{tls | key: {type, Secret.reveal(key)}}

  # Revealed only here, on its way to `:ssl`, which needs the bytes.
  defp with_meta_certificate(%{key: {type, key}} = tls, meta_certificate) do
    %{
      cert: Certificates.append_meta_certificate(tls.cert, meta_certificate),
      key: {type, Secret.reveal(key)}
    }
  end

  defp load_cached_entry(state, subject) do
    case Map.fetch(state.entries, subject) do
      {:ok, _entry} ->
        state

      :error ->
        case load_cached(state.directory, subject) do
          {:ok, entry} -> put_entry(state, subject, entry)
          {:error, _reason} -> state
        end
    end
  end

  defp load_cached(directory, ip) do
    {certificate_path, key_path} = certificate_paths(directory, ip)

    with [certificate_der | _intermediates] = chain <-
           certificate_path |> File.read!() |> chain_from_pem(),
         [key_entry | _rest] <- key_path |> File.read!() |> :public_key.pem_decode(),
         private_key <- :public_key.pem_entry_decode(key_entry),
         true <- Certificates.private_key_matches?(certificate_der, private_key),
         :ok <- Manual.verify_certificate(certificate_der, ip),
         {:ok, entry} <-
           valid_entry(%{
             certificate_der: certificate_der,
             chain: chain,
             private_key: private_key
           }),
         false <- needs_renewal?(entry) do
      {:ok, entry}
    else
      _invalid -> {:error, :invalid_cache}
    end
  rescue
    _error -> {:error, :cache_miss}
  end

  defp chain_from_pem(pem) do
    Enum.flat_map(:public_key.pem_decode(pem), fn
      {:Certificate, der, :not_encrypted} -> [der]
      _other -> []
    end)
  end

  # `Derpex.Clock` is the only time source: renewal and expiry are observable
  # server behavior, so they have to be steerable from a test clock.
  defp valid_entry(certificate) do
    case validity(certificate.certificate_der) do
      {:ok, {not_before, not_after}} ->
        entry = %{
          new_entry()
          | certificate: Map.delete(certificate, :private_key),
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

  # A certificate authority returns the leaf followed by the intermediates a
  # client needs to build a path, so the whole chain is what gets served and
  # cached. A self-signed issuer returns a leaf and nothing else.
  # The encoded key is wrapped: this map lives in the manager's state, and an
  # exception's arguments are rendered into a crash report whatever
  # `format_status/1` does with the state itself.
  defp certs_keys_entry(%{private_key: private_key} = certificate) do
    type = elem(private_key, 0)
    key = Secret.wrap(:public_key.der_encode(type, private_key))
    %{cert: chain(certificate), key: {type, key}}
  end

  defp chain(%{chain: [_leaf | _rest] = chain}), do: chain
  defp chain(%{certificate_der: certificate_der}), do: [certificate_der]

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

  defp write_cached(directory, ip, chain, private_key) do
    {certificate_path, key_path} = certificate_paths(directory, ip)

    certificate_pem =
      chain
      |> Enum.map(&{:Certificate, &1, :not_encrypted})
      |> :public_key.pem_encode()

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
