# This module implements the observable state machine of cmd/derper's IP certificate manager.
# Copyright (c) 2026 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Certificates.IPManager do
  @moduledoc """
  Caches and serves per-destination-IP certificates from an injected issuer.

  A cached certificate is served only while `Derpex.Clock` reports a time
  inside its validity window, and is reissued once less than a third of its
  lifetime remains — upstream `certNeedsRenewal`, which replaces a six-day
  LetsEncrypt short-lived certificate after roughly four days.

  The only issuer DERPEX ships is `self_signed_issuer/2`, reachable through
  `DERPEX_IP_CERT_ISSUER=self`. The ACME issuer this manager was modelled on
  is pending; PLAN.md section 2.3 records that.
  """

  use GenServer

  alias Derpex.AtomicFile
  alias Derpex.Certificates
  alias Derpex.Certificates.Manual
  alias Derpex.Clock
  alias Derpex.MetaCertificate

  @short_lived_profile "shortlived"
  @challenge_prefix "/.well-known/acme-challenge/"
  @certificate_mode 0o644
  @key_mode 0o600

  @type certificate :: %{certificate_der: binary(), private_key: tuple()}
  @type issuer :: (binary(), binary() -> {:ok, certificate()} | {:error, term()})
  @type next_provider :: (binary() -> {:ok, term()} | {:error, term()})

  def start_link(options) do
    GenServer.start_link(__MODULE__, options, Keyword.take(options, [:name]))
  end

  @doc "Returns a certificate for the connection's local IP and optional SNI."
  @spec certificate(GenServer.server(), binary(), binary()) ::
          {:ok, certificate() | term()} | {:error, term()}
  def certificate(manager, local_ip, server_name \\ "") do
    GenServer.call(manager, {:certificate, local_ip, server_name}, :infinity)
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

  @doc "Returns OTP TLS options for one managed certificate, DERP metacertificate appended."
  @spec tls_options(certificate(), binary()) :: keyword()
  def tls_options(certificate, <<server_public_key::binary-size(32)>>) do
    certificate_options(certificate, MetaCertificate.generate(server_public_key))
  end

  @doc """
  Returns an OTP SNI callback backed by this manager.

  OTP consults `sni_fun` only for a hello that carries a `server_name`, so a
  no-SNI hello keeps the certificate the listener bound for `local_ip`. Both
  paths therefore answer for the same local address, and a name the manager
  refuses — a mismatched IP, or a DNS name with no next provider — declines
  the handshake instead of serving the wrong certificate.
  """
  @spec sni_fun(GenServer.server(), binary(), binary()) ::
          (charlist() -> keyword() | :undefined)
  def sni_fun(manager, local_ip, <<server_public_key::binary-size(32)>>) do
    # The metacertificate only carries the server node key, so it is built once
    # per listener rather than per hello: an RSA key pair on the handshake path
    # would cost more than the DERP handshake it advertises.
    meta_certificate = MetaCertificate.generate(server_public_key)

    fn server_name ->
      case certificate(manager, local_ip, IO.chardata_to_string(server_name)) do
        {:ok, %{certificate_der: _der, private_key: _key} = certificate} ->
          certificate_options(certificate, meta_certificate)

        _no_certificate_for_this_name ->
          :undefined
      end
    end
  end

  @impl true
  def init(options) do
    directory = Keyword.fetch!(options, :directory)
    issuer = Keyword.fetch!(options, :issuer)
    :ok = AtomicFile.ensure_directory(directory)

    {:ok,
     %{
       directory: directory,
       issuer: issuer,
       next_provider: Keyword.get(options, :next_provider),
       certificates: %{},
       challenges: %{}
     }}
  end

  @impl true
  def handle_call({:certificate, local_ip, server_name}, _from, state) do
    case certificate_for_request(state, local_ip, server_name) do
      {:ok, certificate, state} -> {:reply, {:ok, certificate}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
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

  defp certificate_for_request(state, local_ip, server_name) do
    case parse_ip(local_ip) do
      {:ok, local_address} ->
        route_server_name(state, local_ip, local_address, server_name)

      :error ->
        {:error, :unable_to_determine_local_ip, state}
    end
  end

  defp route_server_name(state, local_ip, _local_address, "") do
    certificate_for_ip(state, local_ip)
  end

  defp route_server_name(state, local_ip, local_address, server_name) do
    case parse_ip(server_name) do
      {:ok, ^local_address} ->
        certificate_for_ip(state, local_ip)

      {:ok, _different_address} ->
        {:error, {:sni_ip_mismatch, server_name, local_ip}, state}

      :error ->
        next_certificate(state, server_name)
    end
  end

  defp next_certificate(%{next_provider: nil} = state, server_name) do
    {:error, {:no_certificate_for_hostname, server_name}, state}
  end

  defp next_certificate(state, server_name) do
    case state.next_provider.(server_name) do
      {:ok, certificate} -> {:ok, certificate, state}
      {:error, reason} -> {:error, reason, state}
    end
  end

  defp certificate_for_ip(state, ip) do
    case Map.fetch(state.certificates, ip) do
      {:ok, entry} ->
        serve_or_renew(state, ip, entry)

      :error ->
        load_or_issue(state, ip)
    end
  end

  defp serve_or_renew(state, ip, entry) do
    cond do
      not valid_now?(entry) -> load_or_issue(state, ip)
      needs_renewal?(entry) -> renew(state, ip, entry)
      true -> {:ok, entry.certificate, state}
    end
  end

  # A renewal that cannot reach its issuer must not take a listener's working
  # certificate away: upstream keeps serving the cached leaf until NotAfter and
  # retries, so a failed renewal falls back to the certificate still in hand.
  defp renew(state, ip, entry) do
    case issue(state, ip) do
      {:ok, certificate, state} -> {:ok, certificate, state}
      {:error, _reason, state} -> {:ok, entry.certificate, state}
    end
  end

  defp load_or_issue(state, ip) do
    case load_cached(state.directory, ip) do
      {:ok, entry} ->
        {:ok, entry.certificate, put_entry(state, ip, entry)}

      {:error, _cache_reason} ->
        issue(state, ip)
    end
  end

  defp issue(state, ip) do
    case state.issuer.(ip, @short_lived_profile) do
      {:ok, %{certificate_der: certificate_der, private_key: private_key} = certificate} ->
        with :ok <- Manual.verify_certificate(certificate_der, ip),
             {:ok, entry} <- valid_entry(certificate),
             :ok <- write_cached(state.directory, ip, certificate_der, private_key) do
          {:ok, certificate, put_entry(state, ip, entry)}
        else
          {:error, reason} -> {:error, {:issuance, reason}, state}
        end

      {:error, reason} ->
        {:error, {:issuance, reason}, state}
    end
  end

  defp put_entry(state, ip, entry) do
    %{state | certificates: Map.put(state.certificates, ip, entry)}
  end

  defp load_cached(directory, ip) do
    {certificate_path, key_path} = certificate_paths(directory, ip)

    with [{:Certificate, certificate_der, :not_encrypted} | _rest] <-
           certificate_path |> File.read!() |> :public_key.pem_decode(),
         [key_entry | _rest] <- key_path |> File.read!() |> :public_key.pem_decode(),
         private_key <- :public_key.pem_entry_decode(key_entry),
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
        entry = %{certificate: certificate, not_before: not_before, not_after: not_after}

        if valid_now?(entry) do
          {:ok, entry}
        else
          {:error, {:certificate_not_valid_now, not_before, not_after}}
        end

      :error ->
        {:error, :unreadable_certificate_validity}
    end
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

  defp certificate_options(
         %{certificate_der: certificate_der, private_key: private_key},
         meta_certificate
       ) do
    [
      certs_keys: [
        %{
          cert: Certificates.append_meta_certificate([certificate_der], meta_certificate),
          key: tls_private_key(private_key)
        }
      ]
    ]
  end

  defp tls_private_key(private_key) do
    type = elem(private_key, 0)
    {type, :public_key.der_encode(type, private_key)}
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

  defp normalize_ip({0, 0, 0, 0, 0, 0xFFFF, high, low}) do
    <<a, b, c, d>> = <<high::16, low::16>>
    {a, b, c, d}
  end

  defp normalize_ip(address), do: address
end
