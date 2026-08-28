# This module implements cmd/derper certificate-mode validation.
# Copyright (c) 2020 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Certificates.Mode do
  @moduledoc "Validates and normalizes DERP certificate provider modes."

  @gcp_directory_url "https://dv.acme-v02.api.pki.goog/directory"

  @type provider ::
          %{type: :manual, directory: Path.t(), hostname: binary()}
          | %{
              type: :acme,
              directory: Path.t(),
              hostname: binary(),
              email: binary(),
              directory_url: binary() | nil,
              eab: nil | %{kid: binary(), key: binary()}
            }
          | %{
              type: :ip_acme,
              directory: Path.t(),
              email: binary(),
              next: nil | provider()
            }

  @doc "Returns a normalized provider plan or the upstream validation error."
  @spec provider(binary(), keyword()) :: {:ok, provider()} | {:error, binary()}
  def provider(mode, options) when is_binary(mode) and is_list(options) do
    directory = Keyword.get(options, :directory, "")
    hostname = Keyword.get(options, :hostname, "")
    ip_certificates? = Keyword.get(options, :ip_certificates, false)

    cond do
      directory == "" ->
        {:error, "missing required --certdir flag"}

      ip_certificates? and mode != "letsencrypt" ->
        {:error, "--acme-ip-certs requires --certmode=letsencrypt"}

      mode in ["letsencrypt", "gcp"] ->
        automatic_provider(mode, directory, hostname, ip_certificates?, options)

      mode == "manual" ->
        {:ok, %{type: :manual, directory: directory, hostname: hostname}}

      true ->
        {:error, ~s(unsupport cert mode: #{inspect(mode)})}
    end
  end

  @doc "Allows only the production derp*.tailscale.com single-label shape."
  @spec production_hostname_allowed?(binary()) :: boolean()
  def production_hostname_allowed?(hostname) when is_binary(hostname) do
    Regex.match?(~r/^derp([^.]*)\.tailscale\.com\.?$/, hostname)
  end

  defp automatic_provider(mode, directory, hostname, ip_certificates?, options) do
    if ip_address?(hostname) do
      ip_hostname_provider(mode, directory, hostname, ip_certificates?, options)
    else
      hostname_provider(mode, directory, hostname, ip_certificates?, options)
    end
  end

  defp ip_hostname_provider("gcp", _directory, _hostname, _ip_certificates?, _options) do
    {:error, "--certmode=gcp requires --hostname to be a DNS name, not an IP address"}
  end

  defp ip_hostname_provider("letsencrypt", _directory, _hostname, false, _options) do
    {:error,
     "--hostname is an IP address; use --certmode=manual for a self-signed cert, or set --acme-ip-certs to get LetsEncrypt IP address certs"}
  end

  defp ip_hostname_provider("letsencrypt", directory, _hostname, true, options) do
    {:ok,
     %{
       type: :ip_acme,
       directory: directory,
       email: Keyword.get(options, :email, ""),
       next: nil
     }}
  end

  defp hostname_provider(mode, directory, hostname, ip_certificates?, options) do
    with {:ok, eab, directory_url} <- gcp_options(mode, options) do
      provider = %{
        type: :acme,
        directory: directory,
        hostname: hostname,
        email: default_email(hostname, Keyword.get(options, :email, "")),
        directory_url: directory_url,
        eab: eab
      }

      if ip_certificates? do
        {:ok,
         %{
           type: :ip_acme,
           directory: directory,
           email: Keyword.get(options, :email, ""),
           next: provider
         }}
      else
        {:ok, provider}
      end
    end
  end

  defp gcp_options("letsencrypt", _options), do: {:ok, nil, nil}

  defp gcp_options("gcp", options) do
    kid = Keyword.get(options, :eab_kid, "")
    encoded_key = Keyword.get(options, :eab_key, "")
    email = Keyword.get(options, :email, "")

    cond do
      kid == "" or encoded_key == "" ->
        {:error, "--certmode=gcp requires --acme-eab-kid and --acme-eab-key flags"}

      email == "" ->
        {:error, "--certmode=gcp requires --acme-email flag"}

      true ->
        case decode_eab_key(encoded_key) do
          {:ok, key} -> {:ok, %{kid: kid, key: key}, @gcp_directory_url}
          :error -> {:error, "invalid --acme-eab-key: expected base64 or unpadded base64url"}
        end
    end
  end

  defp decode_eab_key(encoded) do
    case Base.url_decode64(encoded, padding: false) do
      {:ok, key} -> {:ok, key}
      :error -> Base.decode64(encoded)
    end
  end

  defp default_email("derp.tailscale.com", ""), do: "security@tailscale.com"
  defp default_email(_hostname, email), do: email

  defp ip_address?(hostname) do
    match?({:ok, _address}, :inet.parse_address(String.to_charlist(hostname)))
  end
end
