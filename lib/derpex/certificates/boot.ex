defmodule Derpex.Certificates.Boot do
  @moduledoc """
  Resolves the certificate configuration a relay is allowed to boot with.

  DERPEX implements the `manual` certificate mode. `letsencrypt` and `gcp` both
  need an RFC 8555 ACME client, which DERPEX has not written yet, so they are
  refused here instead of being accepted and silently downgraded to a
  self-signed certificate. PLAN.md section 2.3 records ACME as pending, and the
  `TestIPCertManager` inventory rows stay `pending` until it exists.

  `Derpex.Certificates.IPManager` is therefore reachable only through
  `DERPEX_IP_CERT_ISSUER=self`, which issues the same persistent self-signed
  per-IP certificate `Derpex.Certificates.Manual` already creates. That is a
  local issuer, not an ACME one: nothing here talks to a certificate authority.
  """

  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Mode

  @manager IPManager

  @type plan :: %{
          mode: :manual,
          directory: Path.t(),
          hostname: binary(),
          ip_certificate_issuer: nil | :self
        }

  @doc "Returns the boot certificate plan, or the error that must stop the boot."
  @spec plan(keyword()) :: {:ok, plan()} | {:error, binary()}
  def plan(options \\ []) when is_list(options) do
    mode = text(Keyword.get(options, :mode), "manual")
    directory = text(Keyword.get(options, :directory), "")
    hostname = text(Keyword.get(options, :hostname), "")

    with {:ok, issuer} <- issuer(Keyword.get(options, :ip_certificate_issuer)),
         :ok <- validate_mode(mode, directory, hostname, options),
         :ok <- validate_operator_certificates(issuer, options),
         :ok <- validate_issuer(issuer, directory, hostname) do
      {:ok,
       %{
         mode: :manual,
         directory: directory,
         hostname: hostname,
         ip_certificate_issuer: issuer
       }}
    end
  end

  @doc "Returns the boot certificate plan or raises the operator-facing error."
  @spec plan!(keyword()) :: plan()
  def plan!(options \\ []) do
    case plan(options) do
      {:ok, plan} -> plan
      {:error, message} -> raise ArgumentError, message
    end
  end

  @doc "Returns the certificate children a plan needs, before any listener starts."
  @spec children(plan()) :: [Supervisor.child_spec() | {module(), term()}]
  def children(%{ip_certificate_issuer: :self, directory: directory}) do
    [
      {@manager, name: @manager, directory: directory, issuer: &IPManager.self_signed_issuer/2}
    ]
  end

  def children(%{ip_certificate_issuer: nil}), do: []

  @doc "Points one listener at the certificate manager this plan started, if any."
  @spec listener_options(plan(), keyword()) :: keyword()
  def listener_options(%{ip_certificate_issuer: :self, hostname: hostname}, listener) do
    Keyword.put(listener, :ip_certificate_manager, {@manager, hostname})
  end

  def listener_options(%{ip_certificate_issuer: nil}, listener), do: listener

  # A manual relay with no certificate directory is the file-backed listener
  # DERPEX has always booted with, so upstream's `--certdir` rule only applies
  # once a directory is actually configured.
  defp validate_mode("manual", "", _hostname, _options), do: :ok

  defp validate_mode("manual", directory, hostname, options) do
    options = Keyword.merge(options, directory: directory, hostname: hostname)

    case Mode.provider("manual", options) do
      {:ok, _provider} -> :ok
      {:error, message} -> {:error, message}
    end
  end

  defp validate_mode(mode, _directory, _hostname, _options)
       when mode in ["letsencrypt", "gcp"] do
    {:error,
     "DERPEX_CERT_MODE=#{mode} needs an RFC 8555 ACME client, which DERPEX has not " <>
       "implemented yet (PLAN.md section 2.3 records ACME as pending). Use " <>
       "DERPEX_CERT_MODE=manual with DERPEX_TLS_CERTFILE and DERPEX_TLS_KEYFILE, or " <>
       "DERPEX_IP_CERT_ISSUER=self for a self-signed per-IP certificate."}
  end

  defp validate_mode(mode, _directory, _hostname, _options) do
    {:error, ~s(unsupport cert mode: #{inspect(mode)})}
  end

  defp issuer(nil), do: {:ok, nil}
  defp issuer(""), do: {:ok, nil}
  defp issuer(:self), do: {:ok, :self}
  defp issuer("self"), do: {:ok, :self}

  defp issuer(other) do
    {:error,
     "DERPEX_IP_CERT_ISSUER must be \"self\", got #{inspect(other)}. ACME-issued IP " <>
       "certificates need an RFC 8555 client, which DERPEX has not implemented yet " <>
       "(PLAN.md section 2.3 records ACME as pending)."}
  end

  # Two certificate sources for one listener is an operator mistake with a
  # silent outcome — whichever the listener happens to bind wins — so it is
  # refused rather than resolved by precedence.
  defp validate_operator_certificates(nil, _options), do: :ok

  defp validate_operator_certificates(:self, options) do
    if is_nil(Keyword.get(options, :certfile)) and is_nil(Keyword.get(options, :keyfile)) do
      :ok
    else
      {:error,
       "DERPEX_IP_CERT_ISSUER=self issues the listener's certificate itself and cannot be " <>
         "combined with DERPEX_TLS_CERTFILE or DERPEX_TLS_KEYFILE. Unset the operator " <>
         "certificate paths, or unset DERPEX_IP_CERT_ISSUER to serve them."}
    end
  end

  defp validate_issuer(nil, _directory, _hostname), do: :ok

  defp validate_issuer(:self, "", _hostname) do
    {:error, "DERPEX_IP_CERT_ISSUER=self requires DERPEX_CERT_DIR"}
  end

  defp validate_issuer(:self, _directory, hostname) do
    case :inet.parse_address(String.to_charlist(hostname)) do
      {:ok, _address} ->
        :ok

      {:error, _reason} ->
        {:error,
         "DERPEX_IP_CERT_ISSUER=self requires DERPEX_CERT_HOSTNAME to be an IP address, " <>
           "got #{inspect(hostname)}"}
    end
  end

  defp text(nil, default), do: default
  defp text(value, _default) when is_binary(value), do: value
end
