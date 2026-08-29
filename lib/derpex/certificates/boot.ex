defmodule Derpex.Certificates.Boot do
  @moduledoc """
  Resolves the certificate configuration a relay is allowed to boot with.

  Four sources of a listener certificate, in the order an operator meets them:

  - `DERPEX_CERT_MODE=manual` with `DERPEX_TLS_CERTFILE` and
    `DERPEX_TLS_KEYFILE`, the file-backed listener DERPEX has always had;
  - `DERPEX_IP_CERT_ISSUER=self`, a persistent self-signed per-IP certificate
    that contacts no certificate authority;
  - `DERPEX_CERT_MODE=letsencrypt`, ACME over HTTP-01, for a DNS hostname or —
    with `DERPEX_IP_CERT_ISSUER=acme` — for the address a connection arrives
    on, under the six-day `shortlived` profile;
  - `DERPEX_CERT_MODE=gcp`, the same with an external account binding.

  An ACME mode needs somewhere to answer challenges, so it also requires a
  plaintext HTTP listener: a certificate authority validates HTTP-01 by
  connecting to port 80 at the identifier being validated. That is checked here
  rather than discovered when the first order times out.
  """

  alias Derpex.ACME
  alias Derpex.Certificates.IPManager
  alias Derpex.Certificates.Mode

  @manager IPManager
  @client ACME.Client

  @type plan :: %{
          mode: :manual | :acme,
          directory: Path.t(),
          hostname: binary(),
          ip_certificate_issuer: nil | :self | :acme,
          ip_certificates: boolean(),
          acme: nil | map()
        }

  @doc "Returns the boot certificate plan, or the error that must stop the boot."
  @spec plan(keyword()) :: {:ok, plan()} | {:error, binary()}
  def plan(options \\ []) when is_list(options) do
    mode = text(Keyword.get(options, :mode), "manual")
    directory = text(Keyword.get(options, :directory), "")
    hostname = text(Keyword.get(options, :hostname), "")

    requested = Keyword.get(options, :ip_certificate_issuer)

    with {:ok, issuer} <- issuer(mode, requested),
         {:ok, provider} <- provider(mode, directory, hostname, requested, options),
         :ok <- validate_operator_certificates(issuer, provider, options),
         :ok <- validate_issuer(issuer, directory, hostname),
         :ok <- validate_challenge_listener(provider, options) do
      {:ok, build(mode, directory, hostname, issuer, provider, requested, options)}
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
  def children(%{ip_certificate_issuer: nil}), do: []

  def children(%{ip_certificate_issuer: :self, directory: directory}) do
    [{@manager, name: @manager, directory: directory, issuer: &IPManager.self_signed_issuer/2}]
  end

  def children(%{ip_certificate_issuer: :acme} = plan) do
    [
      {@client,
       name: @client,
       directory: plan.directory,
       directory_url: plan.acme.directory_url,
       email: plan.acme.email,
       external_account: plan.acme.external_account,
       challenge: {@manager, @manager}},
      {@manager,
       name: @manager,
       directory: plan.directory,
       hostnames: plan.acme.hostnames,
       issuer: acme_issuer()}
    ]
  end

  @doc """
  Points one listener at the pieces this plan started.

  A listener marked `plaintext_challenge: true` is the HTTP-01 responder and
  gets the challenge source; every other listener is the TLS one and gets the
  certificate manager.
  """
  @spec listener_options(plan(), keyword()) :: keyword()
  def listener_options(plan, listener) do
    {challenge_responder?, listener} = Keyword.pop(listener, :plaintext_challenge, false)

    cond do
      challenge_responder? -> put_handler_options(listener, challenge_options(plan))
      plan.ip_certificate_issuer == nil -> listener
      true -> Keyword.put(listener, :ip_certificate_manager, {@manager, plan.hostname})
    end
  end

  defp put_handler_options(listener, []), do: listener

  defp put_handler_options(listener, options) do
    Keyword.update(listener, :handler_options, options, &Keyword.merge(&1, options))
  end

  @doc """
  Children that must start only once every listener is accepting.

  The first order publishes an HTTP-01 challenge that a certificate authority
  fetches over the plaintext listener, so it cannot begin while the listener
  supervisor is still building its children.
  """
  @spec post_listener_children(plan()) :: [Supervisor.child_spec()]
  def post_listener_children(%{ip_certificate_issuer: nil}), do: []

  def post_listener_children(%{hostname: hostname}) do
    [
      Supervisor.child_spec({Task, fn -> IPManager.ensure(@manager, hostname) end},
        id: {@manager, :bootstrap},
        restart: :transient
      )
    ]
  end

  @doc "Returns the HTTP-01 challenge source to give a plaintext listener."
  @spec challenge_options(plan()) :: keyword()
  def challenge_options(%{ip_certificate_issuer: :acme}) do
    [acme_challenges: {@manager, @manager}]
  end

  def challenge_options(_plan), do: []

  # The client is started before the manager, so the issuer resolves it by name
  # rather than capturing a pid that does not exist yet.
  defp acme_issuer do
    fn subject, profile -> ACME.Client.issue(@client, ACME.Client.identify(subject), profile) end
  end

  defp build(mode, directory, hostname, issuer, provider, requested, options) do
    %{
      mode: if(mode == "manual", do: :manual, else: :acme),
      directory: directory,
      hostname: hostname,
      ip_certificate_issuer: issuer,
      ip_certificates: requested == "acme" or requested == :acme,
      acme: acme(provider, hostname, options)
    }
  end

  defp acme(nil, _hostname, _options), do: nil

  defp acme(provider, hostname, options) do
    %{
      directory_url: Keyword.get(options, :directory_url) || directory_url(provider),
      email: email(provider),
      external_account: external_account(provider),
      hostnames: if(ip_address?(hostname), do: [], else: [hostname])
    }
  end

  defp directory_url(%{directory_url: url}) when is_binary(url), do: url
  defp directory_url(%{next: %{directory_url: url}}) when is_binary(url), do: url
  defp directory_url(_provider), do: "https://acme-v02.api.letsencrypt.org/directory"

  defp email(%{email: email}) when is_binary(email) and email != "", do: email
  defp email(%{next: %{email: email}}) when is_binary(email) and email != "", do: email
  defp email(_provider), do: nil

  defp external_account(%{eab: %{} = eab}), do: eab
  defp external_account(%{next: %{eab: %{} = eab}}), do: eab
  defp external_account(_provider), do: nil

  # `manual` with no certificate directory is the file-backed listener DERPEX
  # has always booted with, so upstream's `--certdir` rule only applies once a
  # directory is actually configured.
  defp provider("manual", "", _hostname, _issuer, _options), do: {:ok, nil}

  defp provider(mode, directory, hostname, requested, options)
       when mode in ["manual", "letsencrypt", "gcp"] do
    options =
      options
      |> Keyword.merge(directory: directory, hostname: hostname)
      |> Keyword.put(:ip_certificates, requested in ["acme", :acme])

    case Mode.provider(mode, options) do
      {:ok, %{type: :manual}} -> {:ok, nil}
      {:ok, provider} -> {:ok, provider}
      {:error, message} -> {:error, message}
    end
  end

  defp provider(mode, _directory, _hostname, _issuer, _options) do
    {:error, ~s(unsupport cert mode: #{inspect(mode)})}
  end

  # An ACME mode always serves through the certificate manager, so it selects
  # the ACME issuer on its own. `DERPEX_IP_CERT_ISSUER=acme` is the separate,
  # explicit opt-in to ordering a certificate for whatever address a connection
  # arrives on, which is upstream's `--acme-ip-certs`.
  defp issuer(mode, unset) when unset in [nil, ""] do
    if mode in ["letsencrypt", "gcp"], do: {:ok, :acme}, else: {:ok, nil}
  end

  defp issuer(_mode, self_issuer) when self_issuer in [:self, "self"], do: {:ok, :self}

  defp issuer(mode, acme) when acme in [:acme, "acme"] do
    if mode in ["letsencrypt", "gcp"] do
      {:ok, :acme}
    else
      {:error,
       "DERPEX_IP_CERT_ISSUER=acme needs an ACME certificate mode, got " <>
         "DERPEX_CERT_MODE=#{mode}. Set DERPEX_CERT_MODE=letsencrypt."}
    end
  end

  defp issuer(_mode, other) do
    {:error, "DERPEX_IP_CERT_ISSUER must be \"self\" or \"acme\", got #{inspect(other)}."}
  end

  # Two certificate sources for one listener is an operator mistake with a
  # silent outcome — whichever the listener happens to bind wins — so it is
  # refused rather than resolved by precedence.
  defp validate_operator_certificates(nil, nil, _options), do: :ok

  defp validate_operator_certificates(issuer, provider, options) do
    if is_nil(Keyword.get(options, :certfile)) and is_nil(Keyword.get(options, :keyfile)) do
      :ok
    else
      {:error, conflict_message(issuer, provider)}
    end
  end

  defp conflict_message(:self, _provider) do
    "DERPEX_IP_CERT_ISSUER=self issues the listener's certificate itself and cannot be " <>
      "combined with DERPEX_TLS_CERTFILE or DERPEX_TLS_KEYFILE. Unset the operator " <>
      "certificate paths, or unset DERPEX_IP_CERT_ISSUER to serve them."
  end

  defp conflict_message(_issuer, _provider) do
    "An ACME certificate mode obtains the listener's certificate itself and cannot be " <>
      "combined with DERPEX_TLS_CERTFILE or DERPEX_TLS_KEYFILE. Unset the operator " <>
      "certificate paths, or set DERPEX_CERT_MODE=manual to serve them."
  end

  defp validate_issuer(nil, _directory, _hostname), do: :ok

  defp validate_issuer(_issuer, "", _hostname) do
    {:error, "DERPEX_IP_CERT_ISSUER requires DERPEX_CERT_DIR"}
  end

  defp validate_issuer(:self, _directory, hostname) do
    if ip_address?(hostname) do
      :ok
    else
      {:error,
       "DERPEX_IP_CERT_ISSUER=self requires DERPEX_CERT_HOSTNAME to be an IP address, " <>
         "got #{inspect(hostname)}"}
    end
  end

  defp validate_issuer(:acme, _directory, _hostname), do: :ok

  # HTTP-01 is the only challenge DERPEX answers and a certificate authority
  # validates it over plaintext HTTP, so an ACME mode without a cleartext
  # listener could never complete an order.
  defp validate_challenge_listener(nil, _options), do: :ok

  defp validate_challenge_listener(_provider, options) do
    if Keyword.get(options, :challenge_listener, false) do
      :ok
    else
      {:error,
       "an ACME certificate mode answers HTTP-01 challenges over plaintext HTTP, so it " <>
         "requires DERPEX_HTTP_PORT (conventionally 80) to be set and reachable from the " <>
         "certificate authority."}
    end
  end

  defp ip_address?(hostname) do
    match?({:ok, _address}, :inet.parse_address(String.to_charlist(hostname)))
  end

  defp text(nil, default), do: default
  defp text(value, _default) when is_binary(value), do: value
end
