# This module implements the certificate issuance flow of cmd/derper's
# ipcert.go obtainCert, over golang.org/x/crypto/acme as vendored at
# ../tailscale/tempfork/acme.
# Copyright (c) 2026 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.Client do
  @moduledoc """
  Orders certificates from an RFC 8555 certificate authority.

  The process owns only the session — directory, account key, account URL and
  the replay-nonce pool. An order itself runs in the caller, which is the
  certificate manager's flight process, so a certificate authority that takes
  minutes never occupies this one and two addresses can be ordered at once.

  ## Challenges

  `:challenge` names a `{module, server}` that exports `put_challenge/3` and
  `delete_challenge/2`; `Derpex.Certificates.IPManager` does. The response is
  published before the challenge is accepted and removed afterwards, whether
  the order succeeded or not, so a token is never left answering.

  ## Nonces

  Every authenticated request spends a replay nonce and every response carries
  the next one, so nonces are pooled here rather than fetched per request. A
  `badNonce` problem document means the server rejected the one we sent, and
  RFC 8555 section 6.5 requires the client to retry with a fresh one.
  """

  use GenServer

  alias Derpex.ACME.Account
  alias Derpex.ACME.Challenge
  alias Derpex.ACME.CSR
  alias Derpex.ACME.Directory
  alias Derpex.ACME.HTTP
  alias Derpex.ACME.JWS
  alias Derpex.ACME.Order
  alias Derpex.Certificates
  alias Derpex.Clock

  @bad_nonce_suffix "badnonce"
  @nonce_attempts 3
  @nonce_backoff_ms 200
  @poll_interval_ms 250
  @maximum_poll_interval_ms 10_000
  @order_deadline_ms 180_000

  @type subject :: {:ip, binary()} | {:dns, binary()}
  @type certificate :: %{certificate_der: binary(), chain: [binary()], private_key: tuple()}

  def start_link(options) do
    GenServer.start_link(__MODULE__, options, Keyword.take(options, [:name]))
  end

  @doc "Returns an issuer function for `Derpex.Certificates.IPManager`."
  @spec issuer(GenServer.server()) ::
          (binary(), binary() -> {:ok, certificate()} | {:error, term()})
  def issuer(client) do
    fn subject, profile -> issue(client, identify(subject), profile) end
  end

  @doc """
  Classifies a certificate manager's subject as an ACME identifier.

  RFC 8555 identifier types are `dns` and `ip`, and which one an order carries
  decides how the authority validates it, so it is read from the subject rather
  than configured.
  """
  @spec identify(binary()) :: subject()
  def identify(subject) do
    case :inet.parse_address(String.to_charlist(subject)) do
      {:ok, _address} -> {:ip, subject}
      {:error, _reason} -> {:dns, subject}
    end
  end

  @doc "Orders one certificate, fulfilling every authorization it requires."
  @spec issue(GenServer.server(), subject(), binary() | nil, keyword()) ::
          {:ok, certificate()} | {:error, term()}
  def issue(client, identifier, profile \\ nil, options \\ []) do
    deadline =
      Clock.system_time(:millisecond) + Keyword.get(options, :deadline_ms, @order_deadline_ms)

    with {:ok, session} <- GenServer.call(client, :session, :infinity),
         :ok <- supported_profile(session, profile),
         {:ok, order} <- create_order(client, session, identifier, profile),
         :ok <- authorize(client, session, order, deadline),
         {:ok, order} <- await_ready(client, session, order, deadline),
         {:ok, {csr, private_key}} <- CSR.generate(identifier),
         {:ok, order} <- finalize(client, session, order, csr, deadline),
         {:ok, chain} <- download(client, session, order),
         :ok <- verify_key(chain, private_key) do
      {:ok, %{certificate_der: hd(chain), chain: chain, private_key: private_key}}
    end
  end

  @impl true
  def init(options) do
    {:ok,
     %{
       directory_url: Keyword.fetch!(options, :directory_url),
       certificate_directory: Keyword.fetch!(options, :directory),
       email: Keyword.get(options, :email),
       external_account: Keyword.get(options, :external_account),
       challenge: Keyword.fetch!(options, :challenge),
       http_options: Keyword.get(options, :http_options, []),
       session: nil,
       nonces: []
     }}
  end

  @impl true
  def handle_call(:session, _from, state) do
    case establish(state) do
      {:ok, state} -> {:reply, {:ok, public_session(state)}, state}
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  def handle_call(:clear_nonces, _from, state), do: {:reply, :ok, %{state | nonces: []}}

  def handle_call(:take_nonce, _from, %{nonces: [nonce | rest]} = state) do
    {:reply, {:ok, nonce}, %{state | nonces: rest}}
  end

  def handle_call(:take_nonce, _from, state) do
    case establish(state) do
      {:ok, state} -> fetch_nonce(state)
      {:error, reason, state} -> {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_cast({:put_nonce, nonce}, state) do
    {:noreply, %{state | nonces: Enum.take([nonce | state.nonces], 8)}}
  end

  defp public_session(state) do
    %{
      directory: state.session.directory,
      account_key: state.session.account_key,
      kid: state.session.kid,
      challenge: state.challenge,
      http_options: state.http_options
    }
  end

  # The directory fetch and the account registration happen once, inside this
  # process, so concurrent orders cannot register the same key twice.
  defp establish(%{session: session} = state) when not is_nil(session), do: {:ok, state}

  defp establish(state) do
    with {:ok, directory} <- Directory.fetch(state.directory_url, state.http_options),
         {:ok, account_key} <- Account.load_or_create_key(state.certificate_directory),
         state = %{state | session: %{directory: directory, account_key: account_key, kid: nil}},
         {:ok, kid, state} <- register(state) do
      {:ok, put_in(state.session.kid, kid)}
    else
      {:error, reason} -> {:error, reason, %{state | session: nil}}
      {:error, reason, state} -> {:error, reason, %{state | session: nil}}
    end
  end

  defp register(state) do
    url = state.session.directory.new_account

    payload =
      Account.payload(
        [email: state.email, external_account: state.external_account],
        state.session.account_key,
        url
      )

    case request(state, url, payload, nil) do
      {:ok, response, state} ->
        case Account.identifier(response) do
          {:ok, kid} -> {:ok, kid, state}
          {:error, reason} -> {:error, reason, state}
        end

      {:error, reason, state} ->
        {:error, reason, state}
    end
  end

  # Registration runs before the client can serve `:take_nonce`, so it spends
  # nonces from this process's own pool rather than calling back into itself.
  defp request(state, url, payload, kid, attempt \\ 1) do
    case local_nonce(state) do
      {:ok, nonce, state} -> send_request(state, url, payload, kid, attempt, nonce)
      {:error, reason, state} -> {:error, reason, state}
    end
  end

  defp send_request(state, url, payload, kid, attempt, nonce) do
    body = JWS.encode(payload, state.session.account_key, kid: kid, nonce: nonce, url: url)

    case HTTP.post(url, body, state.http_options) do
      {:ok, response} ->
        state = store_local_nonce(state, response)
        requested(state, url, payload, kid, attempt, response)

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp requested(state, url, payload, kid, attempt, response) do
    cond do
      response.status < 400 ->
        {:ok, response, state}

      bad_nonce?(response) and attempt < @nonce_attempts ->
        request(%{state | nonces: []}, url, payload, kid, attempt + 1)

      true ->
        {:error, error(response), state}
    end
  end

  defp local_nonce(%{nonces: [nonce | rest]} = state), do: {:ok, nonce, %{state | nonces: rest}}

  defp local_nonce(state) do
    case HTTP.get(state.session.directory.new_nonce, state.http_options) do
      {:ok, response} ->
        case HTTP.header(response, "replay-nonce") do
          nonce when is_binary(nonce) and nonce != "" -> {:ok, nonce, state}
          _absent -> {:error, :no_replay_nonce, state}
        end

      {:error, reason} ->
        {:error, reason, state}
    end
  end

  defp store_local_nonce(state, response) do
    case HTTP.header(response, "replay-nonce") do
      nonce when is_binary(nonce) and nonce != "" ->
        %{state | nonces: Enum.take([nonce | state.nonces], 8)}

      _absent ->
        state
    end
  end

  defp fetch_nonce(state) do
    case HTTP.get(state.session.directory.new_nonce, state.http_options) do
      {:ok, response} ->
        case HTTP.header(response, "replay-nonce") do
          nonce when is_binary(nonce) and nonce != "" -> {:reply, {:ok, nonce}, state}
          _absent -> {:reply, {:error, :no_replay_nonce}, state}
        end

      {:error, reason} ->
        {:reply, {:error, reason}, state}
    end
  end

  defp supported_profile(session, profile) do
    if Directory.supports_profile?(session.directory, profile) do
      :ok
    else
      {:error, {:unsupported_profile, profile}}
    end
  end

  defp create_order(client, session, identifier, profile) do
    with {:ok, response} <-
           post(client, session, session.directory.new_order, Order.payload(identifier, profile)) do
      Order.parse(response)
    end
  end

  defp authorize(client, session, order, deadline) do
    Enum.reduce_while(order.authorizations, :ok, fn url, :ok ->
      case fulfill(client, session, url, deadline) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp fulfill(client, session, url, deadline) do
    with {:ok, response} <- post(client, session, url, :post_as_get),
         {:ok, _status, challenge} <- Challenge.select(response) do
      accept(client, session, url, challenge, deadline)
    end
  end

  defp accept(_client, _session, _url, nil, _deadline), do: :ok

  defp accept(client, session, authorization_url, challenge, deadline) do
    path = Challenge.path(challenge.token)
    response = Challenge.key_authorization(challenge.token, session.account_key)
    {module, server} = session.challenge
    :ok = module.put_challenge(server, path, response)

    try do
      with {:ok, _accepted} <- post(client, session, challenge.url, %{}) do
        await_authorization(client, session, authorization_url, deadline)
      end
    after
      _removed = module.delete_challenge(server, path)
    end
  end

  defp await_authorization(client, session, url, deadline) do
    poll(client, session, url, deadline, fn response ->
      case Challenge.status(response) do
        {:ok, "valid"} -> {:done, :ok}
        {:ok, "invalid"} -> {:done, {:error, {:authorization_invalid, url}}}
        {:ok, _pending} -> :again
        {:error, reason} -> {:done, {:error, reason}}
      end
    end)
  end

  defp await_ready(_client, _session, %{url: nil} = order, _deadline), do: {:ok, order}

  defp await_ready(client, session, order, deadline) do
    poll(client, session, order.url, deadline, fn response ->
      case Order.parse(response) do
        {:ok, parsed} -> ready(parsed, order)
        {:error, reason} -> {:done, {:error, reason}}
      end
    end)
  end

  defp ready(parsed, order) do
    parsed = %{parsed | url: parsed.url || order.url}

    case Order.settled(parsed) do
      :pending -> :again
      {:error, reason} -> {:done, {:error, reason}}
      _ready_or_issued -> {:done, {:ok, parsed}}
    end
  end

  defp finalize(client, session, order, csr, deadline) do
    with {:ok, response} <-
           post(client, session, order.finalize, Order.finalize_payload(csr)),
         {:ok, finalized} <- Order.parse(response) do
      finalized = %{finalized | url: finalized.url || order.url}

      case Order.settled(finalized) do
        :issued -> {:ok, finalized}
        {:error, reason} -> {:error, reason}
        _not_yet -> await_issued(client, session, finalized, deadline)
      end
    end
  end

  defp await_issued(client, session, order, deadline) do
    poll(client, session, order.url, deadline, fn response ->
      case Order.parse(response) do
        {:ok, parsed} -> issued(parsed, order)
        {:error, reason} -> {:done, {:error, reason}}
      end
    end)
  end

  defp issued(parsed, order) do
    parsed = %{parsed | url: parsed.url || order.url}

    case Order.settled(parsed) do
      :issued -> {:done, {:ok, parsed}}
      {:error, reason} -> {:done, {:error, reason}}
      _not_yet -> :again
    end
  end

  defp download(client, session, %{certificate: url}) when is_binary(url) do
    with {:ok, response} <- post(client, session, url, :post_as_get) do
      case certificates(response.body) do
        [] -> {:error, :empty_certificate_chain}
        chain -> {:ok, chain}
      end
    end
  end

  defp download(_client, _session, _order), do: {:error, :order_without_certificate}

  # autocert's `validCert`: a chain whose leaf does not carry the public key of
  # the key we generated is not ours to serve, however well formed it is.
  defp verify_key([leaf | _intermediates], private_key) do
    if Certificates.private_key_matches?(leaf, private_key) do
      :ok
    else
      {:error, :issued_certificate_key_mismatch}
    end
  end

  defp certificates(pem) do
    pem
    |> :public_key.pem_decode()
    |> Enum.flat_map(fn
      {:Certificate, der, :not_encrypted} -> [der]
      _other -> []
    end)
  rescue
    _error -> []
  end

  # An order is bounded by a deadline, not by a fixed number of attempts: a
  # certificate authority that asks for a minute between polls is entitled to,
  # and thirty quarter-second attempts would give up in under eight seconds.
  # `Retry-After` decides the pause, clamped so neither a zero nor an hour is
  # taken literally, and the deadline that bounds the whole order is read from
  # `Derpex.Clock` and is therefore steerable. The pause itself is a delay
  # inside one order's own process, not a protocol timer.
  defp poll(client, session, url, deadline, decide) do
    with {:ok, response} <- post(client, session, url, :post_as_get) do
      case decide.(response) do
        {:done, result} -> result
        :again -> poll_again(client, session, url, deadline, decide, response)
      end
    end
  end

  defp poll_again(client, session, url, deadline, decide, response) do
    case remaining(deadline) do
      0 ->
        {:error, {:order_deadline, url}}

      remaining ->
        Process.sleep(min(retry_after(response), remaining))
        poll(client, session, url, deadline, decide)
    end
  end

  defp remaining(deadline), do: max(deadline - Clock.system_time(:millisecond), 0)

  defp retry_after(response) do
    case HTTP.header(response, "retry-after") do
      value when is_binary(value) ->
        case Integer.parse(String.trim(value)) do
          {seconds, ""} when seconds >= 0 ->
            seconds |> Kernel.*(1_000) |> max(@poll_interval_ms) |> min(@maximum_poll_interval_ms)

          _not_delta_seconds ->
            @poll_interval_ms
        end

      nil ->
        @poll_interval_ms
    end
  end

  # A nonce that cannot be fetched is an error, never a request sent without
  # one: RFC 8555 rejects an unauthenticated replay, and a JWS with no nonce
  # would be indistinguishable from one at the far end.
  defp post(client, session, url, payload, attempt \\ 1) do
    with {:ok, nonce} <- GenServer.call(client, :take_nonce, :infinity) do
      body =
        JWS.encode(payload, session.account_key, kid: session.kid, nonce: nonce, url: url)

      case HTTP.post(url, body, session.http_options) do
        {:ok, response} ->
          store_nonce(client, response)
          posted(client, session, url, payload, attempt, response)

        {:error, reason} ->
          {:error, reason}
      end
    end
  end

  # RFC 8555 section 6.5: a rejected nonce is retried with a fresh one. Every
  # nonce held is suspect once the server rejects one, so the pool is emptied
  # rather than spent one rejection at a time, and the retries back off.
  defp posted(client, session, url, payload, attempt, response) do
    cond do
      response.status < 400 ->
        {:ok, response}

      bad_nonce?(response) and attempt < @nonce_attempts ->
        GenServer.call(client, :clear_nonces, :infinity)
        Process.sleep(@nonce_backoff_ms * attempt)
        post(client, session, url, payload, attempt + 1)

      true ->
        {:error, error(response)}
    end
  end

  defp store_nonce(client, response) do
    case HTTP.header(response, "replay-nonce") do
      nonce when is_binary(nonce) and nonce != "" -> GenServer.cast(client, {:put_nonce, nonce})
      _absent -> :ok
    end
  end

  # Authorities differ on the case of the URN, so it is matched case
  # insensitively on its suffix rather than compared byte for byte.
  defp bad_nonce?(response) do
    case HTTP.problem(response) do
      %{type: type} -> type |> String.downcase(:ascii) |> String.ends_with?(@bad_nonce_suffix)
      nil -> false
    end
  end

  # A certificate authority that answers with something other than a problem
  # document still has to be diagnosable, so a bounded slice of the body is
  # carried with the status rather than discarded.
  defp error(response) do
    case HTTP.problem(response) do
      nil -> {:acme_status, response.status, String.slice(response.body, 0, 256)}
      problem -> {:acme_error, response.status, problem.type, problem.detail}
    end
  end
end
