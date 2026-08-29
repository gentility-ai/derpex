# Ported from fakeIPACME in ../tailscale/cmd/derper/ipcert_test.go.
# Copyright (c) Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.Test.FakeACME do
  @moduledoc """
  A minimal fake ACME (RFC 8555) certificate authority.

  It implements just enough of the protocol for an HTTP-01 order flow with one
  identifier and an optional profile: one order at a time, no nonce tracking,
  and no JWS signature verification. What it does check is what upstream's
  `fakeIPACME` checks, because those are the claims the client has to get
  right:

  - the `newOrder` payload decodes as a JWS payload and carries one identifier
    and the requested profile;
  - the challenge response is fetched back over HTTP from the server under
    test and starts with `token.`, which is the key authorization;
  - the finalize payload carries a base64url DER certificate request with
    exactly one subject alternative name.
  """

  use GenServer

  alias Derpex.HTTP1.Parser
  alias Derpex.HTTP1.Request
  alias Derpex.HTTPClient
  alias Derpex.JSON

  @common_name_oid {2, 5, 4, 3}
  @basic_constraints_oid {2, 5, 29, 19}
  @key_usage_oid {2, 5, 29, 15}
  @subject_alt_name_oid {2, 5, 29, 17}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @sha256_with_rsa_oid {1, 2, 840, 113_549, 1, 1, 11}
  @ec_public_key_oid {1, 2, 840, 10_045, 2, 1}
  @extension_request_oid {1, 2, 840, 113_549, 1, 9, 14}
  @leaf_lifetime_seconds 6 * 24 * 60 * 60

  @doc "Starts a fake certificate authority on a loopback port."
  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, options, Keyword.take(options, [:name]))
  end

  @doc "Returns the directory URL to configure a client with."
  def directory_url(server), do: base_url(server) <> "/directory"

  @doc "Returns the authority's base URL."
  def base_url(server), do: GenServer.call(server, :base_url)

  @doc "Points the authority at the base URL it fetches challenge responses from."
  def set_challenge_base(server, base), do: GenServer.call(server, {:challenge_base, base})

  @doc "Returns how many orders have been created."
  def orders(server), do: GenServer.call(server, :orders)

  @doc "Returns the profile and identifier of the most recent order."
  def last_order(server), do: GenServer.call(server, :last_order)

  @doc "Returns the external account binding the last registration carried, if any."
  def last_binding(server), do: GenServer.call(server, :last_binding)

  @doc "Returns the DER of the authority's root, for verifying an issued chain."
  def root_certificate(server), do: GenServer.call(server, :root)

  @doc "Makes the next request to `path` answer with an ACME problem document."
  def fail_next(server, path, problem), do: GenServer.call(server, {:fail_next, path, problem})

  @doc "Holds the order pending for `count` polls, advertising `retry_after` seconds."
  def defer_order(server, count, retry_after) do
    GenServer.call(server, {:defer_order, count, retry_after})
  end

  @doc "How many times the order resource has been read."
  def order_polls(server), do: GenServer.call(server, :order_polls)

  @doc "Signs the next certificate for a key the client did not generate."
  def substitute_certificate(server), do: GenServer.call(server, :substitute_certificate)

  @impl true
  def init(options) do
    {:ok, listen} =
      :gen_tcp.listen(0, [
        :binary,
        ip: {127, 0, 0, 1},
        active: false,
        reuseaddr: true,
        packet: :raw
      ])

    {:ok, {_ip, port}} = :inet.sockname(listen)
    {root_der, root_key} = generate_root()
    server = self()
    acceptor = spawn_link(fn -> accept_loop(listen, server) end)

    {:ok,
     %{
       listen: listen,
       acceptor: acceptor,
       port: port,
       base: "http://127.0.0.1:#{port}",
       challenge_base: Keyword.get(options, :challenge_base),
       root_der: root_der,
       root_key: root_key,
       orders: 0,
       profile: nil,
       identifier: nil,
       token: nil,
       authorization_status: "pending",
       order_status: "pending",
       certificate_pem: nil,
       binding: nil,
       deferrals: 0,
       retry_after: nil,
       order_polls: 0,
       substitute: false,
       failures: %{}
     }}
  end

  @impl true
  def terminate(_reason, state), do: :gen_tcp.close(state.listen)

  @impl true
  def handle_call(:base_url, _from, state), do: {:reply, state.base, state}
  def handle_call(:orders, _from, state), do: {:reply, state.orders, state}
  def handle_call(:root, _from, state), do: {:reply, state.root_der, state}

  def handle_call(:last_binding, _from, state), do: {:reply, state.binding, state}
  def handle_call(:order_polls, _from, state), do: {:reply, state.order_polls, state}

  def handle_call({:defer_order, count, retry_after}, _from, state) do
    {:reply, :ok, %{state | deferrals: count, retry_after: retry_after}}
  end

  def handle_call(:substitute_certificate, _from, state) do
    {:reply, :ok, %{state | substitute: true}}
  end

  def handle_call(:last_order, _from, state) do
    {:reply, %{profile: state.profile, identifier: state.identifier}, state}
  end

  def handle_call({:challenge_base, base}, _from, state) do
    {:reply, :ok, %{state | challenge_base: base}}
  end

  def handle_call({:fail_next, path, problem}, _from, state) do
    {:reply, :ok, %{state | failures: Map.put(state.failures, path, problem)}}
  end

  def handle_call({:request, request, body}, _from, state) do
    path = URI.parse(request.target).path

    case Map.pop(state.failures, path) do
      {nil, _failures} -> dispatch(path, body, state)
      {problem, failures} -> {:reply, problem_response(problem), %{state | failures: failures}}
    end
  end

  def handle_call({:challenge_validated, outcome}, _from, state) do
    case outcome do
      :ok ->
        {:reply, json(200, %{"type" => "http-01", "status" => "valid", "token" => state.token}),
         %{state | authorization_status: "valid", order_status: "ready"}}

      {:error, reason} ->
        {:reply, text(500, "challenge validation failed: #{inspect(reason)}"), state}
    end
  end

  def handle_call({:finalize, csr_base64}, _from, state) do
    case issue(state, csr_base64) do
      {:ok, pem} ->
        state = %{state | certificate_pem: pem, order_status: "valid"}
        {:reply, order_response(state, 200), state}

      {:error, reason} ->
        {:reply, text(500, "issuing certificate: #{inspect(reason)}"), state}
    end
  end

  def handle_call(:challenge_target, _from, state) do
    {:reply, {state.challenge_base, state.token}, state}
  end

  defp dispatch("/directory", _body, state) do
    {:reply,
     json(200, %{
       "newNonce" => state.base <> "/new-nonce",
       "newAccount" => state.base <> "/new-account",
       "newOrder" => state.base <> "/new-order",
       "revokeCert" => state.base <> "/revoke-cert",
       "keyChange" => state.base <> "/key-change",
       "meta" => %{
         "profiles" => %{
           "classic" => "the default profile",
           "shortlived" => "six day certificates"
         }
       }
     }), state}
  end

  defp dispatch("/new-nonce", _body, state), do: {:reply, text(200, ""), state}

  defp dispatch("/new-account", body, state) do
    state = %{state | binding: external_account_binding(body)}
    {:reply, json(201, %{"status" => "valid"}, [{"location", state.base <> "/account/1"}]), state}
  end

  defp dispatch("/new-order", body, state) do
    payload = jws_payload!(body)
    identifiers = field(payload, "identifiers")

    identifier =
      case identifiers do
        [{:object, fields}] -> %{type: field(fields, "type"), value: field(fields, "value")}
        _other -> nil
      end

    orders = state.orders + 1

    state = %{
      state
      | orders: orders,
        profile: field(payload, "profile"),
        identifier: identifier,
        token: "tok-#{orders}",
        authorization_status: "pending",
        order_status: "pending",
        certificate_pem: nil
    }

    {:reply, order_response(state, 201), state}
  end

  defp dispatch("/authz/1", _body, state) do
    {:reply,
     json(200, %{
       "status" => state.authorization_status,
       "identifier" => %{
         "type" => state.identifier.type,
         "value" => state.identifier.value
       },
       "challenges" => [
         %{
           "type" => "http-01",
           "url" => state.base <> "/chal/1",
           "token" => state.token,
           "status" => state.authorization_status
         }
       ]
     }), state}
  end

  # The order stays pending for as many polls as the test asked for, with the
  # Retry-After a real authority would send.
  defp dispatch("/order/1", _body, state) do
    state = %{state | order_polls: state.order_polls + 1}

    case state.deferrals do
      0 ->
        {:reply, order_response(state, 200), state}

      :forever ->
        {:reply, deferred_response(state), state}

      count ->
        {:reply, deferred_response(state), %{state | deferrals: count - 1}}
    end
  end

  defp dispatch("/cert/1", _body, state) do
    {:reply,
     {200, [{"content-type", "application/pem-certificate-chain"}], state.certificate_pem || ""},
     state}
  end

  defp dispatch(path, _body, state) do
    {:reply, text(404, "unexpected request: #{path}"), state}
  end

  # RFC 8555 section 7.3.4: the binding is an inner JWS whose payload is the
  # account JWK and whose protected header names the key the authority issued.
  defp external_account_binding(body) do
    case field(jws_payload!(body), "externalAccountBinding") do
      {:object, fields} ->
        {:ok, protected} = Base.url_decode64(field(fields, "protected"), padding: false)
        {:ok, header} = JSON.decode_object(protected)
        {:ok, payload} = Base.url_decode64(field(fields, "payload"), padding: false)

        %{
          algorithm: field(header, "alg"),
          kid: field(header, "kid"),
          url: field(header, "url"),
          jwk: payload,
          signature: field(fields, "signature")
        }

      _absent ->
        nil
    end
  end

  defp deferred_response(state) do
    {status, headers, body} = json(200, pending_order(state), [])
    {status, [{"retry-after", state.retry_after || "1"} | headers], body}
  end

  defp pending_order(state) do
    identifier = state.identifier || %{type: "unknown", value: "unknown"}

    %{
      "status" => "pending",
      "identifiers" => [%{"type" => identifier.type, "value" => identifier.value}],
      "authorizations" => [state.base <> "/authz/1"],
      "finalize" => state.base <> "/finalize/1",
      "certificate" => state.base <> "/cert/1"
    }
  end

  defp order_response(state, status) do
    identifier = state.identifier || %{type: "unknown", value: "unknown"}

    json(
      status,
      %{
        "status" => state.order_status,
        "identifiers" => [%{"type" => identifier.type, "value" => identifier.value}],
        "authorizations" => [state.base <> "/authz/1"],
        "finalize" => state.base <> "/finalize/1",
        "certificate" => state.base <> "/cert/1"
      },
      [{"location", state.base <> "/order/1"}]
    )
  end

  # `/chal/1` and `/finalize/1` do work outside this process: the first fetches
  # the challenge response back from the server under test, standing in for the
  # authority dialling port 80, and the second signs a certificate.
  defp handle_outside_call(server, "/chal/1", _body) do
    {base, token} = GenServer.call(server, :challenge_target)
    GenServer.call(server, {:challenge_validated, validate_challenge(base, token)}, 30_000)
  end

  defp handle_outside_call(server, "/finalize/1", body) do
    payload = jws_payload!(body)
    GenServer.call(server, {:finalize, field(payload, "csr")}, 30_000)
  end

  defp validate_challenge(nil, _token), do: {:error, :no_challenge_base}

  defp validate_challenge(base, token) do
    url = base <> "/.well-known/acme-challenge/" <> token
    uri = URI.parse(url)

    request = [
      "GET ",
      uri.path,
      " HTTP/1.1\r\nHost: ",
      "#{uri.host}:#{uri.port}",
      "\r\nConnection: close\r\n\r\n"
    ]

    case HTTPClient.request(uri, request, timeout_ms: 10_000) do
      {:ok, {200, _headers, body}} ->
        if String.starts_with?(body, token <> "."),
          do: :ok,
          else: {:error, {:unexpected_response, body}}

      {:ok, {status, _headers, _body}} ->
        {:error, {:status, status}}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp issue(state, csr_base64) when is_binary(csr_base64) do
    with {:ok, csr_der} <- Base.url_decode64(csr_base64, padding: false),
         {:ok, {public_key, names}} <- parse_request(csr_der),
         1 <- length(names) do
      {:ok, sign_leaf(state, public_key, hd(names))}
    else
      count when is_integer(count) -> {:error, {:subject_alt_names, count}}
      :error -> {:error, :invalid_base64}
      {:error, reason} -> {:error, reason}
    end
  end

  defp issue(_state, other), do: {:error, {:invalid_csr, other}}

  defp parse_request(csr_der) do
    {:CertificationRequest, info, _algorithm, signature} =
      :public_key.der_decode(:CertificationRequest, csr_der)

    {:CertificationRequestInfo, :v1, _subject, subject_public_key_info, attributes} = info

    {:CertificationRequestInfo_subjectPKInfo,
     {:CertificationRequestInfo_subjectPKInfo_algorithm, @ec_public_key_oid, _parameters},
     public_point} = subject_public_key_info

    public_key = {{:ECPoint, public_point}, {:namedCurve, :secp256r1}}

    unless :public_key.verify(
             :public_key.der_encode(:CertificationRequestInfo, info),
             :sha256,
             signature,
             public_key
           ) do
      throw({:error, :bad_csr_signature})
    end

    {:ok, {public_point, subject_alt_names(attributes)}}
  rescue
    error -> {:error, {:unparsable_csr, error}}
  catch
    {:error, reason} -> {:error, reason}
  end

  defp subject_alt_names(attributes) do
    for {:Attribute, @extension_request_oid, values} <- attributes,
        {:asn1_OPENTYPE, extensions_der} <- values,
        {:Extension, @subject_alt_name_oid, _critical, san_der} <-
          :public_key.der_decode(:Extensions, extensions_der),
        name <- :public_key.der_decode(:SubjectAltName, san_der) do
      name
    end
  end

  defp sign_leaf(state, public_point, general_name) do
    public_point = if state.substitute, do: substitute_point(), else: public_point
    now = System.system_time(:second)

    tbs =
      {:OTPTBSCertificate, :v3, 2, signature_algorithm(), distinguished_name("fake IP ACME root"),
       validity(now - 60, now + @leaf_lifetime_seconds), {:rdnSequence, []},
       {:OTPSubjectPublicKeyInfo,
        {:PublicKeyAlgorithm, @ec_public_key_oid, {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}},
        {:ECPoint, public_point}}, :asn1_NOVALUE, :asn1_NOVALUE,
       [
         {:Extension, @basic_constraints_oid, false, {:BasicConstraints, false, :asn1_NOVALUE}},
         {:Extension, @key_usage_oid, false, [:digitalSignature]},
         {:Extension, @subject_alt_name_oid, false, [general_name]}
       ]}

    leaf = :public_key.pkix_sign(tbs, state.root_key)

    :public_key.pem_encode([
      {:Certificate, leaf, :not_encrypted},
      {:Certificate, state.root_der, :not_encrypted}
    ])
  end

  # A well-formed certificate for somebody else's key, which a client has to
  # refuse however good the chain looks.
  defp substitute_point do
    elem(:public_key.generate_key({:namedCurve, :secp256r1}), 4)
  end

  defp generate_root do
    key = :public_key.generate_key({:rsa, 2_048, 65_537})
    public_key = {:RSAPublicKey, elem(key, 2), elem(key, 3)}
    name = distinguished_name("fake IP ACME root")
    now = System.system_time(:second)

    tbs =
      {:OTPTBSCertificate, :v3, 1, signature_algorithm(), name,
       validity(now - 3_600, now + 24 * 3_600), name,
       {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_encryption_oid, :NULL}, public_key},
       :asn1_NOVALUE, :asn1_NOVALUE,
       [
         {:Extension, @basic_constraints_oid, true, {:BasicConstraints, true, :asn1_NOVALUE}},
         {:Extension, @key_usage_oid, true, [:keyCertSign]}
       ]}

    {:public_key.pkix_sign(tbs, key), key}
  end

  defp signature_algorithm do
    {:SignatureAlgorithm, @sha256_with_rsa_oid, {:asn1_OPENTYPE, <<5, 0>>}}
  end

  defp distinguished_name(common_name) do
    {:rdnSequence,
     [
       [
         {:AttributeTypeAndValue, @common_name_oid,
          {:utf8String, String.to_charlist(common_name)}}
       ]
     ]}
  end

  defp validity(from, until), do: {:Validity, certificate_time(from), certificate_time(until)}

  defp certificate_time(unix_seconds) do
    datetime = DateTime.from_unix!(unix_seconds)
    {:utcTime, datetime |> Calendar.strftime("%y%m%d%H%M%SZ") |> String.to_charlist()}
  end

  defp jws_payload!(body) do
    {:ok, fields} = JSON.decode_object(body)
    payload = field(fields, "payload")

    case payload do
      "" ->
        []

      encoded ->
        {:ok, decoded} = Base.url_decode64(encoded, padding: false)
        {:ok, object} = JSON.decode_object(decoded)
        object
    end
  end

  defp field(fields, name) when is_list(fields) do
    case List.keyfind(fields, name, 0) do
      {^name, value} -> value
      nil -> nil
    end
  end

  defp json(status, body, headers \\ []) do
    {status, [{"content-type", "application/json"} | headers],
     JSON.encode_object(encodable(body))}
  end

  defp encodable(map) when is_map(map) do
    Enum.map(map, fn {key, value} -> {key, encodable_value(value)} end)
  end

  defp encodable_value(value) when is_map(value), do: Map.new(value, &encodable_pair/1)
  defp encodable_value(value) when is_list(value), do: Enum.map(value, &encodable_value/1)
  defp encodable_value(value), do: value

  defp encodable_pair({key, value}), do: {key, encodable_value(value)}

  defp text(status, body), do: {status, [{"content-type", "text/plain"}], body}

  defp problem_response({status, type, detail}) do
    {status, [{"content-type", "application/problem+json"}],
     JSON.encode_object([{"type", type}, {"detail", detail}])}
  end

  defp accept_loop(listen, server) do
    case :gen_tcp.accept(listen) do
      {:ok, socket} ->
        {:ok, pid} = Task.start(fn -> serve(socket, server) end)
        :ok = :gen_tcp.controlling_process(socket, pid)
        accept_loop(listen, server)

      {:error, _closed} ->
        :ok
    end
  end

  defp serve(socket, server) do
    with {:ok, request, body} <- read_request(socket) do
      path = URI.parse(request.target).path

      {status, headers, response_body} =
        case path do
          "/chal/1" -> handle_outside_call(server, path, body)
          "/finalize/1" -> handle_outside_call(server, path, body)
          _other -> GenServer.call(server, {:request, request, body}, 30_000)
        end

      headers = [{"replay-nonce", nonce()} | headers]
      :gen_tcp.send(socket, encode_response(status, headers, response_body))
    end

    :gen_tcp.close(socket)
  end

  defp read_request(socket, parser \\ nil, buffer \\ "") do
    parser = parser || Parser.new()

    case Parser.push(parser, buffer) do
      {:ok, request, read_ahead, _parser} ->
        read_body(socket, request, read_ahead)

      {:more, parser} ->
        case :gen_tcp.recv(socket, 0, 10_000) do
          {:ok, chunk} -> read_request(socket, parser, chunk)
          {:error, reason} -> {:error, reason}
        end

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp read_body(socket, request, read_ahead) do
    length =
      case Request.header(request, "content-length") do
        nil -> 0
        value -> String.to_integer(String.trim(value))
      end

    read_body_bytes(socket, request, read_ahead, length)
  end

  defp read_body_bytes(_socket, request, buffer, length) when byte_size(buffer) >= length do
    {:ok, request, binary_part(buffer, 0, length)}
  end

  defp read_body_bytes(socket, request, buffer, length) do
    case :gen_tcp.recv(socket, 0, 10_000) do
      {:ok, chunk} -> read_body_bytes(socket, request, buffer <> chunk, length)
      {:error, reason} -> {:error, reason}
    end
  end

  defp nonce, do: Base.url_encode64(:crypto.strong_rand_bytes(16), padding: false)

  # A local encoder rather than `Derpex.HTTP1.Response`: a certificate
  # authority answers with statuses the relay never sends, and every response
  # here carries a Content-Length even when the body is empty.
  defp encode_response(status, headers, body) do
    headers = [{"content-length", Integer.to_string(IO.iodata_length(body))} | headers]
    encoded = Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end)
    ["HTTP/1.1 ", Integer.to_string(status), " ACME\r\n", encoded, "\r\n", body]
  end
end
