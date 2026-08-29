defmodule Derpex.ACME.ClientTest do
  use ExUnit.Case, async: false

  alias Derpex.ACME.Challenge
  alias Derpex.ACME.Client
  alias Derpex.Certificates.Manual
  alias Derpex.Test.ChallengeServer
  alias Derpex.Test.FakeACME

  setup do
    directory =
      Path.join(System.tmp_dir!(), "derpex-acme-#{System.unique_integer([:positive])}")

    File.mkdir_p!(directory)
    on_exit(fn -> File.rm_rf!(directory) end)

    authority = start_supervised!(FakeACME)
    store = start_supervised!(ChallengeServer)
    :ok = FakeACME.set_challenge_base(authority, ChallengeServer.base_url(store))

    {:ok, directory: directory, authority: authority, store: store}
  end

  test "orders an IPv4 certificate under the shortlived profile", context do
    client = start_client(context)

    assert {:ok, certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
    assert :ok = Manual.verify_certificate(certificate.certificate_der, "127.0.0.1")

    # The chain the authority returned, leaf first, is kept whole.
    assert [leaf, root] = certificate.chain
    assert leaf == certificate.certificate_der
    assert root == FakeACME.root_certificate(context.authority)

    assert FakeACME.orders(context.authority) == 1

    assert FakeACME.last_order(context.authority) == %{
             profile: "shortlived",
             identifier: %{type: "ip", value: "127.0.0.1"}
           }

    # The challenge is removed once the order finishes.
    assert ChallengeServer.published(context.store) == %{}
  end

  test "orders a DNS certificate and records the identifier type", context do
    client = start_client(context)

    assert {:ok, certificate} = Client.issue(client, {:dns, "derp.example.com"}, nil)
    assert :ok = Manual.verify_certificate(certificate.certificate_der, "derp.example.com")

    assert FakeACME.last_order(context.authority) == %{
             profile: nil,
             identifier: %{type: "dns", value: "derp.example.com"}
           }
  end

  test "serves the key authorization the authority fetches back", context do
    client = start_client(context)
    assert {:ok, _certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")

    [{path, response}] = ChallengeServer.history(context.store)
    assert path == Challenge.path("tok-1")
    assert [token, thumbprint] = String.split(response, ".")
    assert token == "tok-1"
    assert byte_size(Base.url_decode64!(thumbprint, padding: false)) == 32
  end

  test "registers the account once and reuses its key across orders", context do
    client = start_client(context)

    assert {:ok, first} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
    assert {:ok, second} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")

    assert FakeACME.orders(context.authority) == 2
    refute first.certificate_der == second.certificate_der

    # One account key, written 0600, shared by both orders.
    key_path = Path.join(context.directory, "acme-account.key")
    assert {:ok, stat} = File.stat(key_path)
    assert Bitwise.band(stat.mode, 0o777) == 0o600
  end

  test "binds an external account when the authority requires one", context do
    mac_key = :crypto.strong_rand_bytes(32)

    client =
      start_supervised!(
        {Client,
         directory_url: FakeACME.directory_url(context.authority),
         directory: context.directory,
         email: "security@example.com",
         external_account: %{kid: "gcp-eab-kid", key: mac_key},
         challenge: {ChallengeServer, context.store}}
      )

    assert {:ok, _certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")

    binding = FakeACME.last_binding(context.authority)
    assert binding.algorithm == "HS256"
    assert binding.kid == "gcp-eab-kid"
    assert binding.url == FakeACME.base_url(context.authority) <> "/new-account"
    assert binding.jwk =~ ~s("kty":"EC")
  end

  test "registers without a binding when none is configured", context do
    client = start_client(context)
    assert {:ok, _certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
    assert FakeACME.last_binding(context.authority) == nil
  end

  test "refuses a profile the authority does not advertise", context do
    client = start_client(context)

    assert {:error, {:unsupported_profile, "ultrashort"}} =
             Client.issue(client, {:ip, "127.0.0.1"}, "ultrashort")

    assert FakeACME.orders(context.authority) == 0
  end

  test "reports an ACME problem document rather than a bare status", context do
    client = start_client(context)

    :ok =
      FakeACME.fail_next(
        context.authority,
        "/new-order",
        {403, "urn:ietf:params:acme:error:rateLimited", "too many certificates"}
      )

    assert {:error, {:acme_error, 403, "urn:ietf:params:acme:error:rateLimited", detail}} =
             Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")

    assert detail == "too many certificates"
  end

  test "refuses a chain whose leaf does not carry the key it generated", context do
    client = start_client(context)
    :ok = FakeACME.substitute_certificate(context.authority)

    assert {:error, :issued_certificate_key_mismatch} =
             Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
  end

  test "waits past thirty polls when the authority asks it to", context do
    client = start_client(context)
    # Thirty-five polls is more than the fixed thirty attempts this used to
    # give up after; Retry-After of zero is clamped up to the floor, so the
    # test costs a few seconds rather than a minute.
    :ok = FakeACME.defer_order(context.authority, 35, "0")

    assert {:ok, _certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
    assert FakeACME.order_polls(context.authority) > 30
  end

  test "gives up on an order that never settles, at the deadline", context do
    client = start_client(context)
    :ok = FakeACME.defer_order(context.authority, :forever, "0")

    assert {:error, {:order_deadline, _url}} =
             Client.issue(client, {:ip, "127.0.0.1"}, "shortlived", deadline_ms: 500)
  end

  test "treats a differently cased badNonce URN as one", context do
    client = start_client(context)

    :ok =
      FakeACME.fail_next(
        context.authority,
        "/new-order",
        {400, "urn:ietf:params:acme:error:BADNONCE", "stale nonce"}
      )

    assert {:ok, _certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
    assert FakeACME.orders(context.authority) == 1
  end

  test "retries once with a fresh nonce when the authority rejects one", context do
    client = start_client(context)

    :ok =
      FakeACME.fail_next(
        context.authority,
        "/new-order",
        {400, "urn:ietf:params:acme:error:badNonce", "stale nonce"}
      )

    assert {:ok, _certificate} = Client.issue(client, {:ip, "127.0.0.1"}, "shortlived")
    assert FakeACME.orders(context.authority) == 1
  end

  defp start_client(context) do
    start_supervised!(
      {Client,
       directory_url: FakeACME.directory_url(context.authority),
       directory: context.directory,
       email: "security@example.com",
       challenge: {ChallengeServer, context.store}}
    )
  end
end
