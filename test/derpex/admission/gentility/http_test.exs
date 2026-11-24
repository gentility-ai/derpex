defmodule Derpex.Admission.Gentility.HTTPTest do
  # D4 and D5 of the DERP admission design (T-642 closure 1): the HTTP adapter
  # against a fake Gentility app, and records Gentility signed verifying here.
  use ExUnit.Case, async: false

  alias Derpex.Admission.Gentility
  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.HTTP
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation
  alias Derpex.Admission.Gentility.Signer
  alias Derpex.Admission.Request
  alias Derpex.ClientInfo

  @private_key :binary.copy(<<0x10>>, 32)
  @public_key elem(:crypto.generate_key(:eddsa, :ed25519, @private_key), 0)
  @token String.duplicate("t", 32)
  @instance "derpex-sin-1"
  @source {203, 0, 113, 9}

  setup do
    {:ok, listener} =
      :gen_tcp.listen(0, [
        :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        ip: {127, 0, 0, 1}
      ])

    {:ok, {_address, port}} = :inet.sockname(listener)
    on_exit(fn -> :gen_tcp.close(listener) end)

    {:ok, options} =
      HTTP.config(
        url: "http://127.0.0.1:#{port}/app/",
        token: @token,
        instance_id: @instance,
        region_id: 900,
        timeout_ms: 300,
        reconcile_timeout_ms: 1_000
      )

    {:ok, listener: listener, port: port, options: options}
  end

  describe "D4: authorize" do
    test "a 200 lease is the record; the call names the relay and sends no source", context do
      lease = signed_lease(node_key(1))
      server = serve(context.listener, [{200, [], lease}])

      assert HTTP.authorize(request(node_key(1)), context.options) == {:ok, lease}

      [{head, body}] = Task.await(server)

      assert head =~ "POST /app/overlay/derp/authorize HTTP/1.1\r\n"
      assert head =~ "\r\nHost: 127.0.0.1:#{context.port}\r\n"
      assert head =~ "\r\nx-derp-instance: #{@instance}\r\n"
      assert head =~ "\r\nauthorization: Bearer #{@token}\r\n"

      assert body ==
               ~s({"node_key":"#{String.duplicate("01", 32)}","renewal":false,"region_id":900})

      refute_source_sent(head <> body)
    end

    test "a renewal says so, and carries no source either", context do
      server = serve(context.listener, [{200, [], signed_lease(node_key(2))}])
      renewal = %Request{request(node_key(2)) | source_ip: nil, metadata: %{renewal: true}}

      assert {:ok, _lease} = HTTP.authorize(renewal, context.options)
      [{head, body}] = Task.await(server)
      assert body =~ ~s("renewal":true)
      refute_source_sent(head <> body)
    end

    test "a 200 revocation is the record too", context do
      revocation = signed_revocation(node_key(3), 10)
      server = serve(context.listener, [{200, [], revocation}])

      assert HTTP.authorize(request(node_key(3)), context.options) == {:ok, revocation}
      Task.await(server)
    end

    test "a 404, any other status, and a silent app are errors, never denials", context do
      server =
        serve(context.listener, [
          {404, [], ~s({"error":"unknown_node"})},
          {403, [], ~s({"error":"forbidden"})},
          {500, [], ""}
        ])

      assert HTTP.authorize(request(node_key(4)), context.options) == {:error, {:http, 404}}
      assert HTTP.authorize(request(node_key(4)), context.options) == {:error, {:http, 403}}
      assert HTTP.authorize(request(node_key(4)), context.options) == {:error, {:http, 500}}
      Task.await(server)

      silent = serve(context.listener, [:silent])
      assert {:error, _timeout} = HTTP.authorize(request(node_key(4)), context.options)
      Task.await(silent)
    end

    test "through the controller, a 404 with no cached lease refuses and a lease admits",
         context do
      server = serve(context.listener, [{404, [], ""}, {200, [], signed_lease(node_key(5))}])

      controller =
        start_supervised!(
          {Gentility,
           [
             authority: {HTTP, context.options},
             verification_keys: %{"gentility-test" => @public_key},
             max_lease_ms: 900_000,
             clock: Derpex.Clock.System
           ]}
        )

      policy = Gentility.policy(controller)

      assert Gentility.authorize(request(node_key(5)), policy) == {:error, :no_cached_lease}

      assert {:ok, %{gentility: %{source: :live, owner_kind: "computer@ryzen"}}} =
               Gentility.authorize(request(node_key(5)), policy)

      Task.await(server)
    end
  end

  describe "D4: the revocation stream" do
    test "a 200 revocation and a 204 each carry the next cursor", context do
      revocation = signed_revocation(node_key(6), 10)

      server =
        serve(context.listener, [
          {200, [{"x-derp-cursor", "41"}], revocation},
          {204, [{"x-derp-cursor", "57"}], ""}
        ])

      assert HTTP.next_revocation("", 30_000, context.options) == {:ok, revocation, "41"}
      assert HTTP.next_revocation("41", 30_000, context.options) == {:timeout, "57"}

      [{first, _body}, {second, _body2}] = Task.await(server)
      assert first =~ "GET /app/overlay/derp/revocations?cursor=&wait_ms=25000 HTTP/1.1\r\n"
      assert second =~ "GET /app/overlay/derp/revocations?cursor=41&wait_ms=25000 HTTP/1.1\r\n"
      assert first =~ "\r\nx-derp-instance: #{@instance}\r\n"
      assert first =~ "\r\nauthorization: Bearer #{@token}\r\n"
    end

    test "the wait leaves room under the caller's deadline", context do
      server = serve(context.listener, [{204, [{"x-derp-cursor", "1"}], ""}])

      assert HTTP.next_revocation("9", 8_000, context.options) == {:timeout, "1"}

      [{head, _body}] = Task.await(server)
      assert head =~ "?cursor=9&wait_ms=3000 HTTP/1.1"
    end

    test "a 409 means the app no longer holds the cursor", context do
      server = serve(context.listener, [{409, [], ~s({"error":"cursor_not_held"})}])
      assert HTTP.next_revocation("99", 30_000, context.options) == {:error, :cursor_not_held}
      Task.await(server)
    end

    test "an answer with no cursor, or another status, is an error", context do
      server =
        serve(context.listener, [
          {204, [], ""},
          {200, [], signed_revocation(node_key(7), 10)},
          {503, [], ""}
        ])

      assert HTTP.next_revocation("1", 30_000, context.options) == {:error, :missing_cursor}
      assert HTTP.next_revocation("1", 30_000, context.options) == {:error, :missing_cursor}
      assert HTTP.next_revocation("1", 30_000, context.options) == {:error, {:http, 503}}
      Task.await(server)
    end
  end

  describe "D4: reconcile" do
    test "pages until the empty page with no cursor", context do
      first = signed_revocation(node_key(8), 10)
      second = signed_revocation(node_key(9), 11)
      third = signed_revocation(node_key(10), 12)

      server =
        serve(context.listener, [
          {200, [{"x-derp-cursor", "2"}], framed([first, second])},
          {200, [{"x-derp-cursor", "3"}], framed([third])},
          {200, [], ""}
        ])

      assert HTTP.reconcile(nil, context.options) == {:ok, [first, second], "2"}
      assert HTTP.reconcile("2", context.options) == {:ok, [third], "3"}
      assert HTTP.reconcile("3", context.options) == {:ok, [], nil}

      heads = server |> Task.await() |> Enum.map(&elem(&1, 0))

      assert Enum.at(heads, 0) =~ "GET /app/overlay/derp/reconcile?cursor= HTTP/1.1\r\n"
      assert Enum.at(heads, 1) =~ "GET /app/overlay/derp/reconcile?cursor=2 HTTP/1.1\r\n"
      assert Enum.at(heads, 2) =~ "GET /app/overlay/derp/reconcile?cursor=3 HTTP/1.1\r\n"
      Enum.each(heads, &refute_source_sent/1)
    end

    test "a malformed page, records with no cursor, and a 409 are errors", context do
      record = signed_revocation(node_key(11), 10)

      server =
        serve(context.listener, [
          {200, [{"x-derp-cursor", "2"}], <<byte_size(record) + 1::16, record::binary>>},
          {200, [{"x-derp-cursor", "2"}], <<0::16>>},
          {200, [], framed([record])},
          {409, [], ~s({"error":"cursor_not_held"})}
        ])

      assert HTTP.reconcile(nil, context.options) == {:error, :invalid_reconcile_page}
      assert HTTP.reconcile(nil, context.options) == {:error, :invalid_reconcile_page}
      assert HTTP.reconcile(nil, context.options) == {:error, :invalid_reconcile_page}
      assert HTTP.reconcile("7", context.options) == {:error, :cursor_not_held}
      Task.await(server)
    end
  end

  describe "D4: usage and settings" do
    test "usage is acknowledged as discarded, and sends nothing", context do
      assert HTTP.export_usage(:binary.copy(<<0>>, 32), "batch", context.options) ==
               {:ok, :discarded}
    end

    test "the bearer renders without its bytes" do
      {:ok, options} =
        HTTP.config(url: "https://app.example", token: @token, instance_id: "a", region_id: 1)

      refute inspect(options) =~ @token
    end

    test "refuses a short or unprintable bearer, a bad URL, and a bad instance id" do
      base = [url: "https://app.example", token: @token, instance_id: "a", region_id: 1]

      for {key, value, reason} <- [
            {:token, String.duplicate("t", 31), :invalid_token},
            {:token, String.duplicate("t", 31) <> " ", :invalid_token},
            {:token, String.duplicate("t", 31) <> "\n", :invalid_token},
            {:url, "app.example", :invalid_url},
            {:url, "https://app.example/?x=1", :invalid_url},
            {:url, "ftp://app.example", :invalid_url},
            {:instance_id, "", :invalid_instance_id},
            {:instance_id, "a\r\nb", :invalid_instance_id},
            {:region_id, -1, :invalid_region_id}
          ] do
        assert HTTP.config(Keyword.put(base, key, value)) == {:error, reason},
               "#{key} #{inspect(value)} was accepted"
      end
    end
  end

  describe "D5: records Gentility signed" do
    # These are the bytes `Gentility.Overlay.DerpContract` produces for the
    # fields below, under key id "gentility-test" and the seed 0x10 x 32 that
    # `ContractTest` uses. They were generated with this repository's
    # independent test encoder (`Signer`); Gentility's own test checks it
    # produces the same hex, so the two sides cannot drift apart unnoticed.
    @phoenix_lease "4458414c0001000e67656e74696c6974792d746573740101010101010101010101010101010101010101010101010101010101010101002430313961303030302d303030302d373030302d383030302d303030303030303030303031002430313961303030302d303030302d373030302d383030302d303030303030303030303032000e636f6d70757465724072797a656e000773746167696e6700000384000644594164224000000000000000010000019ab697e87b0000019ab6a1103b0000000800000400000000000000000000000000000000000000000000000000000000000000000022811db62b42b9a9e9f425b4211d36fe10f1bae81f61881d6f01590e67bc032ac16cc8226210a42c78441794b68b3c7d550cb81a71c05f6610760ca637db740e"
    @phoenix_revocation "445852560001000e67656e74696c6974792d74657374020202020202020202020202020202020202020202020202020202020202020200064459416c3bf10000019ab69c7e6e000b6b65795f726f74617465642a47896dc41dce98ddeac35fce4f307d977167e46c59f91da4239c6024a59fbb5cf426770f9452a31374e667efaa49649bce216f9e7037b7e7ddc3ca46acdd01"

    test "a lease Gentility signed verifies field for field" do
      wire = Base.decode16!(@phoenix_lease, case: :lower)
      keys = %{"gentility-test" => @public_key}

      assert {:ok, lease} = Contract.verify_lease(wire, keys, 1_764_000_000_200)

      assert lease == %Lease{
               key_id: "gentility-test",
               node_key: :binary.copy(<<0x01>>, 32),
               node_id: "019a0000-0000-7000-8000-000000000001",
               organization_id: "019a0000-0000-7000-8000-000000000002",
               owner_kind: "computer@ryzen",
               deployment_id: "staging",
               region_id: 900,
               policy_revision: 1_764_000_000_123_456,
               quota_revision: 1,
               issued_at_ms: 1_764_000_000_123,
               expires_at_ms: 1_764_000_600_123,
               node_connection_limit: 8,
               organization_connection_limit: 1024,
               node_bytes_per_second: 0,
               node_byte_burst: 0,
               organization_bytes_per_second: 0,
               organization_byte_burst: 0
             }

      assert {:ok, ^wire} = Signer.sign_lease(lease, @private_key)
    end

    test "a revocation Gentility signed verifies field for field" do
      wire = Base.decode16!(@phoenix_revocation, case: :lower)

      assert {:ok, revocation} =
               Contract.verify_revocation(wire, %{"gentility-test" => @public_key})

      assert revocation == %Revocation{
               key_id: "gentility-test",
               node_key: :binary.copy(<<0x02>>, 32),
               policy_revision: 1_764_000_000_654_321,
               revoked_at_ms: 1_764_000_300_654,
               reason: "key_rotated"
             }

      assert {:ok, ^wire} = Signer.sign_revocation(revocation, @private_key)
    end
  end

  # The fake app: one connection per answer, in order. `:silent` reads the
  # request and never answers.
  defp serve(listener, answers) do
    Task.async(fn -> Enum.map(answers, &answer_one(listener, &1)) end)
  end

  defp answer_one(listener, answer) do
    {:ok, socket} = :gen_tcp.accept(listener, 2_000)
    {:ok, request} = receive_request(socket, "")
    answer(socket, answer)
    :gen_tcp.close(socket)
    request
  end

  defp answer(_socket, :silent), do: Process.sleep(500)

  defp answer(socket, {status, headers, body}),
    do: :ok = :gen_tcp.send(socket, response(status, headers, body))

  defp receive_request(socket, buffer) do
    case :binary.match(buffer, "\r\n\r\n") do
      {head_length, 4} ->
        <<head::binary-size(^head_length), "\r\n\r\n", rest::binary>> = buffer
        receive_body(socket, head <> "\r\n\r\n", rest, content_length(head))

      :nomatch ->
        with {:ok, data} <- :gen_tcp.recv(socket, 0, 1_000) do
          receive_request(socket, buffer <> data)
        end
    end
  end

  defp receive_body(_socket, head, body, length) when byte_size(body) >= length,
    do: {:ok, {head, body}}

  defp receive_body(socket, head, body, length) do
    with {:ok, data} <- :gen_tcp.recv(socket, 0, 1_000) do
      receive_body(socket, head, body <> data, length)
    end
  end

  defp content_length(head) do
    case Regex.run(~r/\r\ncontent-length: (\d+)/i, head) do
      [_match, length] -> String.to_integer(length)
      nil -> 0
    end
  end

  defp response(status, headers, body) do
    [
      "HTTP/1.1 #{status} Answer\r\n",
      Enum.map(headers, fn {name, value} -> [name, ": ", value, "\r\n"] end),
      "content-length: #{byte_size(body)}\r\nconnection: close\r\n\r\n",
      body
    ]
  end

  defp framed(records), do: Enum.map_join(records, &<<byte_size(&1)::16, &1::binary>>)

  defp refute_source_sent(text) do
    refute text =~ "203.0.113.9"
    refute text =~ :inet.ntoa(@source) |> List.to_string()
    refute text =~ ~r/source/i
    refute text =~ ~r/x-forwarded-for/i
  end

  defp request(node_key) do
    %Request{
      node_key: node_key,
      client_info: %ClientInfo{version: 2, app_name: "gentility"},
      source_ip: @source,
      mesh_peer?: false,
      metadata: %{}
    }
  end

  defp node_key(byte), do: :binary.copy(<<byte>>, 32)

  defp signed_lease(node_key) do
    now = System.system_time(:millisecond)

    lease = %Lease{
      key_id: "gentility-test",
      node_key: node_key,
      node_id: "node_01",
      organization_id: "org_01",
      owner_kind: "computer@ryzen",
      deployment_id: "staging",
      region_id: 900,
      policy_revision: 9,
      quota_revision: 1,
      issued_at_ms: now,
      expires_at_ms: now + 600_000,
      node_connection_limit: 8,
      organization_connection_limit: 1024,
      node_bytes_per_second: 0,
      node_byte_burst: 0,
      organization_bytes_per_second: 0,
      organization_byte_burst: 0
    }

    {:ok, wire} = Signer.sign_lease(lease, @private_key)
    wire
  end

  defp signed_revocation(node_key, revision) do
    revocation = %Revocation{
      key_id: "gentility-test",
      node_key: node_key,
      policy_revision: revision,
      revoked_at_ms: 1_100,
      reason: "key_rotated"
    }

    {:ok, wire} = Signer.sign_revocation(revocation, @private_key)
    wire
  end
end
