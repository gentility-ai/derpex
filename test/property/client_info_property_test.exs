defmodule Derpex.ClientInfoPropertyTest do
  use ExUnit.Case, async: false
  use ExUnitProperties

  alias Derpex.ClientInfo

  @moduletag :property

  @max_app_name_length 32
  @min_integer -9_223_372_036_854_775_808
  @max_integer 9_223_372_036_854_775_807

  # A process that decodes tens of megabytes may still reference the fixture
  # documents it started with, and nothing else.
  @leak_budget 256 * 1_024

  property "encode round trips through decode" do
    check all info <- client_info() do
      encoded = ClientInfo.encode(info)

      assert {:ok, decoded} = ClientInfo.decode(encoded)
      assert decoded == info
      assert ClientInfo.encode(decoded) == encoded
    end
  end

  property "decoding is insensitive to field name case, order, and unknown fields" do
    check all info <- client_info(),
              unknown <- list_of(unknown_field(), max_length: 4),
              weights <- list_of(integer(0..64), length: 16) do
      fields = reorder(known_fields(info) ++ unknown, weights)

      assert {:ok, decoded} = ClientInfo.decode(encode_object(fields))
      assert decoded == info
    end
  end

  property "arbitrary bytes never raise" do
    check all bytes <- json_bytes() do
      case ClientInfo.decode(bytes) do
        {:ok, info} ->
          assert byte_size(info.app_name) <= @max_app_name_length
          assert info.mesh_key == nil or byte_size(info.mesh_key) == 32
          assert is_integer(info.version)
          assert is_boolean(info.can_ack_pings)
          assert is_boolean(info.is_prober)

        {:error, reason} ->
          assert is_atom(reason) or is_tuple(reason)
      end
    end
  end

  property "rejects an app name past the declared cap" do
    check all name <- app_name(@max_app_name_length + 1, 4 * @max_app_name_length) do
      assert ClientInfo.decode(encode_object([{"AppName", name}])) == {:error, :invalid_app_name}
    end
  end

  property "rejects a mesh key that is not 32 hex-encoded bytes" do
    check all key <- filter(binary(max_length: 80), &(byte_size(&1) != 32)) do
      json = encode_object([{"meshKey", Base.encode16(key, case: :lower)}])

      assert ClientInfo.decode(json) == {:error, :invalid_mesh_key}
    end
  end

  test "decoding many large documents keeps binary memory bounded" do
    documents =
      Enum.map(1..8, fn index ->
        encode_object([
          {"meshKey", String.duplicate("ab", 32)},
          {"padding", String.duplicate("p", 8 * 1_024 * index)},
          {"AppName", "derpex"}
        ])
      end)

    iterations = 200
    before = referenced_binary_bytes()

    for _iteration <- 1..iterations, document <- documents do
      assert {:ok, info} = ClientInfo.decode(document)
      assert info.app_name == "derpex"
    end

    assert iterations * Enum.sum_by(documents, &byte_size/1) > 32 * 1_024 * 1_024
    assert referenced_binary_bytes() - before < @leak_budget
  end

  defp client_info do
    gen all mesh_key <- one_of([constant(nil), binary(length: 32)]),
            # The 64-bit range is what the field must survive; 0 through 3 is
            # what a client actually sends, since the pinned ProtocolVersion is
            # 2. Drawing only from the wide range generated the plausible
            # versions about as often as never.
            version <- one_of([integer(0..3), integer(@min_integer..@max_integer)]),
            can_ack_pings <- boolean(),
            is_prober <- boolean(),
            app_name <- app_name(0, @max_app_name_length) do
      %ClientInfo{
        mesh_key: mesh_key,
        version: version,
        can_ack_pings: can_ack_pings,
        is_prober: is_prober,
        app_name: app_name
      }
    end
  end

  # `list_of(max_length: n)` is also bounded by the generation size, which stays
  # near 100 for a default run count. Driving the length with an integer reaches
  # the declared 32-byte cap on every run.
  defp app_name(min_length, max_length) do
    printable = member_of(Enum.map(0x20..0x7E, &<<&1>>))

    bind(integer(min_length..max_length), fn length ->
      map(list_of(printable, length: length), &IO.iodata_to_binary/1)
    end)
  end

  defp known_fields(info) do
    mesh_key =
      case info.mesh_key do
        nil -> []
        key -> [{"MESHKEY", Base.encode16(key, case: :upper)}]
      end

    mesh_key ++
      [
        {"Version", info.version},
        {"canAckPings", info.can_ack_pings},
        {"isprober", info.is_prober},
        {"appNAME", info.app_name}
      ]
  end

  defp unknown_field do
    gen all name <- app_name(1, 8),
            value <- one_of([integer(), boolean(), app_name(0, 8), constant(:null)]) do
      {"x-" <> name, value}
    end
  end

  # A stable sort on generated weights permutes the fields deterministically, so
  # a shrunk counterexample still reproduces its original ordering.
  defp reorder(fields, weights) do
    fields
    |> Enum.zip(weights)
    |> Enum.sort_by(&elem(&1, 1))
    |> Enum.map(&elem(&1, 0))
  end

  defp json_bytes do
    one_of([
      binary(max_length: 64),
      map(client_info(), &ClientInfo.encode/1),
      map(app_name(0, 64), fn name -> "{\"AppName\":\"" <> name <> "\"}" end),
      map(app_name(0, 64), fn key -> "{\"meshKey\":\"" <> key <> "\"}" end),
      map(list_of(unknown_field(), max_length: 6), &encode_object/1)
    ])
  end

  defp encode_object(fields) do
    fields
    |> Enum.map(fn {key, value} -> [:json.encode_binary(key), ?:, :json.encode(value)] end)
    |> Enum.intersperse(?,)
    |> then(&IO.iodata_to_binary([?{, &1, ?}]))
  end

  # `:erlang.memory(:binary)` is VM-global and moves under any concurrent test;
  # the refc binaries this process still holds after a collection are the signal
  # a retained document would show up in.
  defp referenced_binary_bytes do
    :erlang.garbage_collect()
    {:binary, references} = Process.info(self(), :binary)
    Enum.sum_by(references, &elem(&1, 1))
  end
end
