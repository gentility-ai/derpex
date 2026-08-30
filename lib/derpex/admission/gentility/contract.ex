defmodule Derpex.Admission.Gentility.Contract do
  @moduledoc """
  Canonical Gentility admission contract v1 authentication and decoding.

  Both leases and revocations are signed with Ed25519. All integers are
  unsigned big-endian values and all text fields are length-prefixed UTF-8.

  A relay verifies records; it never mints them. Signing therefore lives with
  Gentility, and in this repository with the test fixtures, so no release ships
  the ability to issue a lease.
  """

  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation

  @lease_magic "DXAL"
  @revocation_magic "DXRV"
  @version 1
  @signature_size 64
  @max_wire_size 4_096
  @max_key_id_size 64
  @max_identity_size 512
  @max_owner_kind_size 64
  @max_reason_size 512
  @u32_max 0xFFFF_FFFF
  @u64_max 0xFFFF_FFFF_FFFF_FFFF

  @type verification_keys :: %{required(binary()) => <<_::256>>}
  @type verify_option :: {:max_lease_ms, pos_integer()} | {:max_future_skew_ms, non_neg_integer()}

  @doc """
  Classifies a signed record by its contract v1 type magic without authenticating it.

  The authority answers an authorization with either an admission lease or a
  denial, and a denial is a signed revocation record. Callers use this to route
  a record to the matching verifier before any state is touched.
  """
  @spec record_type(binary()) :: {:ok, :lease | :revocation} | {:error, term()}
  def record_type(<<@lease_magic, _rest::binary>>), do: {:ok, :lease}
  def record_type(<<@revocation_magic, _rest::binary>>), do: {:ok, :revocation}
  def record_type(wire) when is_binary(wire), do: {:error, :unknown_record_type}

  @doc "Authenticates, decodes, and time-validates a contract v1 lease."
  @spec verify_lease(binary(), verification_keys(), integer(), [verify_option()]) ::
          {:ok, Lease.t()} | {:error, term()}
  def verify_lease(wire, verification_keys, now_ms, options \\ [])
      when is_binary(wire) and is_map(verification_keys) and is_integer(now_ms) do
    with :ok <- wire_size(wire),
         {:ok, payload, signature} <- split_signature(wire),
         {:ok, lease} <- decode_lease_payload(payload),
         {:ok, public_key} <- verification_key(verification_keys, lease.key_id),
         :ok <- verify_signature(payload, signature, public_key),
         :ok <- validate_time(lease, now_ms, options) do
      {:ok, lease}
    end
  end

  @doc """
  Decodes a lease without authenticating it.

  The durable cache uses this to tell which of two records for one node key is
  the later one before either is verified.
  """
  @spec decode_lease(binary()) :: {:ok, Lease.t()} | {:error, term()}
  def decode_lease(wire) when is_binary(wire) do
    with :ok <- wire_size(wire),
         {:ok, payload, _signature} <- split_signature(wire) do
      decode_lease_payload(payload)
    end
  end

  @doc "Authenticates and decodes a contract v1 revocation."
  @spec verify_revocation(binary(), verification_keys()) ::
          {:ok, Revocation.t()} | {:error, term()}
  def verify_revocation(wire, verification_keys)
      when is_binary(wire) and is_map(verification_keys) do
    with :ok <- wire_size(wire),
         {:ok, payload, signature} <- split_signature(wire),
         {:ok, revocation} <- decode_revocation_payload(payload),
         {:ok, public_key} <- verification_key(verification_keys, revocation.key_id),
         :ok <- verify_signature(payload, signature, public_key) do
      {:ok, revocation}
    end
  end

  defp decode_lease_payload(<<@lease_magic, @version::16, rest::binary>>) do
    with {:ok, key_id, rest} <- take_text(rest, @max_key_id_size),
         <<node_key::binary-size(32), rest::binary>> <- rest,
         {:ok, node_id, rest} <- take_text(rest, @max_identity_size),
         {:ok, organization_id, rest} <- take_text(rest, @max_identity_size),
         {:ok, owner_kind, rest} <- take_text(rest, @max_owner_kind_size),
         {:ok, deployment_id, rest} <- take_text(rest, @max_identity_size),
         <<
           region_id::32,
           policy_revision::64,
           quota_revision::64,
           issued_at_ms::64,
           expires_at_ms::64,
           node_connection_limit::32,
           organization_connection_limit::32,
           node_bytes_per_second::64,
           node_byte_burst::64,
           organization_bytes_per_second::64,
           organization_byte_burst::64
         >> <- rest do
      lease = %Lease{
        key_id: key_id,
        node_key: node_key,
        node_id: node_id,
        organization_id: organization_id,
        owner_kind: owner_kind,
        deployment_id: deployment_id,
        region_id: region_id,
        policy_revision: policy_revision,
        quota_revision: quota_revision,
        issued_at_ms: issued_at_ms,
        expires_at_ms: expires_at_ms,
        node_connection_limit: node_connection_limit,
        organization_connection_limit: organization_connection_limit,
        node_bytes_per_second: node_bytes_per_second,
        node_byte_burst: node_byte_burst,
        organization_bytes_per_second: organization_bytes_per_second,
        organization_byte_burst: organization_byte_burst
      }

      with :ok <- validate_lease(lease), do: {:ok, lease}
    else
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_lease_encoding}
    end
  end

  defp decode_lease_payload(<<@lease_magic, version::16, _rest::binary>>),
    do: {:error, {:unsupported_version, version}}

  defp decode_lease_payload(_payload), do: {:error, :invalid_lease_encoding}

  defp decode_revocation_payload(<<@revocation_magic, @version::16, rest::binary>>) do
    with {:ok, key_id, rest} <- take_text(rest, @max_key_id_size),
         <<node_key::binary-size(32), policy_revision::64, revoked_at_ms::64, rest::binary>> <-
           rest,
         {:ok, reason, ""} <- take_text(rest, @max_reason_size) do
      revocation = %Revocation{
        key_id: key_id,
        node_key: node_key,
        policy_revision: policy_revision,
        revoked_at_ms: revoked_at_ms,
        reason: reason
      }

      with :ok <- validate_revocation(revocation), do: {:ok, revocation}
    else
      {:error, _reason} = error -> error
      _invalid -> {:error, :invalid_revocation_encoding}
    end
  end

  defp decode_revocation_payload(<<@revocation_magic, version::16, _rest::binary>>),
    do: {:error, {:unsupported_version, version}}

  defp decode_revocation_payload(_payload), do: {:error, :invalid_revocation_encoding}

  @doc "Validates every field of a lease against contract v1 ranges."
  @spec validate_lease(Lease.t()) :: :ok | {:error, term()}
  def validate_lease(%Lease{} = lease) do
    with :ok <- binary_size(lease.key_id, @max_key_id_size, :key_id),
         :ok <- exact_binary_size(lease.node_key, 32, :node_key),
         :ok <- utf8_size(lease.node_id, @max_identity_size, :node_id),
         :ok <- utf8_size(lease.organization_id, @max_identity_size, :organization_id),
         :ok <- utf8_size(lease.owner_kind, @max_owner_kind_size, :owner_kind),
         :ok <- utf8_size(lease.deployment_id, @max_identity_size, :deployment_id),
         :ok <- uint(lease.region_id, @u32_max, :region_id),
         :ok <- uint(lease.policy_revision, @u64_max, :policy_revision),
         :ok <- uint(lease.quota_revision, @u64_max, :quota_revision),
         :ok <- uint(lease.issued_at_ms, @u64_max, :issued_at_ms),
         :ok <- uint(lease.expires_at_ms, @u64_max, :expires_at_ms),
         :ok <- ordered_times(lease),
         :ok <- uint(lease.node_connection_limit, @u32_max, :node_connection_limit),
         :ok <-
           uint(
             lease.organization_connection_limit,
             @u32_max,
             :organization_connection_limit
           ),
         :ok <- uint(lease.node_bytes_per_second, @u64_max, :node_bytes_per_second),
         :ok <- uint(lease.node_byte_burst, @u64_max, :node_byte_burst),
         :ok <-
           uint(
             lease.organization_bytes_per_second,
             @u64_max,
             :organization_bytes_per_second
           ) do
      uint(lease.organization_byte_burst, @u64_max, :organization_byte_burst)
    end
  end

  @doc "Validates every field of a revocation against contract v1 ranges."
  @spec validate_revocation(Revocation.t()) :: :ok | {:error, term()}
  def validate_revocation(%Revocation{} = revocation) do
    with :ok <- binary_size(revocation.key_id, @max_key_id_size, :key_id),
         :ok <- exact_binary_size(revocation.node_key, 32, :node_key),
         :ok <- uint(revocation.policy_revision, @u64_max, :policy_revision),
         :ok <- uint(revocation.revoked_at_ms, @u64_max, :revoked_at_ms) do
      utf8_size(revocation.reason, @max_reason_size, :reason)
    end
  end

  defp ordered_times(%Lease{issued_at_ms: issued, expires_at_ms: expires})
       when expires > issued,
       do: :ok

  defp ordered_times(_lease), do: {:error, :invalid_lease_time_range}

  defp validate_time(lease, now_ms, options) do
    max_lease_ms = Keyword.get(options, :max_lease_ms, 15 * 60 * 1_000)
    max_future_skew_ms = Keyword.get(options, :max_future_skew_ms, 30_000)

    cond do
      lease.issued_at_ms > now_ms + max_future_skew_ms -> {:error, :lease_not_yet_valid}
      lease.expires_at_ms <= now_ms -> {:error, :lease_expired}
      lease.expires_at_ms - lease.issued_at_ms > max_lease_ms -> {:error, :lease_too_long}
      true -> :ok
    end
  end

  defp verify_signature(payload, signature, public_key) do
    if :crypto.verify(:eddsa, :none, payload, signature, [public_key, :ed25519]) do
      :ok
    else
      {:error, :invalid_signature}
    end
  end

  defp verification_key(keys, key_id) do
    case keys[key_id] do
      <<public_key::binary-size(32)>> -> {:ok, public_key}
      nil -> {:error, {:unknown_signing_key, key_id}}
      _invalid -> {:error, {:invalid_signing_key, key_id}}
    end
  end

  defp split_signature(wire) when byte_size(wire) > @signature_size do
    payload_size = byte_size(wire) - @signature_size
    <<payload::binary-size(^payload_size), signature::binary-size(@signature_size)>> = wire
    {:ok, payload, signature}
  end

  defp split_signature(_wire), do: {:error, :invalid_signed_record}

  defp wire_size(wire) when byte_size(wire) <= @max_wire_size, do: :ok
  defp wire_size(_wire), do: {:error, :record_too_large}

  defp take_text(<<size::16, rest::binary>>, maximum) when size <= maximum do
    case rest do
      <<value::binary-size(^size), rest::binary>> ->
        if String.valid?(value), do: {:ok, value, rest}, else: {:error, :invalid_utf8}

      _short ->
        {:error, :truncated_text}
    end
  end

  defp take_text(<<_size::16, _rest::binary>>, _maximum), do: {:error, :text_too_large}
  defp take_text(_data, _maximum), do: {:error, :truncated_text}

  defp binary_size(value, maximum, _field)
       when is_binary(value) and byte_size(value) > 0 and byte_size(value) <= maximum,
       do: :ok

  defp binary_size(_value, _maximum, field), do: {:error, {:invalid_field, field}}

  defp exact_binary_size(value, size, _field)
       when is_binary(value) and byte_size(value) == size,
       do: :ok

  defp exact_binary_size(_value, _size, field), do: {:error, {:invalid_field, field}}

  defp utf8_size(value, maximum, field) do
    with :ok <- binary_size(value, maximum, field),
         true <- String.valid?(value) do
      :ok
    else
      false -> {:error, {:invalid_utf8, field}}
      {:error, _reason} = error -> error
    end
  end

  defp uint(value, maximum, _field)
       when is_integer(value) and value >= 0 and value <= maximum,
       do: :ok

  defp uint(_value, _maximum, field), do: {:error, {:invalid_field, field}}
end
