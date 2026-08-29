defmodule Derpex.Admission.Gentility.Signer do
  @moduledoc """
  Signs contract v1 records for tests and contract fixtures.

  Signing belongs to Gentility, not to the relay: a DERPEX release verifies
  records and never mints them, so this lives in the test tree and ships
  nowhere. Encoding is written out here rather than shared with `Contract`, so
  the canonical vectors in `ContractTest` pin the production decoder against an
  independent encoder — the same check any other implementation of the contract
  has to pass.
  """

  alias Derpex.Admission.Gentility.Contract
  alias Derpex.Admission.Gentility.Lease
  alias Derpex.Admission.Gentility.Revocation

  @lease_magic "DXAL"
  @revocation_magic "DXRV"
  @version 1

  @doc "Signs a validated lease and returns its portable contract record."
  @spec sign_lease(Lease.t(), <<_::256>>) :: {:ok, binary()} | {:error, term()}
  def sign_lease(%Lease{} = lease, <<private_key::binary-size(32)>>) do
    with :ok <- Contract.validate_lease(lease) do
      payload =
        IO.iodata_to_binary([
          @lease_magic,
          <<@version::16>>,
          text(lease.key_id),
          lease.node_key,
          text(lease.node_id),
          text(lease.organization_id),
          text(lease.owner_kind),
          text(lease.deployment_id),
          <<
            lease.region_id::32,
            lease.policy_revision::64,
            lease.quota_revision::64,
            lease.issued_at_ms::64,
            lease.expires_at_ms::64,
            lease.node_connection_limit::32,
            lease.organization_connection_limit::32,
            lease.node_bytes_per_second::64,
            lease.node_byte_burst::64,
            lease.organization_bytes_per_second::64,
            lease.organization_byte_burst::64
          >>
        ])

      {:ok, payload <> sign(payload, private_key)}
    end
  end

  @doc "Signs a validated active-revocation record."
  @spec sign_revocation(Revocation.t(), <<_::256>>) :: {:ok, binary()} | {:error, term()}
  def sign_revocation(%Revocation{} = revocation, <<private_key::binary-size(32)>>) do
    with :ok <- Contract.validate_revocation(revocation) do
      payload =
        IO.iodata_to_binary([
          @revocation_magic,
          <<@version::16>>,
          text(revocation.key_id),
          revocation.node_key,
          <<revocation.policy_revision::64, revocation.revoked_at_ms::64>>,
          text(revocation.reason)
        ])

      {:ok, payload <> sign(payload, private_key)}
    end
  end

  defp text(value), do: <<byte_size(value)::16, value::binary>>

  defp sign(payload, private_key) do
    :crypto.sign(:eddsa, :none, payload, [private_key, :ed25519])
  end
end
