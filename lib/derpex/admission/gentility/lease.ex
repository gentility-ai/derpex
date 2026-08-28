defmodule Derpex.Admission.Gentility.Lease do
  @moduledoc """
  A signed, time-bounded Gentility authorization for one DERP node key.

  Limits are instance-local allocations. A zero byte rate means unlimited;
  connection limits are always explicit and may be zero.
  """

  @enforce_keys [
    :key_id,
    :node_key,
    :node_id,
    :organization_id,
    :owner_kind,
    :deployment_id,
    :region_id,
    :policy_revision,
    :quota_revision,
    :issued_at_ms,
    :expires_at_ms,
    :node_connection_limit,
    :organization_connection_limit,
    :node_bytes_per_second,
    :node_byte_burst,
    :organization_bytes_per_second,
    :organization_byte_burst
  ]

  defstruct @enforce_keys

  @type t :: %__MODULE__{
          key_id: binary(),
          node_key: <<_::256>>,
          node_id: binary(),
          organization_id: binary(),
          owner_kind: binary(),
          deployment_id: binary(),
          region_id: non_neg_integer(),
          policy_revision: non_neg_integer(),
          quota_revision: non_neg_integer(),
          issued_at_ms: non_neg_integer(),
          expires_at_ms: non_neg_integer(),
          node_connection_limit: non_neg_integer(),
          organization_connection_limit: non_neg_integer(),
          node_bytes_per_second: non_neg_integer(),
          node_byte_burst: non_neg_integer(),
          organization_bytes_per_second: non_neg_integer(),
          organization_byte_burst: non_neg_integer()
        }
end
