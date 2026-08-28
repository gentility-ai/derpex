defmodule Derpex.Admission.Gentility.Revocation do
  @moduledoc "A signed Gentility instruction that invalidates leases through a policy revision."

  @enforce_keys [:key_id, :node_key, :policy_revision, :revoked_at_ms, :reason]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          key_id: binary(),
          node_key: <<_::256>>,
          policy_revision: non_neg_integer(),
          revoked_at_ms: non_neg_integer(),
          reason: binary()
        }
end
