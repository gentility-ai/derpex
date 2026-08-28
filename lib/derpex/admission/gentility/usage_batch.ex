defmodule Derpex.Admission.Gentility.UsageBatch do
  @moduledoc "A fixed-window, idempotently identified Gentility relay-usage batch."

  defmodule Entry do
    @moduledoc "Aggregated sender attribution and outcome counters for one usage window."

    @enforce_keys [
      :node_id,
      :organization_id,
      :owner_kind,
      :deployment_id,
      :accepted_packets,
      :accepted_bytes,
      :dropped_packets,
      :dropped_bytes
    ]

    defstruct @enforce_keys

    @type t :: %__MODULE__{
            node_id: binary(),
            organization_id: binary(),
            owner_kind: binary(),
            deployment_id: binary(),
            accepted_packets: non_neg_integer(),
            accepted_bytes: non_neg_integer(),
            dropped_packets: non_neg_integer(),
            dropped_bytes: non_neg_integer()
          }
  end

  @enforce_keys [:instance_id, :region_id, :window_start_ms, :window_end_ms, :entries]
  defstruct @enforce_keys

  @type t :: %__MODULE__{
          instance_id: binary(),
          region_id: non_neg_integer(),
          window_start_ms: non_neg_integer(),
          window_end_ms: non_neg_integer(),
          entries: [Entry.t()]
        }
end
