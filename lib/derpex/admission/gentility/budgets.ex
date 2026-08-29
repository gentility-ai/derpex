defmodule Derpex.Admission.Gentility.Budgets do
  @moduledoc """
  Incremental per-node and per-organization allocations.

  Every cached lease and every live claim contributes one node allocation and
  one organization allocation. Contributions are reference counted per quota
  revision, so admitting a lease, claiming a connection, or releasing one
  touches exactly the two identities it names and never walks the cache. The
  newest revision wins; contributions sharing a revision are merged to the
  stricter allocation, which keeps a divergent control-plane answer from
  loosening a limit.

  Byte-budget rows are published to `ByteBudget` only when an identity's
  effective allocation changes. Rows for identities with no lease and no claim
  are reclaimed by `prune/1` on the controller's timer rather than on the
  admission path.
  """

  alias Derpex.Admission.Gentility.ByteBudget
  alias Derpex.Admission.Gentility.Lease

  @enforce_keys [:table, :node, :organization]
  defstruct @enforce_keys

  @type scope :: :node | :organization

  @type budget :: %{
          identity: binary(),
          revision: non_neg_integer(),
          connection_limit: non_neg_integer(),
          bytes_per_second: non_neg_integer(),
          byte_burst: non_neg_integer()
        }

  @type t :: %__MODULE__{
          table: :ets.tid(),
          node: %{optional(binary()) => map()},
          organization: %{optional(binary()) => map()}
        }

  @doc "Creates empty allocations over shared token-bucket storage."
  @spec new(nil | :ets.tid()) :: t()
  def new(table \\ nil) do
    %__MODULE__{table: table || ByteBudget.new(), node: %{}, organization: %{}}
  end

  @doc "Returns the shared token-bucket table published to the lock-free policy handle."
  @spec table(t()) :: :ets.tid()
  def table(%__MODULE__{table: table}), do: table

  @doc "Projects the node allocation a lease grants."
  @spec node_budget(Lease.t()) :: budget()
  def node_budget(%Lease{} = lease) do
    %{
      identity: lease.node_key,
      revision: lease.quota_revision,
      connection_limit: lease.node_connection_limit,
      bytes_per_second: lease.node_bytes_per_second,
      byte_burst: lease.node_byte_burst
    }
  end

  @doc "Projects the organization allocation a lease grants."
  @spec organization_budget(Lease.t()) :: budget()
  def organization_budget(%Lease{} = lease) do
    %{
      identity: lease.organization_id,
      revision: lease.quota_revision,
      connection_limit: lease.organization_connection_limit,
      bytes_per_second: lease.organization_bytes_per_second,
      byte_burst: lease.organization_byte_burst
    }
  end

  @doc "Adds the two allocations a cached lease contributes."
  @spec add_lease(t(), Lease.t(), integer()) :: t()
  def add_lease(budgets, %Lease{} = lease, now_microsecond) do
    budgets
    |> add(:node, node_budget(lease), now_microsecond)
    |> add(:organization, organization_budget(lease), now_microsecond)
  end

  @doc "Removes the two allocations a cached lease contributed."
  @spec remove_lease(t(), Lease.t(), integer()) :: t()
  def remove_lease(budgets, %Lease{} = lease, now_microsecond) do
    budgets
    |> remove(:node, node_budget(lease), now_microsecond)
    |> remove(:organization, organization_budget(lease), now_microsecond)
  end

  @doc "Adds the two allocations a claim holds for as long as its connection lives."
  @spec add_claim(t(), map(), integer()) :: t()
  def add_claim(budgets, claim, now_microsecond) do
    budgets
    |> add(:node, claim.node_budget, now_microsecond)
    |> add(:organization, claim.organization_budget, now_microsecond)
  end

  @doc "Removes the two allocations a released claim held."
  @spec remove_claim(t(), map(), integer()) :: t()
  def remove_claim(budgets, claim, now_microsecond) do
    budgets
    |> remove(:node, claim.node_budget, now_microsecond)
    |> remove(:organization, claim.organization_budget, now_microsecond)
  end

  @doc "Adds one contribution to an identity's allocation."
  @spec add(t(), scope(), budget(), integer()) :: t()
  def add(budgets, scope, budget, now_microsecond) do
    update(budgets, scope, budget, &add_revision(&1, budget), now_microsecond)
  end

  @doc "Removes one contribution from an identity's allocation."
  @spec remove(t(), scope(), budget(), integer()) :: t()
  def remove(budgets, scope, budget, now_microsecond) do
    update(budgets, scope, budget, &remove_revision(&1, budget), now_microsecond)
  end

  @doc "Returns the connection allocation in force, or zero for an unknown identity."
  @spec connection_limit(t(), scope(), binary()) :: non_neg_integer()
  def connection_limit(budgets, scope, identity) do
    case budgets |> scope_map(scope) |> Map.get(identity) do
      nil -> 0
      entry -> entry.effective.connection_limit
    end
  end

  @doc "Returns the quota revision in force, or nil for an unknown identity."
  @spec revision(t(), scope(), binary()) :: nil | non_neg_integer()
  def revision(budgets, scope, identity) do
    case budgets |> scope_map(scope) |> Map.get(identity) do
      nil -> nil
      entry -> entry.effective.revision
    end
  end

  @doc """
  Reclaims one bounded step of token-bucket rows no longer backed by an allocation.

  Retention is decided per row against the live allocation maps, so a sweep
  neither materializes the retained set nor walks the whole table at once.
  """
  @spec prune_step(t(), :start | term(), pos_integer()) :: :done | {:cont, term()}
  def prune_step(%__MODULE__{} = budgets, cursor, limit) do
    selected =
      if cursor == :start,
        do: ByteBudget.keys(budgets.table, limit),
        else: ByteBudget.next_keys(cursor)

    case selected do
      :done ->
        :done

      {keys, continuation} ->
        Enum.each(keys, &delete_unbacked(budgets, &1))
        {:cont, continuation}
    end
  end

  @doc "Returns bounded allocation counts for health checks and assertions."
  @spec stats(t()) :: %{nodes: non_neg_integer(), organizations: non_neg_integer()}
  def stats(%__MODULE__{} = budgets) do
    %{nodes: map_size(budgets.node), organizations: map_size(budgets.organization)}
  end

  defp delete_unbacked(budgets, {scope, identity} = key) do
    if budgets |> scope_map(scope) |> Map.has_key?(identity) do
      :ok
    else
      ByteBudget.delete(budgets.table, key)
    end
  end

  defp update(budgets, scope, budget, transform, now_microsecond) do
    map = scope_map(budgets, scope)
    previous = Map.get(map, budget.identity)

    case transform.(previous) do
      nil ->
        put_scope(budgets, scope, Map.delete(map, budget.identity))

      entry ->
        if is_nil(previous) or previous.effective != entry.effective do
          ByteBudget.sync(budgets.table, scope, entry.effective, now_microsecond)
        end

        put_scope(budgets, scope, Map.put(map, budget.identity, entry))
    end
  end

  defp add_revision(nil, budget) do
    %{revisions: %{budget.revision => {budget, 1}}, effective: budget}
  end

  defp add_revision(entry, budget) do
    revisions =
      Map.update(entry.revisions, budget.revision, {budget, 1}, fn {current, count} ->
        {stricter(current, budget), count + 1}
      end)

    %{revisions: revisions, effective: effective(revisions)}
  end

  defp remove_revision(nil, _budget), do: nil

  defp remove_revision(entry, budget) do
    revisions =
      case Map.get(entry.revisions, budget.revision) do
        nil -> entry.revisions
        {_budget, 1} -> Map.delete(entry.revisions, budget.revision)
        {current, count} -> Map.put(entry.revisions, budget.revision, {current, count - 1})
      end

    if map_size(revisions) == 0 do
      nil
    else
      %{revisions: revisions, effective: effective(revisions)}
    end
  end

  defp effective(revisions) do
    {_revision, {budget, _count}} = Enum.max_by(revisions, fn {revision, _held} -> revision end)
    budget
  end

  defp stricter(left, right) do
    %{
      left
      | connection_limit: min(left.connection_limit, right.connection_limit),
        bytes_per_second: stricter_rate(left.bytes_per_second, right.bytes_per_second),
        byte_burst: min(left.byte_burst, right.byte_burst)
    }
  end

  defp stricter_rate(0, rate), do: rate
  defp stricter_rate(rate, 0), do: rate
  defp stricter_rate(left, right), do: min(left, right)

  defp scope_map(budgets, :node), do: budgets.node
  defp scope_map(budgets, :organization), do: budgets.organization

  defp put_scope(budgets, :node, map), do: %{budgets | node: map}
  defp put_scope(budgets, :organization, map), do: %{budgets | organization: map}
end
