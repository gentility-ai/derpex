defmodule Derpex.Outbox do
  @moduledoc """
  The one call site for both outbox structures.

  Packets go into a fixed `Derpex.Outbox.Ring`, which replaces its oldest entry
  when it is full. Lifecycle frames go into a `Derpex.Outbox.LifecycleQueue`,
  which grows instead, because a dropped state change is never corrected by a
  later one. Both answer the same four calls, so the router, the writer and the
  drain coordinator do not care which one they hold.
  """

  alias Derpex.Outbox.LifecycleQueue
  alias Derpex.Outbox.Ring

  @type t :: Ring.t() | LifecycleQueue.t()
  @type enqueue_result :: Ring.enqueue_result() | LifecycleQueue.enqueue_result()

  @doc "True for anything this module can dispatch on."
  defguard is_outbox(value) when is_struct(value, Ring) or is_struct(value, LifecycleQueue)

  @doc "Publishes one message."
  @spec enqueue(t(), term(), keyword()) :: enqueue_result()
  def enqueue(outbox, message, options \\ [])
  def enqueue(%Ring{} = ring, message, options), do: Ring.enqueue(ring, message, options)

  def enqueue(%LifecycleQueue{} = queue, message, options),
    do: LifecycleQueue.enqueue(queue, message, options)

  @doc "Takes the next message with its queue residence time."
  @spec take_with_age(t()) :: {:ok, term(), non_neg_integer()} | :empty | :closed | :busy
  def take_with_age(%Ring{} = ring), do: Ring.take_with_age(ring)
  def take_with_age(%LifecycleQueue{} = queue), do: LifecycleQueue.take_with_age(queue)

  @doc "Takes the next message."
  @spec take(t()) :: {:ok, term()} | :empty | :closed | :busy
  def take(%Ring{} = ring), do: Ring.take(ring)
  def take(%LifecycleQueue{} = queue), do: LifecycleQueue.take(queue)

  @doc "Closes and releases everything retained. Idempotent."
  @spec close(t()) :: :ok | :busy
  def close(%Ring{} = ring), do: Ring.close(ring)
  def close(%LifecycleQueue{} = queue), do: LifecycleQueue.close(queue)

  @doc "Closes and then deletes the underlying table."
  @spec delete(t()) :: :ok
  def delete(%Ring{} = ring), do: Ring.delete(ring)
  def delete(%LifecycleQueue{} = queue), do: LifecycleQueue.delete(queue)

  @doc "True once the structure has been closed."
  @spec closed?(t()) :: boolean()
  def closed?(%Ring{} = ring), do: Ring.closed?(ring)
  def closed?(%LifecycleQueue{} = queue), do: LifecycleQueue.closed?(queue)

  @doc "Returns the structure's counters."
  @spec stats(t()) :: map() | :busy
  def stats(%Ring{} = ring), do: Ring.stats(ring)
  def stats(%LifecycleQueue{} = queue), do: LifecycleQueue.stats(queue)
end
