defmodule Derpex.Admission.Gentility.CacheWriter do
  @moduledoc """
  Serializes durable admission-cache writes off the controller process.

  The controller keeps the records it wants durable in a shared ordered table
  and asks for a write; the sort, the encode, and the fsync all happen here. A
  cache of a hundred thousand leases therefore costs the controller nothing per
  revocation, which is what keeps revocation latency flat as the cache grows.

  At most one write is in flight; requests that arrive while one runs collapse
  into a single later write, so a burst of lease churn costs one write rather
  than a queue of them. Revocation writes are synchronous because their
  durability is what bounds a revoked node's reconnection window.

  Every row is an independently signed record, so a snapshot taken while the
  controller is still writing rows is a valid cache — never a torn one.
  """

  use GenServer

  alias Derpex.Admission.Gentility.Cache

  @journal_compaction_floor 1_000

  @doc false
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(options), do: GenServer.start_link(__MODULE__, options)

  @doc "Asks for a write, collapsing into any write still waiting to run."
  @spec write(GenServer.server()) :: :ok
  def write(server), do: GenServer.cast(server, :write)

  @doc """
  Appends revocations to the journal and waits for them to reach disk.

  This is the durability a revocation actually needs, and it costs one append
  and one flush however large the lease cache is.
  """
  @spec append_revocations(GenServer.server(), [binary()], timeout()) :: :ok | {:error, term()}
  def append_revocations(server, wires, timeout) do
    GenServer.call(server, {:append, wires}, timeout)
  catch
    :exit, reason -> {:error, {:cache_writer, reason}}
  end

  @doc "Writes the current snapshot and waits for it to reach disk."
  @spec write_sync(GenServer.server(), timeout()) :: :ok | {:error, term()}
  def write_sync(server, timeout) do
    GenServer.call(server, :write, timeout)
  catch
    :exit, reason -> {:error, {:cache_writer, reason}}
  end

  @doc false
  @spec stop(nil | pid()) :: :ok
  def stop(nil), do: :ok

  def stop(server) do
    GenServer.stop(server, :shutdown, 500)
  catch
    :exit, _reason -> :ok
  end

  @impl GenServer
  def init(options) do
    path = Keyword.fetch!(options, :path)
    owner = Keyword.fetch!(options, :owner)
    table = Keyword.fetch!(options, :table)

    if is_binary(path) and path != "" and is_pid(owner) do
      {:ok,
       %{
         path: path,
         owner: owner,
         table: table,
         pending?: false,
         journal: nil,
         appended: 0,
         journalled: 0
       }}
    else
      {:stop, :invalid_cache_writer}
    end
  end

  @impl GenServer
  def terminate(_reason, state), do: Cache.close_journal(state.journal)

  @impl GenServer
  def handle_call(:write, _from, state) do
    {result, state} = write_snapshot(state)
    {:reply, result, %{state | pending?: false}}
  end

  def handle_call({:append, wires}, _from, state) do
    case journal(state) do
      {:ok, state} -> append(state, wires)
      {:error, _reason} = error -> {:reply, error, state}
    end
  end

  @impl GenServer
  def handle_cast(:write, state) do
    send(self(), :flush)
    {:noreply, %{state | pending?: true}}
  end

  @impl GenServer
  def handle_info(:flush, %{pending?: false} = state), do: {:noreply, state}

  def handle_info(:flush, state) do
    {result, state} = write_snapshot(state)
    send(state.owner, {__MODULE__, :write_result, result})
    {:noreply, %{state | pending?: false}}
  end

  defp append(state, wires) do
    case Cache.append_journal(state.journal, wires) do
      :ok -> {:reply, :ok, compact(%{state | appended: state.appended + length(wires)})}
      {:error, _reason} = error -> {:reply, error, close(state)}
    end
  end

  # The journal only has to cover revocations the last snapshot missed, so it is
  # rewritten from the live record set once it has appended more than that set is
  # worth. The threshold follows the size of the set: a relay holding fifty
  # thousand revocations must not rewrite the journal on every append.
  defp compact(state) do
    if state.appended > compaction_threshold(state) do
      rewrite(state)
    else
      state
    end
  end

  defp compaction_threshold(state),
    do: max(2 * state.journalled, @journal_compaction_floor)

  defp rewrite(state) do
    {_leases, revocations} = snapshot(state.table)

    case Cache.compact_journal(state.path, revocations) do
      {:ok, journal} ->
        Cache.close_journal(state.journal)
        %{state | journal: journal, appended: 0, journalled: length(revocations)}

      {:error, _reason} ->
        close(state)
    end
  end

  # A snapshot carries every revocation the journal held, so the journal starts
  # over: it exists only to cover what the newest snapshot has not yet recorded.
  # Appends run in this process too, so nothing can slip between the two.
  defp truncate_journal(state) do
    case Cache.compact_journal(state.path, []) do
      {:ok, journal} ->
        Cache.close_journal(state.journal)
        %{state | journal: journal, appended: 0, journalled: 0}

      {:error, _reason} ->
        close(state)
    end
  end

  defp journal(%{journal: nil} = state) do
    with {:ok, journal} <- Cache.open_journal(state.path) do
      {:ok, %{state | journal: journal}}
    end
  end

  defp journal(state), do: {:ok, state}

  defp close(state) do
    Cache.close_journal(state.journal)
    %{state | journal: nil, appended: 0, journalled: 0}
  end

  defp write_snapshot(state) do
    {leases, revocations} = snapshot(state.table)

    case Cache.write(state.path, Cache.encode(leases, revocations)) do
      :ok -> {:ok, truncate_journal(state)}
      {:error, _reason} = error -> {error, state}
    end
  end

  # The table is an ordered set, so folding from the right yields both record
  # kinds already in canonical order without a sort.
  defp snapshot(table) do
    :ets.foldr(&collect/2, {[], []}, table)
  rescue
    ArgumentError -> {[], []}
  end

  defp collect({{:lease, _node_key}, wire}, {leases, revocations}),
    do: {[wire | leases], revocations}

  defp collect({{:revocation, _node_key}, wire}, {leases, revocations}),
    do: {leases, [wire | revocations]}
end
