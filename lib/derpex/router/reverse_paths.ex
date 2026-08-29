defmodule Derpex.Router.ReversePaths do
  @moduledoc """
  Remembers which destination connections have received a packet from a source.

  This is DERPEX's `peerGoneWatchers` (`derpserver.go`): once a destination has
  been written a packet from a source key, that destination is owed a `peerGone`
  frame when the source leaves the region. Go stores a handle set per source and
  a matching handle map per client so both directions are cheap; a single ETS
  table keyed by the `{source, connection}` pair can only answer one direction
  without a full scan, so the same rows are indexed twice here.

  Both tables are `ordered_set`s whose keys lead with the index column, which
  makes "every row for this source" and "every row for this connection" a
  bounded range scan rather than a table scan: teardown costs the rows the
  connection actually holds, not the size of the region.

  The tables are created by, and owned by, the `Derpex.Router` process.
  """

  alias Derpex.Outbox.Ring

  @by_source __MODULE__.BySource
  @by_connection __MODULE__.ByConnection

  @type entry :: {pid(), Ring.t()}

  @doc "Creates the two indexes. Called once from the router's `init/1`."
  @spec new() :: :ok
  def new do
    _by_source = :ets.new(@by_source, table_options())
    _by_connection = :ets.new(@by_connection, table_options())
    :ok
  end

  @doc """
  Records that `connection` was written a packet from `source`.

  Repeating the same pair overwrites in place, so a source that keeps talking to
  the same destination never grows the index.
  """
  @spec note(binary(), pid(), Ring.t()) :: :ok
  def note(<<source::binary-size(32)>>, connection, %Ring{} = lifecycle)
      when is_pid(connection) do
    true = :ets.insert(@by_connection, {{connection, source}, lifecycle})
    true = :ets.insert(@by_source, {{source, connection}, lifecycle})
    :ok
  rescue
    ArgumentError -> :ok
  end

  @doc """
  Removes and returns every destination owed a `peerGone` frame for `source`.

  Mirrors `notePeerGoneFromRegionLocked`, which drains and drops the source's
  watcher set in one step so a later disconnect cannot notify twice.
  """
  @spec take(binary()) :: [entry()]
  def take(<<source::binary-size(32)>>) do
    entries =
      :ets.select(@by_source, [{{{source, :"$1"}, :"$2"}, [], [{{:"$1", :"$2"}}]}])

    Enum.each(entries, fn {connection, _lifecycle} ->
      true = :ets.delete(@by_source, {source, connection})
      true = :ets.delete(@by_connection, {connection, source})
    end)

    entries
  rescue
    ArgumentError -> []
  end

  @doc """
  Drops every reverse path held by a destination that is going away.

  Mirrors `onSendLoopDone`, which unregisters each watcher the client added.
  """
  @spec forget_connection(pid()) :: :ok
  def forget_connection(connection) when is_pid(connection) do
    @by_connection
    |> :ets.select([{{{connection, :"$1"}, :_}, [], [:"$1"]}])
    |> Enum.each(fn source ->
      true = :ets.delete(@by_connection, {connection, source})
      true = :ets.delete(@by_source, {source, connection})
    end)
  rescue
    ArgumentError -> :ok
  end

  @doc "Returns the number of recorded reverse paths, for assertions and gauges."
  @spec size() :: non_neg_integer()
  def size, do: :ets.info(@by_source, :size)

  defp table_options do
    [
      :named_table,
      :ordered_set,
      :public,
      read_concurrency: true,
      write_concurrency: true
    ]
  end
end
