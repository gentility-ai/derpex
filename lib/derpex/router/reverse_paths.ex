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

  `note/3` and `take/1` run in different processes - a destination's writer and
  the router - and are not serialised against each other. A note that lands
  after its source's `take/1` has already run records a path for a peer that
  has just left; nothing will take it, and it is removed when the destination's
  writer stops, which bounds it to that connection's lifetime. A note for a
  destination whose queue is already closed is refused outright and counted as
  `derp_reverse_path_late_notes`, so the window is visible rather than assumed
  to be empty.

  Cost: recording a path is two `ordered_set` inserts, roughly +0.5 us over the
  single insert this replaced, and the writer pays it once per
  `{destination, source}` pair rather than once per packet: it remembers which
  sources it has already noted and calls `note/3` only on first sight. Only the
  source index carries the lifecycle ring; the connection index stores bare
  keys.
  """

  require Derpex.Outbox

  alias Derpex.Metrics
  alias Derpex.Outbox

  @by_source __MODULE__.BySource
  @by_connection __MODULE__.ByConnection

  @type entry :: {pid(), Outbox.t()}

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

  The two inserts are not atomic, so the order picks which half-written row is
  survivable. `by_source` is written first: an interrupted `note/3` then leaves
  a row that `take/1` still notifies and then deletes, which is the failure the
  peer can recover from. Writing `by_connection` first would instead leave a row
  that no `take/1` can ever see, silently owing the destination a `peerGone`.
  """
  @spec note(binary(), pid(), Outbox.t()) :: :ok
  def note(<<source::binary-size(32)>>, connection, lifecycle)
      when is_pid(connection) and Outbox.is_outbox(lifecycle) do
    if Outbox.closed?(lifecycle) do
      Metrics.add(Metrics.default_handle(), :reverse_path_late_notes, 1)
    else
      note_open(source, connection, lifecycle)
    end
  rescue
    ArgumentError -> :ok
  end

  defp note_open(source, connection, lifecycle) do
    true = :ets.insert(@by_source, {{source, connection}, lifecycle})
    # The connection index only answers "which sources does this connection
    # hold", and its rows are read for their key alone, so it carries no copy
    # of the ring.
    true = :ets.insert(@by_connection, {{connection, source}})
    :ok
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
    |> :ets.select([{{{connection, :"$1"}}, [], [:"$1"]}])
    |> Enum.each(fn source ->
      true = :ets.delete(@by_connection, {connection, source})
      true = :ets.delete(@by_source, {source, connection})
    end)
  rescue
    ArgumentError -> :ok
  end

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
