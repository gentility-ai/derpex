defmodule Derpex.Metrics do
  @moduledoc """
  Fixed-cardinality counters for the relay data path.

  Callers retain the opaque counter reference resolved at listener startup, so
  packet accounting performs no process call and cannot create labels from
  node, organization, peer, or source-IP data.
  """

  use GenServer

  @metric_names [
    :accepts,
    :bytes_received,
    :bytes_sent,
    :packets_received,
    :packets_sent,
    :packets_received_disco,
    :packets_received_other,
    :counter_total_dup_client_conns,
    :unknown_frames,
    :got_ping,
    :sent_pong,
    :peer_gone_disconnected_frames,
    :peer_gone_not_here_frames,
    :packets_forwarded_out,
    :packets_forwarded_in,
    :home_moves_in,
    :home_moves_out,
    :write_errors
  ]

  @indexes @metric_names |> Enum.with_index(1) |> Map.new()
  @persistent_key {__MODULE__, :default_handle}

  @type key :: unquote(Enum.reduce(@metric_names, &{:|, [], [&1, &2]}))
  @opaque handle :: :counters.counters_ref()

  @doc false
  def start_link(options \\ []) do
    {name, options} = Keyword.pop(options, :name, __MODULE__)
    GenServer.start_link(__MODULE__, options, if(name, do: [name: name], else: []))
  end

  @doc "Resolves the fixed counter handle once for a listener or test."
  @spec handle(GenServer.server()) :: handle()
  def handle(server \\ __MODULE__), do: GenServer.call(server, :handle)

  @doc "Returns the supervised default handle without a process call."
  @spec default_handle() :: handle() | nil
  def default_handle do
    case :persistent_term.get(@persistent_key, nil) do
      {_owner, handle} -> handle
      nil -> nil
    end
  end

  @doc "Adds a non-negative delta without a GenServer or ETS operation."
  @spec add(handle() | nil, key(), non_neg_integer()) :: :ok
  def add(nil, _key, _delta), do: :ok

  def add(handle, key, delta) when is_integer(delta) and delta >= 0 do
    :counters.add(handle, Map.fetch!(@indexes, key), delta)
    :ok
  end

  @doc "Returns all fixed counters by their stable names."
  @spec snapshot(GenServer.server()) :: %{key() => non_neg_integer()}
  def snapshot(server \\ __MODULE__), do: GenServer.call(server, :snapshot)

  @doc false
  @spec metric_names() :: [key()]
  def metric_names, do: @metric_names

  @impl true
  def init(_options) do
    counters = :counters.new(length(@metric_names), [:write_concurrency])
    :persistent_term.put(@persistent_key, {self(), counters})
    {:ok, counters}
  end

  @impl true
  def handle_call(:handle, _from, counters), do: {:reply, counters, counters}

  def handle_call(:snapshot, _from, counters) do
    snapshot =
      Map.new(@indexes, fn {name, index} ->
        {name, :counters.get(counters, index)}
      end)

    {:reply, snapshot, counters}
  end

  @impl true
  def terminate(_reason, counters) do
    case :persistent_term.get(@persistent_key, nil) do
      {owner, ^counters} when owner == self() -> :persistent_term.erase(@persistent_key)
      _different -> :ok
    end

    :ok
  end
end
