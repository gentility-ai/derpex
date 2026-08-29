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
    :remove_forwarder_other,
    :home_moves_in,
    :home_moves_out,
    :write_errors,
    :ring_producer_naps
  ]

  @drop_reasons [
    :unknown_dest,
    :unknown_dest_on_fwd,
    :gone_disconnected,
    :queue_head,
    :queue_tail,
    :write_error,
    :dup_client
  ]
  @packet_kinds [:disco, :other, :forward]
  @tcp_rtt_buckets [
    {10_000, "10ms"},
    {20_000, "20ms"},
    {50_000, "50ms"},
    {100_000, "100ms"},
    {150_000, "150ms"},
    {250_000, "250ms"},
    {500_000, "500ms"}
  ]
  @tcp_rtt_labels Enum.map(@tcp_rtt_buckets, &elem(&1, 1)) ++ ["inf", "error", "non-tcp"]
  @drop_metric_names for metric <- [:packets_dropped, :bytes_dropped],
                         reason <- @drop_reasons,
                         kind <- @packet_kinds,
                         do: {metric, reason, kind}
  @tcp_rtt_metric_names Enum.map(@tcp_rtt_labels, &{:tcp_rtt, &1})
  @metric_names @metric_names ++ @drop_metric_names ++ @tcp_rtt_metric_names

  @indexes @metric_names |> Enum.with_index(1) |> Map.new()
  @persistent_key {__MODULE__, :default_handle}

  @type key :: atom() | {atom(), atom(), atom()}
  @opaque handle :: %{
            counters: :counters.counters_ref(),
            queue_average: :atomics.atomics_ref()
          }

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
    :counters.add(handle.counters, Map.fetch!(@indexes, key), delta)
    :ok
  end

  @doc "Observes packet queue residence using Go's alpha-0.1 moving average."
  @spec observe_queue_duration(handle() | nil, non_neg_integer()) :: :ok
  def observe_queue_duration(nil, _microseconds), do: :ok

  def observe_queue_duration(handle, microseconds)
      when is_integer(microseconds) and microseconds >= 0 do
    update_queue_average(handle.queue_average, microseconds / 1_000)
  end

  @doc "Adds a sample to the pinned Linux TCP RTT bucket set."
  @spec observe_tcp_rtt(handle() | nil, non_neg_integer() | :error | :non_tcp) :: :ok
  def observe_tcp_rtt(handle, microseconds)
      when is_integer(microseconds) and microseconds >= 0 do
    label =
      case Enum.find(@tcp_rtt_buckets, fn {upper_bound, _label} ->
             microseconds <= upper_bound
           end) do
        {_upper_bound, label} -> label
        nil -> "inf"
      end

    add(handle, {:tcp_rtt, label}, 1)
  end

  def observe_tcp_rtt(handle, :error), do: add(handle, {:tcp_rtt, "error"}, 1)
  def observe_tcp_rtt(handle, :non_tcp), do: add(handle, {:tcp_rtt, "non-tcp"}, 1)

  @doc "Records one packet drop in the fixed reason/kind matrix."
  @spec add_drop(handle() | nil, atom(), :disco | :other, non_neg_integer()) :: :ok
  def add_drop(handle, reason, kind, bytes)
      when reason in @drop_reasons and kind in @packet_kinds and is_integer(bytes) and bytes >= 0 do
    :ok = add(handle, {:packets_dropped, reason, kind}, 1)
    add(handle, {:bytes_dropped, reason, kind}, bytes)
  end

  @doc "Returns all fixed counters by their stable names."
  @spec snapshot(GenServer.server()) :: %{key() => non_neg_integer()}
  def snapshot(server \\ __MODULE__), do: GenServer.call(server, :snapshot)

  @doc false
  @spec metric_names() :: [key()]
  def metric_names, do: [:average_queue_duration_ms | @metric_names]

  @impl true
  def init(_options) do
    handle = %{
      counters: :counters.new(length(@metric_names), [:write_concurrency]),
      queue_average: :atomics.new(1, signed: false)
    }

    :persistent_term.put(@persistent_key, {self(), handle})
    {:ok, handle}
  end

  @impl true
  def handle_call(:handle, _from, handle), do: {:reply, handle, handle}

  def handle_call(:snapshot, _from, handle) do
    snapshot =
      Map.new(@indexes, fn {name, index} ->
        {name, :counters.get(handle.counters, index)}
      end)
      |> Map.put(
        :average_queue_duration_ms,
        handle.queue_average |> :atomics.get(1) |> bits_to_float()
      )

    {:reply, snapshot, handle}
  end

  @impl true
  def terminate(_reason, handle) do
    case :persistent_term.get(@persistent_key, nil) do
      {owner, ^handle} when owner == self() -> :persistent_term.erase(@persistent_key)
      _different -> :ok
    end

    :ok
  end

  defp update_queue_average(average, observed_ms) do
    old_bits = :atomics.get(average, 1)
    old_average = bits_to_float(old_bits)
    new_bits = float_to_bits(0.1 * observed_ms + 0.9 * old_average)

    case :atomics.compare_exchange(average, 1, old_bits, new_bits) do
      :ok -> :ok
      _changed -> update_queue_average(average, observed_ms)
    end
  end

  defp float_to_bits(value) do
    <<bits::unsigned-native-64>> = <<value::float-native-64>>
    bits
  end

  defp bits_to_float(bits) do
    <<value::float-native-64>> = <<bits::unsigned-native-64>>
    value
  end
end
