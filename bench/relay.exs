defmodule Derpex.Bench.Transport do
  @moduledoc false

  @behaviour Derpex.Transport
  import Kernel, except: [send: 2]

  @impl true
  def send(socket, data) do
    :atomics.add(socket.started, 1, 1)
    if socket.delay_ms > 0, do: Process.sleep(socket.delay_ms)

    :atomics.add(socket.bytes, 1, IO.iodata_length(data))
    index = :atomics.add_get(socket.frames, 1, 1)
    record_latency(socket, data, index)
    :ok
  end

  @impl true
  def close(_socket), do: :ok

  @impl true
  def peername(_socket), do: {:ok, :benchmark}

  @impl true
  def secure?(_socket), do: false

  def new(sample_capacity, delay_ms \\ 0) do
    %{
      started: :atomics.new(1, signed: false),
      frames: :atomics.new(1, signed: false),
      bytes: :atomics.new(1, signed: false),
      latencies: :atomics.new(max(sample_capacity, 1), signed: false),
      sample_capacity: sample_capacity,
      delay_ms: delay_ms
    }
  end

  defp record_latency(
         %{sample_capacity: capacity} = socket,
         [<<0x05, _payload_length::unsigned-big-32>>, [_source, packet]],
         index
       )
       when index <= capacity do
    case packet do
      <<sent_at::signed-big-64, _rest::binary>> ->
        elapsed = max(System.monotonic_time(:nanosecond) - sent_at, 0)
        :atomics.put(socket.latencies, index, div(elapsed, 1_000))

      _short ->
        :ok
    end
  end

  defp record_latency(_socket, _data, _index), do: :ok
end

defmodule Derpex.Bench.Relay do
  @moduledoc false

  alias Derpex.Bench.Transport
  alias Derpex.Outbox
  alias Derpex.Outbox.LifecycleQueue
  alias Derpex.Outbox.Ring
  alias Derpex.Router
  alias Derpex.Writer

  @defaults %{
    packets: 2_000,
    sizes: [64, 1_200, 65_536],
    queue_depth: 32,
    slow_packets: 10_000,
    slow_delay_ms: 1_000,
    output: nil,
    fail_on: %{}
  }

  # `--fail-on NAME=VALUE` thresholds. Upstream's TestLookupDestHashTrieNoAlloc
  # asserts the Go relay allocates nothing on the packet path; DERPEX cannot
  # assert allocations, so it asserts the observable consequences instead —
  # bounded memory growth, bounded latency, sustained throughput, and a queue
  # that never has to replace a packet in a healthy flow.
  @thresholds %{
    "memory_delta_bytes" => {:maximum, "per-flow BEAM memory growth in bytes"},
    "latency_p99_us" => {:maximum, "per-flow p99 relay latency in microseconds"},
    "latency_maximum_us" => {:maximum, "per-flow worst relay latency in microseconds"},
    "queue_replacements" => {:maximum, "per-flow queue head replacements"},
    "packets_per_second" => {:minimum, "per-flow sustained relay throughput"}
  }

  def run(arguments) do
    arguments = if List.first(arguments) == "--", do: tl(arguments), else: arguments
    options = parse_options(arguments)

    if options.help do
      usage()
    else
      report = benchmark(options)
      encoded = report |> :json.encode() |> IO.iodata_to_binary()
      IO.puts(encoded)
      if options.output, do: File.write!(options.output, encoded <> "\n")
      enforce_thresholds!(report, options.fail_on)
    end
  end

  # Reporting a regression is only a gate if it fails the build, so the
  # violations are collected and raised after the report has been written.
  defp enforce_thresholds!(_report, thresholds) when map_size(thresholds) == 0, do: :ok

  defp enforce_thresholds!(report, thresholds) do
    violations =
      for flow <- report["relay_flows"],
          {name, limit} <- thresholds,
          violation = violation(flow, name, limit),
          do: violation

    unless violations == [] do
      raise "benchmark thresholds violated:\n  " <> Enum.join(violations, "\n  ")
    end

    :ok
  end

  defp violation(flow, name, limit) do
    {direction, description} = Map.fetch!(@thresholds, name)
    observed = observed(flow, name)
    size = flow["packet_size_bytes"]

    case direction do
      :maximum when observed > limit ->
        "#{size} B flow: #{description} was #{observed}, above the #{limit} ceiling"

      :minimum when observed < limit ->
        "#{size} B flow: #{description} was #{observed}, below the #{limit} floor"

      _within_threshold ->
        nil
    end
  end

  defp observed(flow, "latency_p99_us"), do: flow["latency_us"]["p99"]
  defp observed(flow, "latency_maximum_us"), do: flow["latency_us"]["maximum"]
  defp observed(flow, name), do: flow[name]

  defp benchmark(options) do
    :erlang.garbage_collect()
    memory_before = :erlang.memory(:total)

    flows = Enum.map(options.sizes, &run_flow(&1, options))
    soak = run_slow_client_soak(options)
    idle = measure_idle_connection(options)

    :erlang.garbage_collect()
    memory_after = :erlang.memory(:total)

    %{
      "schema" => "derpex-relay-benchmark-v1",
      "generated_at" => DateTime.utc_now() |> DateTime.truncate(:second) |> DateTime.to_iso8601(),
      "runtime" => runtime_metadata(),
      "configuration" => %{
        "packets_per_size" => options.packets,
        "packet_sizes" => options.sizes,
        "queue_depth" => options.queue_depth,
        "slow_packets" => options.slow_packets,
        "slow_delay_ms" => options.slow_delay_ms
      },
      "relay_flows" => flows,
      "slow_client_isolation" => soak,
      "idle_connection" => idle,
      "beam_total_memory_before_bytes" => memory_before,
      "beam_total_memory_after_bytes" => memory_after,
      "beam_total_memory_delta_bytes" => memory_after - memory_before,
      "thresholds_applied" => options.fail_on
    }
  end

  defp run_flow(packet_size, options) do
    socket = Transport.new(options.packets)
    {writer, rings, destination} = start_destination(socket, options.queue_depth)
    source = :crypto.strong_rand_bytes(32)
    padding = :binary.copy(<<0xA5>>, packet_size - 8)
    memory_before = :erlang.memory(:total)
    started_at = System.monotonic_time(:nanosecond)

    try do
      observations =
        1..options.packets
        |> Enum.chunk_every(options.queue_depth)
        |> Enum.reduce(initial_observations(), fn batch, observations ->
          observations =
            Enum.reduce(batch, observations, fn _sequence, current ->
              packet = <<System.monotonic_time(:nanosecond)::signed-big-64, padding::binary>>
              {retries, replaced?} = route_until_accepted(source, destination, packet, 0)

              %{
                current
                | accepted: current.accepted + 1,
                  contention_retries: current.contention_retries + retries,
                  replacements: current.replacements + if(replaced?, do: 1, else: 0)
              }
            end)

          observations = observe_bounds(observations, writer, rings.ordinary)
          await_counter(socket.frames, observations.accepted, 30_000)
          observations
        end)

      elapsed_ns = max(System.monotonic_time(:nanosecond) - started_at, 1)
      latencies = atomics_values(socket.latencies, options.packets)
      ring_stats = await_ring_stats(rings.ordinary)
      memory_after = :erlang.memory(:total)

      if observations.replacements != 0 do
        raise "healthy relay benchmark replaced queued packets"
      end

      %{
        "packet_size_bytes" => packet_size,
        "packets" => options.packets,
        "payload_bytes" => packet_size * options.packets,
        "wire_bytes" => :atomics.get(socket.bytes, 1),
        "elapsed_ms" => elapsed_ns / 1_000_000,
        "packets_per_second" => options.packets * 1_000_000_000 / elapsed_ns,
        "payload_bytes_per_second" => packet_size * options.packets * 1_000_000_000 / elapsed_ns,
        "latency_us" => percentile_report(latencies),
        "contention_retries" => observations.contention_retries,
        "queue_replacements" => observations.replacements,
        "maximum_ring_size" => observations.maximum_ring_size,
        "maximum_writer_mailbox" => observations.maximum_writer_mailbox,
        "final_ring_size" => ring_stats.size,
        "memory_delta_bytes" => memory_after - memory_before
      }
    after
      stop_destination(writer, rings, destination)
    end
  end

  defp run_slow_client_soak(options) do
    slow_socket = Transport.new(0, options.slow_delay_ms)
    fast_socket = Transport.new(1)

    {slow_writer, slow_rings, slow_destination} =
      start_destination(slow_socket, options.queue_depth)

    {fast_writer, fast_rings, fast_destination} =
      start_destination(fast_socket, options.queue_depth)

    source = :crypto.strong_rand_bytes(32)
    packet = :binary.copy(<<0x5A>>, 1_200)
    memory_before = :erlang.memory(:total)

    try do
      {:ok, _wake} = Router.route(source, slow_destination, packet)
      await_counter(slow_socket.started, 1, 5_000)

      outcomes =
        Enum.reduce(1..options.slow_packets, %{accepted: 0, replacements: 0, tail_drops: 0}, fn _,
                                                                                                acc ->
          case Router.route(source, slow_destination, packet) do
            {:ok, :replaced} ->
              %{acc | accepted: acc.accepted + 1, replacements: acc.replacements + 1}

            {:ok, _wake} ->
              %{acc | accepted: acc.accepted + 1}

            {:dropped, :contention} ->
              %{acc | tail_drops: acc.tail_drops + 1}
          end
        end)

      slow_stats = await_ring_stats(slow_rings.ordinary)
      {:message_queue_len, slow_mailbox} = Process.info(slow_writer, :message_queue_len)

      fast_packet =
        <<System.monotonic_time(:nanosecond)::signed-big-64, :binary.copy(<<0xC3>>, 56)::binary>>

      {fast_retries, fast_replaced?} =
        route_until_accepted(source, fast_destination, fast_packet, 0)

      await_counter(fast_socket.frames, 1, 5_000)
      [fast_latency] = atomics_values(fast_socket.latencies, 1)
      memory_after = :erlang.memory(:total)

      bounded? =
        slow_stats.size <= options.queue_depth and
          slow_stats.packet_slots <= options.queue_depth and slow_mailbox <= 1 and
          not fast_replaced?

      unless bounded?, do: raise("slow-client isolation violated a bounded-state invariant")

      %{
        "bounded" => true,
        "attempted_packets" => options.slow_packets + 1,
        "accepted_packets" => outcomes.accepted + 1,
        "queue_head_replacements" => outcomes.replacements,
        "queue_tail_drops" => outcomes.tail_drops,
        "ring_capacity" => options.queue_depth,
        "retained_packets" => slow_stats.packet_slots,
        "writer_mailbox_messages" => slow_mailbox,
        "independent_flow_latency_us" => fast_latency,
        "independent_flow_contention_retries" => fast_retries,
        "memory_delta_bytes" => memory_after - memory_before
      }
    after
      stop_destination(slow_writer, slow_rings, slow_destination)
      stop_destination(fast_writer, fast_rings, fast_destination)
    end
  end

  # What one connected, silent client costs: four ring tables, their atomics,
  # and the writer process.
  defp measure_idle_connection(options) do
    :erlang.garbage_collect()
    before_bytes = :erlang.memory(:total)
    connections = 64

    started =
      Enum.map(1..connections, fn _index ->
        start_destination(Transport.new(0), options.queue_depth)
      end)

    :erlang.garbage_collect()
    after_bytes = :erlang.memory(:total)

    # Three rings and one lifecycle queue, the way a real connection is built.
    ring_words =
      started
      |> Enum.flat_map(fn {_writer, rings, _destination} -> Map.values(rings) end)
      |> Enum.map(&outbox_memory_words/1)
      |> Enum.sum()

    Enum.each(started, fn {writer, rings, destination} ->
      stop_destination(writer, rings, destination)
    end)

    %{
      "connections" => connections,
      "bytes_per_idle_connection" => div(after_bytes - before_bytes, connections),
      "ring_table_bytes_per_idle_connection" =>
        div(ring_words * :erlang.system_info(:wordsize), connections)
    }
  end

  defp start_destination(socket, queue_depth) do
    {:ok, writer} =
      Writer.start_link(owner: self(), transport: Transport, socket: socket)

    Process.unlink(writer)

    rings = %{
      ordinary: Ring.new(queue_depth, notifier: writer, wake_message: Writer.wake_message()),
      disco: Ring.new(queue_depth, notifier: writer, wake_message: Writer.wake_message()),
      pong: Ring.new(1, notifier: writer, wake_message: Writer.wake_message(), full: :reject),
      lifecycle: LifecycleQueue.new(notifier: writer, wake_message: Writer.wake_message())
    }

    :ok = Writer.attach(writer, rings)
    destination = :crypto.strong_rand_bytes(32)
    :ok = Router.register(destination, writer, rings.ordinary, rings.disco, rings.lifecycle)
    {writer, rings, destination}
  end

  defp stop_destination(writer, rings, destination) do
    _result = Router.unregister(destination, writer)
    Enum.each(rings, fn {_kind, ring} -> close_ring(ring) end)
    if Process.alive?(writer), do: Process.exit(writer, :kill)
  end

  defp outbox_memory_words(%Ring{} = ring), do: Ring.memory_words(ring)

  defp outbox_memory_words(%LifecycleQueue{} = queue), do: LifecycleQueue.memory_words(queue)

  defp close_ring(outbox) do
    case Outbox.close(outbox) do
      :ok -> :ok
      :busy -> close_ring(outbox)
    end
  end

  defp route_until_accepted(source, destination, packet, retries) do
    case Router.route(source, destination, packet) do
      {:ok, :replaced} -> {retries, true}
      {:ok, _wake} -> {retries, false}
      {:dropped, :contention} -> route_until_accepted(source, destination, packet, retries + 1)
    end
  end

  defp initial_observations do
    %{
      accepted: 0,
      contention_retries: 0,
      replacements: 0,
      maximum_ring_size: 0,
      maximum_writer_mailbox: 0
    }
  end

  defp observe_bounds(observations, writer, ring) do
    stats = await_ring_stats(ring)
    {:message_queue_len, mailbox} = Process.info(writer, :message_queue_len)

    %{
      observations
      | maximum_ring_size: max(observations.maximum_ring_size, stats.size),
        maximum_writer_mailbox: max(observations.maximum_writer_mailbox, mailbox)
    }
  end

  defp await_ring_stats(ring) do
    case Ring.stats(ring) do
      :busy -> await_ring_stats(ring)
      stats -> stats
    end
  end

  defp await_counter(counter, expected, timeout_ms) do
    deadline = System.monotonic_time(:millisecond) + timeout_ms
    await_counter_until(counter, expected, deadline)
  end

  defp await_counter_until(counter, expected, deadline) do
    if :atomics.get(counter, 1) >= expected do
      :ok
    else
      if System.monotonic_time(:millisecond) >= deadline do
        raise "benchmark timed out waiting for #{expected} writes"
      end

      Process.sleep(1)
      await_counter_until(counter, expected, deadline)
    end
  end

  defp atomics_values(_atomics, 0), do: []
  defp atomics_values(atomics, count), do: Enum.map(1..count, &:atomics.get(atomics, &1))

  defp percentile_report(values) do
    sorted = Enum.sort(values)

    %{
      "p50" => percentile(sorted, 0.50),
      "p95" => percentile(sorted, 0.95),
      "p99" => percentile(sorted, 0.99),
      "maximum" => List.last(sorted)
    }
  end

  defp percentile(sorted, fraction) do
    index = max(ceil(length(sorted) * fraction) - 1, 0)
    Enum.at(sorted, index)
  end

  defp runtime_metadata do
    {os_family, os_name} = :os.type()

    %{
      "elixir" => System.version(),
      "otp_release" => System.otp_release(),
      "erts" => :erlang.system_info(:version) |> List.to_string(),
      "os" => "#{os_family}/#{os_name}",
      "schedulers" => :erlang.system_info(:schedulers_online),
      "logical_processors" => :erlang.system_info(:logical_processors_available),
      "word_size" => :erlang.system_info(:wordsize)
    }
  end

  defp parse_options(arguments) do
    {parsed, positional, invalid} =
      OptionParser.parse(arguments,
        strict: [
          packets: :integer,
          sizes: :string,
          queue_depth: :integer,
          slow_packets: :integer,
          slow_delay_ms: :integer,
          output: :string,
          fail_on: :keep,
          help: :boolean
        ]
      )

    if positional != [] or invalid != [], do: raise("invalid benchmark arguments")

    {fail_on, parsed} = Keyword.pop_values(parsed, :fail_on)

    options =
      @defaults
      |> Map.merge(Map.new(parsed))
      |> Map.put(:fail_on, parse_thresholds(fail_on))
      |> Map.update!(:sizes, &parse_sizes/1)
      |> Map.put_new(:help, false)

    validate_options!(options)
  end

  defp parse_thresholds(thresholds) do
    Map.new(thresholds, fn threshold ->
      with [name, value] <- String.split(threshold, "=", parts: 2),
           true <- Map.has_key?(@thresholds, name),
           {limit, ""} <- Float.parse(value) do
        {name, limit}
      else
        _invalid ->
          raise "--fail-on takes NAME=VALUE with NAME in " <>
                  "#{@thresholds |> Map.keys() |> Enum.sort() |> Enum.join(", ")}, got " <>
                  inspect(threshold)
      end
    end)
  end

  defp parse_sizes(sizes) when is_list(sizes), do: sizes

  defp parse_sizes(sizes) do
    String.split(sizes, ",", trim: true)
    |> Enum.map(fn size ->
      case Integer.parse(size) do
        {parsed, ""} -> parsed
        _invalid -> raise "packet sizes must be comma-separated integers"
      end
    end)
  end

  defp validate_options!(options) do
    positive = [options.packets, options.queue_depth, options.slow_packets, options.slow_delay_ms]

    if Enum.any?(positive, &(&1 <= 0)) or options.sizes == [] or
         Enum.any?(options.sizes, &(&1 not in 8..65_536)) do
      raise "counts, queue depth, and delay must be positive; packet sizes must be 8..65536"
    end

    options
  end

  defp usage do
    IO.puts("""
    Usage: mix bench -- [options]

      --packets N          packets per healthy-flow size (default 2000)
      --sizes CSV          payload sizes in bytes (default 64,1200,65536)
      --queue-depth N      fixed packet-ring capacity (default 32)
      --slow-packets N     saturation attempts in the slow-client soak (default 10000)
      --slow-delay-ms N    simulated blocked write duration (default 1000)
      --output PATH        also write the JSON report to PATH
      --fail-on NAME=N     fail the run when a healthy flow crosses a threshold;
                           repeatable. NAME is one of:
                             memory_delta_bytes    ceiling
                             latency_p99_us        ceiling
                             latency_maximum_us    ceiling
                             queue_replacements    ceiling
                             packets_per_second    floor
    """)
  end
end

Derpex.Bench.Relay.run(System.argv())
