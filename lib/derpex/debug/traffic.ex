defmodule Derpex.Debug.Traffic do
  @moduledoc "Traffic diagnostics for active DERP clients."

  alias Derpex.Debug.SS
  alias Derpex.JSON
  alias Derpex.Router
  alias Derpex.Writer

  @type state :: %{optional(SS.endpoint()) => SS.counters()}

  @doc "Samples Linux TCP byte counters and encodes changed authenticated clients."
  @spec sample(state(), keyword()) :: {:ok, state(), iodata()} | {:error, term()}
  def sample(previous \\ %{}, options \\ []) when is_map(previous) do
    with {:ok, output} <- run_ss(options) do
      current = SS.parse(output)
      clients = client_keys(options)

      records =
        current
        |> Enum.sort_by(&elem(&1, 0))
        |> Enum.flat_map(&changed_record(&1, previous, clients))

      {:ok, current, [Enum.map(records, &[&1, ?\n]), ?\n]}
    end
  end

  @doc "Estimates the number of distinct non-zero peers that sent to a client."
  @spec unique_senders(binary()) :: {:ok, non_neg_integer()} | {:error, :not_connected}
  def unique_senders(<<key::binary-size(32)>>) do
    with {:ok, writer} <- Router.active_writer(key) do
      {:ok, Writer.estimated_unique_senders(writer)}
    end
  catch
    :exit, _reason -> {:error, :not_connected}
  end

  defp run_ss(options) do
    case Keyword.get(options, :run_ss) do
      function when is_function(function, 0) -> function.()
      nil -> system_ss()
    end
  rescue
    exception -> {:error, Exception.message(exception)}
  catch
    kind, reason -> {:error, Exception.format_banner(kind, reason)}
  end

  defp system_ss do
    case System.cmd("ss", ["-i", "-H", "-t"], stderr_to_stdout: true) do
      {output, 0} -> {:ok, output}
      {_output, status} -> {:error, "exit status #{status}"}
    end
  end

  defp client_keys(options) do
    case Keyword.get(options, :client_keys) do
      function when is_function(function, 0) -> function.()
      nil -> Router.debug_client_keys()
    end
  end

  defp changed_record({endpoint, counters}, previous, clients) do
    prior = Map.get(previous, endpoint, %{sent: 0, received: 0})

    if increased?(prior, counters) do
      case Map.fetch(clients, endpoint) do
        {:ok, key} -> [encode_record(counters, key)]
        :error -> []
      end
    else
      []
    end
  end

  defp increased?(prior, current),
    do: prior.sent < current.sent or prior.received < current.received

  defp encode_record(counters, key) do
    fields = [
      {"Sent", counters.sent},
      {"Recv", counters.received},
      {"Key", "nodekey:" <> Base.encode16(key, case: :lower)}
    ]

    fields =
      case unique_senders(key) do
        {:ok, count} when count > 0 -> fields ++ [{"UniqueSenders", count}]
        _zero_or_disconnected -> fields
      end

    JSON.encode_object(fields)
  end
end
