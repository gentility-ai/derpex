defmodule Derpex.Debug.Traffic do
  @moduledoc "Traffic diagnostics for active DERP clients."

  alias Derpex.Router
  alias Derpex.Writer

  @doc "Estimates the number of distinct non-zero peers that sent to a client."
  @spec unique_senders(binary()) :: {:ok, non_neg_integer()} | {:error, :not_connected}
  def unique_senders(<<key::binary-size(32)>>) do
    with {:ok, writer} <- Router.active_writer(key) do
      {:ok, Writer.estimated_unique_senders(writer)}
    end
  catch
    :exit, _reason -> {:error, :not_connected}
  end
end
