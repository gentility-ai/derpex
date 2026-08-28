defmodule Derpex.SendQueueConfig do
  @moduledoc "Validation for the per-client ordinary/disco send queue depth."

  @default_depth 32

  @doc "Returns the upstream default queue depth."
  @spec default_depth() :: 32
  def default_depth, do: @default_depth

  @doc "Parses an optional environment value, treating empty as the default."
  @spec parse(nil | binary()) :: {:ok, pos_integer()} | {:error, :invalid_send_queue_depth}
  def parse(value)

  def parse(value) when value in [nil, ""], do: {:ok, @default_depth}

  def parse(value) when is_binary(value) do
    case Integer.parse(value) do
      {depth, ""} when depth > 0 -> {:ok, depth}
      _invalid -> {:error, :invalid_send_queue_depth}
    end
  end

  @doc "Validates an embedded handler option."
  @spec validate!(term()) :: pos_integer()
  def validate!(depth) when is_integer(depth) and depth > 0, do: depth

  def validate!(_depth) do
    raise ArgumentError, "send_queue_depth must be a positive integer"
  end
end
