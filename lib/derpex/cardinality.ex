defmodule Derpex.Cardinality do
  @moduledoc """
  Fixed-memory estimator for the number of distinct non-zero node keys.

  A 1,024-bit linear-counting bitmap gives useful per-connection diagnostics
  without retaining attacker-controlled keys or growing with traffic.
  """

  import Bitwise

  @bucket_count 1_024
  @word_bits 64
  @word_count div(@bucket_count, @word_bits)
  @zero_key <<0::256>>

  defstruct [:words]

  @opaque t :: %__MODULE__{words: :atomics.atomics_ref()}

  @doc "Allocates a fresh fixed-size estimator."
  @spec new() :: t()
  def new do
    %__MODULE__{words: :atomics.new(@word_count, signed: false)}
  end

  @doc "Records a node key; the zero key is intentionally ignored."
  @spec insert(t(), binary()) :: :ok
  def insert(%__MODULE__{}, @zero_key), do: :ok

  def insert(%__MODULE__{} = cardinality, <<key::binary-size(32)>>) do
    bucket = :erlang.phash2(key, @bucket_count)
    word = div(bucket, @word_bits) + 1
    mask = 1 <<< rem(bucket, @word_bits)
    set_bit(cardinality.words, word, mask)
  end

  @doc "Returns the current distinct-key estimate."
  @spec estimate(nil | t()) :: non_neg_integer()
  def estimate(nil), do: 0

  def estimate(%__MODULE__{} = cardinality) do
    occupied =
      Enum.reduce(1..@word_count, 0, fn word, count ->
        count + popcount(:atomics.get(cardinality.words, word), 0)
      end)

    estimate_occupied(occupied)
  end

  @doc "Reports the estimator's fixed storage dimensions."
  @spec dimensions() :: %{buckets: 1_024, words: 16}
  def dimensions, do: %{buckets: @bucket_count, words: @word_count}

  defp set_bit(words, word, mask) do
    previous = :atomics.get(words, word)
    updated = previous ||| mask

    case :atomics.compare_exchange(words, word, previous, updated) do
      :ok -> :ok
      _changed -> set_bit(words, word, mask)
    end
  end

  defp estimate_occupied(0), do: 0
  defp estimate_occupied(@bucket_count), do: @bucket_count

  defp estimate_occupied(occupied) do
    zeros = @bucket_count - occupied
    round(-@bucket_count * :math.log(zeros / @bucket_count))
  end

  defp popcount(0, count), do: count
  defp popcount(word, count), do: popcount(word &&& word - 1, count + 1)
end
