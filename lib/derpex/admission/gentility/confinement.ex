defmodule Derpex.Admission.Gentility.Confinement do
  @moduledoc """
  Source confinement: from a listed address prefix, admit only leases of the
  owner kinds listed for it.

  The setting is `DERPEX_GENTILITY_CONFINED_SOURCES`, entries separated by
  `;`, each a prefix and its kinds separated by `|`:

      203.0.113.7/32=computer@sin-1|platform;2001:db8::/64=platform

  A connection whose source lies in a listed prefix is admitted only if its
  lease's owner kind equals one of that prefix's kinds. The compare is of the
  whole string: `computer@ryzen` matches neither `computer@ryz` nor
  `computer@ryzen2`, and a kind is never split. A source in several listed
  prefixes must match the kinds of each. Any other source is unaffected.
  A refusal is `confined_source`.

  The check runs on every new connection, after its lease is verified, whether
  the lease came live or from the cache. A renewal carries no source and is
  not checked again: its connection's source was checked when it was admitted.

  The loader refuses anything it cannot read exactly. A prefix is an address
  and a length, with no host bits set. A kind is one Gentility issues:
  `platform`, `machine`, `user`, `runtime`, or `computer@<runner id>`, where a
  runner id is 1 to 55 bytes of lowercase letters, digits and hyphens (an owner
  kind is at most 64 bytes, and `computer@` is 9). A separator that lands
  inside a runner id therefore leaves a fragment that is no kind, and is
  refused rather than read as two.
  """

  import Bitwise

  @type prefix :: {:inet.ip_address(), 0..128}
  @type t :: [{prefix(), MapSet.t(String.t())}]

  @plain_kinds ~w(platform machine user runtime)
  @computer "computer@"
  @max_runner_id_bytes 55
  @max_entries 256

  @doc "Parses the setting. An unset or empty setting confines nothing."
  @spec parse(nil | binary()) :: {:ok, t()} | {:error, {binary(), atom()}}
  def parse(value) when value in [nil, ""], do: {:ok, []}

  def parse(value) when is_binary(value) do
    entries = String.split(value, ";")

    if length(entries) > @max_entries,
      do: {:error, {value, :too_many_entries}},
      else: entries |> Enum.reduce_while({:ok, []}, &add_entry/2) |> reversed()
  end

  defp add_entry(text, {:ok, rules}) do
    case entry(text) do
      {:ok, {prefix, _kinds} = rule} ->
        if List.keymember?(rules, prefix, 0),
          do: {:halt, {:error, {text, :duplicate_prefix}}},
          else: {:cont, {:ok, [rule | rules]}}

      {:error, reason} ->
        {:halt, {:error, {text, reason}}}
    end
  end

  defp reversed({:ok, rules}), do: {:ok, Enum.reverse(rules)}
  defp reversed(error), do: error

  @doc """
  Checks one new connection's lease against the rules. A `nil` source (a
  renewal) is never confined.
  """
  @spec check(t(), nil | :inet.ip_address(), String.t()) :: :ok | {:error, :confined_source}
  def check([], _source, _owner_kind), do: :ok
  def check(_rules, nil, _owner_kind), do: :ok

  def check(rules, source, owner_kind) when is_binary(owner_kind) do
    source = unmap(source)

    if Enum.all?(rules, fn {prefix, kinds} ->
         not contains?(prefix, source) or MapSet.member?(kinds, owner_kind)
       end),
       do: :ok,
       else: {:error, :confined_source}
  end

  @doc "Checks one owner kind against the loader's rule; exposed for its tests."
  @spec valid_kind?(binary()) :: boolean()
  def valid_kind?(kind) when kind in @plain_kinds, do: true
  def valid_kind?(@computer <> runner_id), do: runner_id?(runner_id)
  def valid_kind?(_kind), do: false

  defp entry(text) do
    with [prefix_text, kinds_text] <- String.split(text, "=", parts: 2),
         {:ok, prefix} <- prefix(prefix_text),
         {:ok, kinds} <- kinds(kinds_text) do
      {:ok, {prefix, kinds}}
    else
      [_no_kinds] -> {:error, :invalid_entry}
      {:error, _reason} = error -> error
    end
  end

  defp kinds(text) do
    kinds = String.split(text, "|")

    cond do
      not Enum.all?(kinds, &valid_kind?/1) -> {:error, :invalid_kind}
      length(Enum.uniq(kinds)) != length(kinds) -> {:error, :duplicate_kind}
      true -> {:ok, MapSet.new(kinds)}
    end
  end

  defp runner_id?(id) when byte_size(id) in 1..@max_runner_id_bytes,
    do: id |> :binary.bin_to_list() |> Enum.all?(&runner_byte?/1)

  defp runner_id?(_id), do: false

  defp runner_byte?(byte), do: byte in ?a..?z or byte in ?0..?9 or byte == ?-

  defp prefix(text) do
    with [address_text, length_text] <- String.split(text, "/", parts: 2),
         {:ok, address} <- address_text |> String.to_charlist() |> :inet.parse_strict_address(),
         {length, ""} <- Integer.parse(length_text),
         true <- length in 0..bits(address),
         true <- host_bits(address, length) == 0 do
      {:ok, {address, length}}
    else
      _invalid -> {:error, :invalid_prefix}
    end
  end

  defp contains?({network, length}, source) when tuple_size(network) == tuple_size(source) do
    shift = bits(network) - length
    integer(network) >>> shift == integer(source) >>> shift
  end

  defp contains?(_prefix, _source), do: false

  defp host_bits(address, length), do: integer(address) &&& (1 <<< (bits(address) - length)) - 1

  # A dual-stack listener reports an IPv4 peer as an IPv4-mapped IPv6 address;
  # it is the IPv4 source, and an IPv4 prefix must see it as one.
  defp unmap({0, 0, 0, 0, 0, 0xFFFF, high, low}) do
    <<a, b, c, d>> = <<high::16, low::16>>
    {a, b, c, d}
  end

  defp unmap(source), do: source

  defp bits(address) when tuple_size(address) == 4, do: 32
  defp bits(address) when tuple_size(address) == 8, do: 128

  defp integer({a, b, c, d}), do: :binary.decode_unsigned(<<a, b, c, d>>)

  defp integer({a, b, c, d, e, f, g, h}),
    do: :binary.decode_unsigned(<<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>)
end
