defmodule Derpex.Test.UpstreamPin do
  @moduledoc """
  Resolves the pinned upstream Tailscale checkout the Go interop suites drive.

  The oracle only means anything if it is the published upstream code. A
  checkout parked on the right commit can still have edits in the working tree,
  and an edited `derpserver` would make DERPEX agree with something nobody
  ships, so both the commit and the cleanliness of the tree are checked before
  any suite runs a Go program out of it.
  """

  @commit "1e69418c298b680562a2fecd7020f7f58d17d166"

  @doc "The commit every interop suite pins the upstream checkout to."
  @spec commit() :: String.t()
  def commit, do: @commit

  @doc """
  Returns the pinned checkout's directory, raising unless it sits on `commit/0`
  with no uncommitted changes.
  """
  @spec checkout!() :: String.t()
  def checkout! do
    directory =
      System.get_env("DERPEX_TAILSCALE_DIR") ||
        raise "DERPEX_TAILSCALE_DIR must name the pinned Tailscale checkout"

    {changes, 0} = System.cmd("git", ["-C", directory, "status", "--porcelain"])

    if String.trim(changes) != "" do
      raise "#{directory} has uncommitted changes; the oracle must be the pinned code:\n#{changes}"
    end

    {head, 0} = System.cmd("git", ["-C", directory, "rev-parse", "HEAD"])
    head = String.trim(head)

    if head != @commit do
      raise "#{directory} is at #{head}; the pinned oracle is #{@commit}"
    end

    directory
  end
end
