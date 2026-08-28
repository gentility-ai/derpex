defmodule Derpex do
  @moduledoc """
  A protocol-compatible DERP server for the Gentility overlay.

  The application is under active development. Public protocol APIs will be
  introduced only after their compatibility contracts are executable tests.
  """

  @doc "Returns the DERPEX application version."
  @spec version() :: String.t()
  def version, do: Application.spec(:derpex, :vsn) |> to_string()
end
