defmodule Derpex.Transport do
  @moduledoc "Common byte-stream operations used by DERPEX writers and handlers."

  @type t :: term()

  @callback send(t(), iodata()) :: :ok | {:error, term()}
  @callback close(t()) :: :ok | {:error, term()}
  @callback peername(t()) :: {:ok, term()} | {:error, term()}
  @callback secure?(t()) :: boolean()
end
