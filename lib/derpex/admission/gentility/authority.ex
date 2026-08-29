defmodule Derpex.Admission.Gentility.Authority do
  @moduledoc """
  The live Gentility authorization boundary used by the admission lease controller.

  A successful call returns a signed contract v1 record: a lease admits the node
  key, a revocation denies it. `{:error, reason}` reports that the authority
  could not answer and is never read as a denial; the controller then serves an
  unexpired cached lease, or rejects the connection when there is none.
  """

  alias Derpex.Admission.Request

  @type response :: {:ok, binary()} | {:error, term()}

  @callback authorize(Request.t(), term()) :: response()
end
