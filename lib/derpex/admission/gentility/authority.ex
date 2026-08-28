defmodule Derpex.Admission.Gentility.Authority do
  @moduledoc "The live Gentility authorization boundary used by the admission lease controller."

  alias Derpex.Admission.Request

  @type response :: {:ok, binary()} | {:error, term()}

  @callback authorize(Request.t(), term()) :: response()
end
