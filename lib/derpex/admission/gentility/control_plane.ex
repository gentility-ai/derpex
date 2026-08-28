defmodule Derpex.Admission.Gentility.ControlPlane do
  @moduledoc """
  Transport boundary implemented by the Gentility control-plane integration.

  DERPEX deliberately does not prescribe HTTP, gRPC, or message-bus transport.
  Returned lease and revocation records are authenticated by contract v1.
  """

  alias Derpex.Admission.Request

  @type cursor :: binary()

  @callback authorize(Request.t(), term()) :: {:ok, binary()} | {:error, term()}
  @callback export_usage(<<_::256>>, binary(), term()) :: :ok | {:ok, term()} | {:error, term()}
  @callback reconcile(term()) :: {:ok, [binary()], cursor()} | {:error, term()}
  @callback next_revocation(cursor(), pos_integer(), term()) ::
              {:ok, binary(), cursor()} | {:timeout, cursor()} | {:error, term()}
end
