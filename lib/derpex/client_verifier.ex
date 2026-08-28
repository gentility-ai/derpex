defmodule Derpex.ClientVerifier do
  @moduledoc "Pre-admission verification for authenticated DERP clients."

  alias Derpex.Admission.Request

  @type verifier :: nil | module() | {module(), term()} | (Request.t() -> result())
  @type result :: :ok | {:error, term()}

  @callback verify(Request.t(), term()) :: result()

  @doc "Verifies an ordinary client; trusted mesh peers always bypass verification."
  @spec verify(verifier(), Request.t()) :: result()
  def verify(_verifier, %Request{mesh_peer?: true}), do: :ok
  def verify(nil, %Request{}), do: :ok

  def verify(verifier, %Request{} = request) when is_function(verifier, 1) do
    verifier.(request) |> normalize_result()
  end

  def verify({module, options}, %Request{} = request) when is_atom(module) do
    module.verify(request, options) |> normalize_result()
  end

  def verify(module, %Request{} = request) when is_atom(module) do
    verify({module, []}, request)
  end

  defp normalize_result(:ok), do: :ok
  defp normalize_result({:error, _reason} = error), do: error
  defp normalize_result(other), do: {:error, {:invalid_verification_result, other}}
end
