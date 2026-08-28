defmodule Derpex.Admission do
  @moduledoc "Pre-registration authorization boundary for authenticated DERP clients."

  alias Derpex.ClientInfo

  defmodule Request do
    @moduledoc "The authenticated identity and connection metadata presented to admission policy."

    @enforce_keys [:node_key, :client_info, :source_ip, :mesh_peer?, :metadata]
    defstruct [:node_key, :client_info, :source_ip, :mesh_peer?, :metadata]

    @type t :: %__MODULE__{
            node_key: <<_::256>>,
            client_info: ClientInfo.t(),
            source_ip: :inet.ip_address(),
            mesh_peer?: boolean(),
            metadata: map()
          }
  end

  @type context :: map()
  @type decision :: {:ok, context()} | {:error, term()}
  @type policy :: nil | module() | {module(), term()} | (Request.t() -> decision())

  @callback authorize(Request.t(), term()) :: decision()
  @callback claim(Request.t(), context(), pid(), term()) :: decision()
  @callback release(pid(), term()) :: :ok
  @optional_callbacks claim: 4, release: 2

  @doc "Runs configured policy after authentication; trusted mesh peers bypass ordinary admission."
  @spec authorize(policy(), Request.t()) :: decision()
  def authorize(_policy, %Request{mesh_peer?: true}), do: {:ok, %{mesh_peer?: true}}
  def authorize(nil, %Request{}), do: {:ok, %{}}

  def authorize(policy, %Request{} = request) when is_function(policy, 1) do
    policy.(request) |> normalize_decision()
  end

  def authorize({module, options}, %Request{} = request) when is_atom(module) do
    module.authorize(request, options) |> normalize_decision()
  end

  def authorize(module, %Request{} = request) when is_atom(module) do
    module.authorize(request, []) |> normalize_decision()
  end

  @doc "Claims connection-scoped resources from policies that implement admission accounting."
  @spec claim(policy(), Request.t(), context(), pid()) :: decision()
  def claim(_policy, %Request{mesh_peer?: true}, context, _connection), do: {:ok, context}
  def claim(nil, %Request{}, context, _connection), do: {:ok, context}

  def claim(policy, %Request{}, context, _connection) when is_function(policy, 1),
    do: {:ok, context}

  def claim({module, options}, %Request{} = request, context, connection)
      when is_atom(module) and is_pid(connection) do
    if function_exported?(module, :claim, 4) do
      module.claim(request, context, connection, options) |> normalize_decision()
    else
      {:ok, context}
    end
  end

  def claim(module, %Request{} = request, context, connection)
      when is_atom(module) and is_pid(connection) do
    claim({module, []}, request, context, connection)
  end

  @doc "Releases connection-scoped resources. It is safe to call when no claim was made."
  @spec release(policy(), pid()) :: :ok
  def release(nil, _connection), do: :ok
  def release(policy, _connection) when is_function(policy, 1), do: :ok

  def release({module, options}, connection) when is_atom(module) and is_pid(connection) do
    if function_exported?(module, :release, 2), do: module.release(connection, options), else: :ok
  end

  def release(module, connection) when is_atom(module) and is_pid(connection) do
    release({module, []}, connection)
  end

  defp normalize_decision({:ok, context}) when is_map(context), do: {:ok, context}
  defp normalize_decision({:error, _reason} = error), do: error
  defp normalize_decision(other), do: {:error, {:invalid_decision, other}}
end
