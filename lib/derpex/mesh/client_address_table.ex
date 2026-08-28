defmodule Derpex.Mesh.ClientAddressTable do
  @moduledoc false

  use GenServer

  @table __MODULE__

  def start_link(options \\ []) do
    GenServer.start_link(__MODULE__, :ok, Keyword.put_new(options, :name, __MODULE__))
  end

  @spec put(pid(), {:inet.ip_address(), :inet.port_number()}) :: true
  def put(client, address), do: :ets.insert(@table, {client, address})

  @spec delete(pid()) :: true
  def delete(client), do: :ets.delete(@table, client)

  @spec fetch(pid()) ::
          {:ok, {:inet.ip_address(), :inet.port_number()}} | {:error, :not_connected}
  def fetch(client) do
    case :ets.lookup(@table, client) do
      [{^client, address}] ->
        if Process.alive?(client) do
          {:ok, address}
        else
          :ets.delete(@table, client)
          {:error, :not_connected}
        end

      [] ->
        {:error, :not_connected}
    end
  rescue
    ArgumentError -> {:error, :not_connected}
  end

  @impl true
  def init(:ok) do
    table = :ets.new(@table, [:named_table, :set, :public, read_concurrency: true])
    {:ok, table}
  end
end
