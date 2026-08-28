defmodule Derpex.SignalHandler do
  @moduledoc false

  @behaviour :gen_event

  @impl :gen_event
  def init(target) when is_pid(target), do: {:ok, target}

  @impl :gen_event
  def handle_event(:sighup, target) do
    send(target, {Derpex.Signals, :sighup})
    {:ok, target}
  end

  def handle_event(_signal, target), do: {:ok, target}

  @impl :gen_event
  def handle_call(_request, target), do: {:ok, :ok, target}

  @impl :gen_event
  def handle_info(_message, target), do: {:ok, target}

  @impl :gen_event
  def terminate(_reason, _target), do: :ok

  @impl :gen_event
  def code_change(_old_version, target, _extra), do: {:ok, target}
end
