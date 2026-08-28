defmodule Derpex.Clock.System do
  @moduledoc false

  @behaviour Derpex.Clock

  @impl true
  def monotonic_time(unit), do: System.monotonic_time(unit)

  @impl true
  def system_time(unit), do: System.system_time(unit)

  @impl true
  def send_after(destination, message, milliseconds) do
    Process.send_after(destination, message, milliseconds)
  end

  @impl true
  def cancel_timer(timer), do: Process.cancel_timer(timer)
end
