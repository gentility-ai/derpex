defmodule Derpex.Clock do
  @moduledoc """
  Injectable time and timer boundary used by DERPEX state machines.

  Protocol code must use this module rather than reading a system clock or
  scheduling a timer directly.
  """

  @type time_unit :: System.time_unit()

  @callback monotonic_time(time_unit()) :: integer()
  @callback system_time(time_unit()) :: integer()
  @callback send_after(pid(), term(), non_neg_integer()) :: reference()
  @callback cancel_timer(reference()) :: non_neg_integer() | false

  @doc "Returns monotonic time from the configured clock."
  @spec monotonic_time(time_unit()) :: integer()
  def monotonic_time(unit \\ :millisecond), do: implementation().monotonic_time(unit)

  @doc "Returns system time from the configured clock."
  @spec system_time(time_unit()) :: integer()
  def system_time(unit \\ :millisecond), do: implementation().system_time(unit)

  @doc "Schedules a message through the configured clock."
  @spec send_after(pid(), term(), non_neg_integer()) :: reference()
  def send_after(destination, message, milliseconds) do
    implementation().send_after(destination, message, milliseconds)
  end

  @doc "Cancels a timer through the configured clock."
  @spec cancel_timer(reference()) :: non_neg_integer() | false
  def cancel_timer(timer), do: implementation().cancel_timer(timer)

  defp implementation do
    Application.fetch_env!(:derpex, :clock)
  end
end
