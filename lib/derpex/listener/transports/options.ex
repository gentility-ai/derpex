defmodule Derpex.Listener.Transports.Options do
  @moduledoc false

  @spec resolve(list(), list()) :: list()
  def resolve(user_options, default_options) do
    Enum.uniq_by(
      [mode: :binary, active: false] ++ user_options ++ default_options,
      &option_identity/1
    )
  end

  defp option_identity({:raw, level, option, _value}), do: {:raw, level, option}
  defp option_identity({key, _value}) when is_atom(key), do: key
  defp option_identity(key) when is_atom(key), do: key
end
