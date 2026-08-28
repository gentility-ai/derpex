defmodule Derpex.Disco do
  @moduledoc "Minimal discovery-wrapper recognition needed at the DERP boundary."

  @magic <<0x54, 0x53, 0xF0, 0x9F, 0x92, 0xAC>>
  @minimum_length byte_size(@magic) + 32 + 24

  @doc "Matches Tailscale's intentionally shallow disco-wrapper check."
  @spec looks_like_wrapper?(binary()) :: boolean()
  def looks_like_wrapper?(<<@magic, _rest::binary>> = packet) do
    byte_size(packet) >= @minimum_length
  end

  def looks_like_wrapper?(_packet), do: false
end
