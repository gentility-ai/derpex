defmodule Derpex.Crypto.Native do
  @moduledoc false

  @version Mix.Project.config()[:version]
  @base_url Application.compile_env!(:derpex, :native_base_url)
  @force_build System.get_env("DERPEX_BUILD") in ["1", "true"] or
                 Version.parse!(@version).pre != []

  use RustlerPrecompiled,
    otp_app: :derpex,
    crate: "derpex_crypto",
    base_url: "#{@base_url}/v#{@version}",
    version: @version,
    nif_versions: ["2.15"],
    targets: ~w(
      aarch64-apple-darwin
      x86_64-apple-darwin
      aarch64-unknown-linux-gnu
      x86_64-unknown-linux-gnu
    ),
    force_build: @force_build

  @spec loaded() :: boolean()
  def loaded, do: :erlang.nif_error(:nif_not_loaded)

  @spec public_key(binary()) :: {:ok, binary()} | {:error, atom()}
  def public_key(_private_key), do: :erlang.nif_error(:nif_not_loaded)

  @spec seal(binary(), binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def seal(_private_key, _peer_public_key, _nonce, _plaintext),
    do: :erlang.nif_error(:nif_not_loaded)

  @spec open(binary(), binary(), binary()) :: {:ok, binary()} | {:error, atom()}
  def open(_private_key, _peer_public_key, _boxed),
    do: :erlang.nif_error(:nif_not_loaded)
end
