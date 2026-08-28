defmodule Derpex.Certificates do
  @moduledoc "TLS certificate-chain loading with an appended DERP metacertificate."

  alias Derpex.MetaCertificate

  @doc "Loads a PEM chain and key into the in-memory OTP TLS representation."
  @spec transport_options(Path.t(), Path.t(), binary()) :: keyword()
  def transport_options(certfile, keyfile, <<server_public_key::binary-size(32)>>) do
    certificates = decode_certificates!(certfile)
    private_key = decode_private_key!(keyfile)
    meta_certificate = MetaCertificate.generate(server_public_key)

    [
      certs_keys: [
        %{cert: append_meta_certificate(certificates, meta_certificate), key: private_key}
      ]
    ]
  end

  @doc "Returns a fresh provider chain with the DERP metacertificate appended."
  @spec append_meta_certificate([binary()], binary()) :: [binary()]
  def append_meta_certificate(certificates, meta_certificate)
      when is_list(certificates) and is_binary(meta_certificate) do
    certificates ++ [meta_certificate]
  end

  defp decode_certificates!(path) do
    certificates =
      path
      |> File.read!()
      |> :public_key.pem_decode()
      |> Enum.flat_map(fn
        {:Certificate, der, :not_encrypted} -> [der]
        _other -> []
      end)

    case certificates do
      [] -> raise ArgumentError, "TLS certificate file contains no certificates: #{path}"
      _certificates -> certificates
    end
  end

  defp decode_private_key!(path) do
    entry =
      path
      |> File.read!()
      |> :public_key.pem_decode()
      |> Enum.find(fn
        {type, _der, :not_encrypted}
        when type in [:PrivateKeyInfo, :RSAPrivateKey, :ECPrivateKey] ->
          true

        _other ->
          false
      end)

    case entry do
      {type, der, :not_encrypted} -> {type, der}
      nil -> raise ArgumentError, "TLS key file contains no unencrypted private key: #{path}"
    end
  end
end
