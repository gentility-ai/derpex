defmodule Derpex.Certificates do
  @moduledoc "TLS certificate-chain loading with an appended DERP metacertificate."

  alias Derpex.MetaCertificate

  @key_check_message "DERPEX certificate private-key check"

  @doc "Loads a PEM chain and key into the in-memory OTP TLS representation."
  @spec transport_options(Path.t(), Path.t(), binary()) :: keyword()
  def transport_options(certfile, keyfile, <<server_public_key::binary-size(32)>>) do
    certfile
    |> File.read!()
    |> transport_options_from_pem(File.read!(keyfile), server_public_key)
  end

  @doc false
  @spec transport_options_from_pem(binary(), binary(), binary()) :: keyword()
  def transport_options_from_pem(
        certificate_pem,
        key_pem,
        <<server_public_key::binary-size(32)>>
      ) do
    certificates = decode_certificates!(certificate_pem)
    {private_key, decoded_private_key} = decode_private_key!(key_pem)
    validate_private_key!(hd(certificates), decoded_private_key)
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

  defp decode_certificates!(pem) do
    certificates =
      pem
      |> :public_key.pem_decode()
      |> Enum.flat_map(fn
        {:Certificate, der, :not_encrypted} -> [der]
        _other -> []
      end)

    case certificates do
      [] -> raise ArgumentError, "TLS certificate data contains no certificates"
      _certificates -> certificates
    end
  end

  defp decode_private_key!(pem) do
    entry =
      pem
      |> :public_key.pem_decode()
      |> Enum.find(fn
        {type, _der, :not_encrypted}
        when type in [:PrivateKeyInfo, :RSAPrivateKey, :ECPrivateKey] ->
          true

        _other ->
          false
      end)

    case entry do
      {type, der, :not_encrypted} -> {{type, der}, :public_key.pem_entry_decode(entry)}
      nil -> raise ArgumentError, "TLS key data contains no unencrypted private key"
    end
  end

  @doc "Reports whether a decoded private key belongs to a DER leaf certificate."
  @spec private_key_matches?(binary(), tuple()) :: boolean()
  def private_key_matches?(certificate_der, private_key) do
    {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, algorithm, parameters}, public_key} =
      certificate_der
      |> :public_key.pkix_decode_cert(:otp)
      |> elem(1)
      |> elem(7)

    Enum.any?(
      [public_key, {public_key, parameters}, {public_key, {:namedCurve, algorithm}}],
      fn public_key ->
        Enum.any?([:sha256, :none], fn digest ->
          try do
            signature = :public_key.sign(@key_check_message, digest, private_key)
            :public_key.verify(@key_check_message, digest, signature, public_key)
          rescue
            _exception -> false
          catch
            _kind, _reason -> false
          end
        end)
      end
    )
  rescue
    _undecodable -> false
  end

  defp validate_private_key!(certificate_der, private_key) do
    unless private_key_matches?(certificate_der, private_key) do
      raise ArgumentError, "TLS private key does not match leaf certificate"
    end
  end
end
