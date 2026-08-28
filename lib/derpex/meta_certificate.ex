defmodule Derpex.MetaCertificate do
  @moduledoc "Builds the self-signed DERP identity certificate used for TLS fast start."

  alias Derpex.Clock

  @common_name_oid {2, 5, 4, 3}
  @basic_constraints_oid {2, 5, 29, 19}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @sha256_with_rsa_oid {1, 2, 840, 113_549, 1, 1, 11}
  @protocol_version 2
  @validity_seconds 30 * 24 * 60 * 60

  @doc "Returns a DER-encoded certificate carrying the server node key and protocol version."
  @spec generate(binary()) :: binary()
  def generate(<<server_public_key::binary-size(32)>>) do
    private_key = :public_key.generate_key({:rsa, 2_048, 65_537})
    public_key = {:RSAPublicKey, elem(private_key, 2), elem(private_key, 3)}
    common_name = "derpkey" <> Base.encode16(server_public_key, case: :lower)
    name = distinguished_name(common_name)
    signature = signature_algorithm()

    tbs_certificate =
      {:OTPTBSCertificate, :v3, @protocol_version, signature, name, validity(), name,
       subject_public_key_info(public_key), :asn1_NOVALUE, :asn1_NOVALUE,
       [basic_constraints_extension()]}

    :public_key.pkix_sign(tbs_certificate, private_key)
  end

  defp distinguished_name(common_name) do
    {:rdnSequence,
     [
       [
         {:AttributeTypeAndValue, @common_name_oid,
          {:utf8String, String.to_charlist(common_name)}}
       ]
     ]}
  end

  defp signature_algorithm do
    {:SignatureAlgorithm, @sha256_with_rsa_oid, {:asn1_OPENTYPE, <<5, 0>>}}
  end

  defp subject_public_key_info(public_key) do
    {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_encryption_oid, :NULL}, public_key}
  end

  defp basic_constraints_extension do
    {:Extension, @basic_constraints_oid, false, {:BasicConstraints, false, :asn1_NOVALUE}}
  end

  defp validity do
    now = Clock.system_time(:second)

    {:Validity, certificate_time(now - @validity_seconds),
     certificate_time(now + @validity_seconds)}
  end

  defp certificate_time(unix_seconds) do
    datetime = DateTime.from_unix!(unix_seconds)

    if datetime.year in 1950..2049 do
      {:utcTime, datetime |> Calendar.strftime("%y%m%d%H%M%SZ") |> String.to_charlist()}
    else
      {:generalTime, datetime |> Calendar.strftime("%Y%m%d%H%M%SZ") |> String.to_charlist()}
    end
  end
end
