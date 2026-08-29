defmodule Derpex.Test.CertificateAuthority do
  @moduledoc """
  A throwaway certificate authority for tests that need a real chain.

  A self-signed leaf is not a chain: OTP refuses one as `selfsigned_peer` even
  when the same certificate is offered as a trust anchor, and
  `Derpex.HTTPClient` no longer lets a caller wave that away with a permissive
  `verify_fun`. A test that wants a TLS peer its client will actually accept
  needs a root to pin and a leaf signed by it, which is what this builds.
  """

  @common_name_oid {2, 5, 4, 3}
  @basic_constraints_oid {2, 5, 29, 19}
  @key_usage_oid {2, 5, 29, 15}
  @subject_alt_name_oid {2, 5, 29, 17}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @sha256_with_rsa_oid {1, 2, 840, 113_549, 1, 1, 11}

  @type t :: %{certificate: binary(), private_key: tuple()}

  @doc "Returns a new root certificate and its key."
  @spec new(binary()) :: t()
  def new(common_name \\ "derpex test root") do
    key = :public_key.generate_key({:rsa, 2_048, 65_537})
    name = distinguished_name(common_name)

    tbs =
      {:OTPTBSCertificate, :v3, 1, signature_algorithm(), name, validity(), name,
       public_key_info(key), :asn1_NOVALUE, :asn1_NOVALUE,
       [
         {:Extension, @basic_constraints_oid, true, {:BasicConstraints, true, :asn1_NOVALUE}},
         {:Extension, @key_usage_oid, true, [:keyCertSign]}
       ]}

    %{certificate: :public_key.pkix_sign(tbs, key), private_key: key}
  end

  @doc "Returns a leaf for one IP address, signed by `authority`."
  @spec issue_ip(t(), binary()) :: {binary(), tuple()}
  def issue_ip(authority, address) do
    {:ok, parsed} = :inet.parse_address(String.to_charlist(address))
    issue(authority, address, {:iPAddress, address_bytes(parsed)})
  end

  @doc "Returns a leaf for one DNS name, signed by `authority`."
  @spec issue_dns(t(), binary()) :: {binary(), tuple()}
  def issue_dns(authority, hostname) do
    issue(authority, hostname, {:dNSName, String.to_charlist(hostname)})
  end

  defp issue(authority, common_name, general_name) do
    key = :public_key.generate_key({:rsa, 2_048, 65_537})

    tbs =
      {:OTPTBSCertificate, :v3, serial(), signature_algorithm(),
       issuer_name(authority.certificate), validity(), distinguished_name(common_name),
       public_key_info(key), :asn1_NOVALUE, :asn1_NOVALUE,
       [
         {:Extension, @basic_constraints_oid, false, {:BasicConstraints, false, :asn1_NOVALUE}},
         {:Extension, @key_usage_oid, false, [:digitalSignature, :keyEncipherment]},
         {:Extension, @subject_alt_name_oid, false, [general_name]}
       ]}

    {:public_key.pkix_sign(tbs, authority.private_key), key}
  end

  defp issuer_name(certificate_der) do
    certificate_der |> :public_key.pkix_decode_cert(:otp) |> elem(1) |> elem(6)
  end

  defp public_key_info(key) do
    {:OTPSubjectPublicKeyInfo, {:PublicKeyAlgorithm, @rsa_encryption_oid, :NULL},
     {:RSAPublicKey, elem(key, 2), elem(key, 3)}}
  end

  defp signature_algorithm do
    {:SignatureAlgorithm, @sha256_with_rsa_oid, {:asn1_OPENTYPE, <<5, 0>>}}
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

  defp validity do
    now = System.system_time(:second)
    {:Validity, certificate_time(now - 3_600), certificate_time(now + 24 * 3_600)}
  end

  defp certificate_time(unix_seconds) do
    {:utcTime,
     unix_seconds
     |> DateTime.from_unix!()
     |> Calendar.strftime("%y%m%d%H%M%SZ")
     |> String.to_charlist()}
  end

  defp serial, do: :crypto.strong_rand_bytes(8) |> :binary.decode_unsigned()

  defp address_bytes({a, b, c, d}), do: <<a, b, c, d>>

  defp address_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end
end
