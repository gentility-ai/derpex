# This module builds the certificate request cmd/derper's ipcert.go creates with
# x509.CreateCertificateRequest.
# Copyright (c) 2026 Tailscale Inc & contributors.
# SPDX-License-Identifier: BSD-3-Clause

defmodule Derpex.ACME.CSR do
  @moduledoc """
  Builds a PKCS#10 certificate request carrying exactly one subject alternative
  name, with a fresh P-256 key.

  Upstream orders a certificate for one identifier at a time and puts nothing in
  the subject, so the request has an empty distinguished name and a single SAN —
  one IP address, or one DNS name. A CA is entitled to refuse anything else, and
  the fake CA the tests run against asserts the count.

  OTP's `PKCS-10` ASN.1 module encodes the request directly. The one non-obvious
  detail is that the `extensionRequest` attribute's values are `SET OF ANY`, so
  the encoded extensions have to be wrapped as `{:asn1_OPENTYPE, der}`.
  """

  @curve {:namedCurve, :secp256r1}
  # `EcpkParameters` encodes the curve by object identifier; the `secp256r1`
  # atom is only accepted where OTP resolves names for us.
  @curve_parameters {:namedCurve, {1, 2, 840, 10_045, 3, 1, 7}}
  @ec_public_key_oid {1, 2, 840, 10_045, 2, 1}
  @ecdsa_with_sha256_oid {1, 2, 840, 10_045, 4, 3, 2}
  @extension_request_oid {1, 2, 840, 113_549, 1, 9, 14}
  @subject_alt_name_oid {2, 5, 29, 17}

  @type subject :: {:ip, binary()} | {:dns, binary()}

  @doc "Returns a DER certificate request for one identifier and the key it binds."
  @spec generate(subject()) :: {:ok, {binary(), tuple()}} | {:error, term()}
  def generate(identifier) do
    with {:ok, general_name} <- general_name(identifier) do
      private_key = :public_key.generate_key(@curve)
      info = request_info(private_key, general_name)
      info_der = :public_key.der_encode(:CertificationRequestInfo, info)

      request =
        {:CertificationRequest, info,
         {:CertificationRequest_signatureAlgorithm, @ecdsa_with_sha256_oid, :asn1_NOVALUE},
         :public_key.sign(info_der, :sha256, private_key)}

      {:ok, {:public_key.der_encode(:CertificationRequest, request), private_key}}
    end
  rescue
    error -> {:error, {:certificate_request, error}}
  end

  defp request_info(private_key, general_name) do
    subject_alt_name = :public_key.der_encode(:SubjectAltName, [general_name])

    extensions =
      :public_key.der_encode(:Extensions, [
        {:Extension, @subject_alt_name_oid, false, subject_alt_name}
      ])

    attributes = [
      {:Attribute, @extension_request_oid, [{:asn1_OPENTYPE, extensions}]}
    ]

    {:CertificationRequestInfo, :v1, {:rdnSequence, []},
     subject_public_key_info(private_key, elem(private_key, 4)), attributes}
  end

  defp subject_public_key_info(_private_key, public_point) do
    parameters = :public_key.der_encode(:EcpkParameters, @curve_parameters)

    {:CertificationRequestInfo_subjectPKInfo,
     {:CertificationRequestInfo_subjectPKInfo_algorithm, @ec_public_key_oid,
      {:asn1_OPENTYPE, parameters}}, public_point}
  end

  defp general_name({:ip, address}) do
    case :inet.parse_address(String.to_charlist(address)) do
      {:ok, parsed} -> {:ok, {:iPAddress, address_bytes(parsed)}}
      {:error, _reason} -> {:error, {:invalid_ip_address, address}}
    end
  end

  defp general_name({:dns, name}) when byte_size(name) > 0 do
    {:ok, {:dNSName, String.to_charlist(name)}}
  end

  defp general_name(identifier), do: {:error, {:invalid_identifier, identifier}}

  defp address_bytes({a, b, c, d}), do: <<a, b, c, d>>

  defp address_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end
end
