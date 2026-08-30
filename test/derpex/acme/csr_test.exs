defmodule Derpex.ACME.CSRTest do
  use ExUnit.Case, async: true

  alias Derpex.ACME.CSR

  test "requests exactly one IP subject alternative name" do
    assert {:ok, {der, private_key}} = CSR.generate({:ip, "203.0.113.7"})
    assert subject_alt_names(der) == [{:iPAddress, <<203, 0, 113, 7>>}]
    assert verifies?(der, private_key)
  end

  test "requests exactly one IPv6 subject alternative name" do
    assert {:ok, {der, _private_key}} = CSR.generate({:ip, "2001:db8::7"})

    assert subject_alt_names(der) == [
             {:iPAddress, <<0x2001::16, 0xDB8::16, 0::16, 0::16, 0::16, 0::16, 0::16, 7::16>>}
           ]
  end

  test "requests exactly one DNS subject alternative name" do
    assert {:ok, {der, private_key}} = CSR.generate({:dns, "derp.example.com"})
    assert subject_alt_names(der) == [{:dNSName, ~c"derp.example.com"}]
    assert verifies?(der, private_key)
  end

  test "refuses an identifier it cannot put in a single SAN" do
    assert {:error, {:invalid_ip_address, "not-an-ip"}} = CSR.generate({:ip, "not-an-ip"})
    assert {:error, {:invalid_identifier, _}} = CSR.generate({:dns, ""})
    assert {:error, {:invalid_identifier, _}} = CSR.generate({:email, "a@b.c"})
  end

  test "binds a fresh key to every request" do
    assert {:ok, {_first, first_key}} = CSR.generate({:ip, "203.0.113.7"})
    assert {:ok, {_second, second_key}} = CSR.generate({:ip, "203.0.113.7"})
    refute elem(first_key, 2) == elem(second_key, 2)
  end

  defp subject_alt_names(der) do
    {:CertificationRequest, info, _algorithm, _signature} =
      :public_key.der_decode(:CertificationRequest, der)

    {:CertificationRequestInfo, :v1, {:rdnSequence, []}, _public_key, attributes} = info

    for {:Attribute, {1, 2, 840, 113_549, 1, 9, 14}, values} <- attributes,
        {:asn1_OPENTYPE, extensions_der} <- values,
        {:Extension, {2, 5, 29, 17}, _critical, san_der} <-
          :public_key.der_decode(:Extensions, extensions_der),
        name <- :public_key.der_decode(:SubjectAltName, san_der) do
      name
    end
  end

  defp verifies?(der, private_key) do
    {:CertificationRequest, info, _algorithm, signature} =
      :public_key.der_decode(:CertificationRequest, der)

    :public_key.verify(
      :public_key.der_encode(:CertificationRequestInfo, info),
      :sha256,
      signature,
      {{:ECPoint, elem(private_key, 4)}, {:namedCurve, :secp256r1}}
    )
  end
end
