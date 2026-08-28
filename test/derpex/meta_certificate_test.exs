defmodule Derpex.MetaCertificateTest do
  use ExUnit.Case, async: true

  alias Derpex.MetaCertificate

  test "encodes the node key and protocol version in one basic-constraints certificate" do
    server_public_key = :crypto.strong_rand_bytes(32)
    der = MetaCertificate.generate(server_public_key)

    assert {:OTPCertificate,
            {:OTPTBSCertificate, :v3, 2, _signature, _issuer, _validity,
             {:rdnSequence,
              [
                [
                  {:AttributeTypeAndValue, {2, 5, 4, 3}, {:utf8String, common_name}}
                ]
              ]}, _subject_public_key, :asn1_NOVALUE, :asn1_NOVALUE,
             [{:Extension, {2, 5, 29, 19}, false, _constraints}]}, _algorithm, _value} =
             :public_key.pkix_decode_cert(der, :otp)

    assert common_name ==
             "derpkey" <> Base.encode16(server_public_key, case: :lower)
  end
end
