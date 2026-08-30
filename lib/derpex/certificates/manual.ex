defmodule Derpex.Certificates.Manual do
  @moduledoc "Loads manual certificates and creates persistent self-signed IP certificates."

  alias Derpex.AtomicFile
  alias Derpex.Clock

  @common_name_oid {2, 5, 4, 3}
  @basic_constraints_oid {2, 5, 29, 19}
  @subject_alt_name_oid {2, 5, 29, 17}
  @rsa_encryption_oid {1, 2, 840, 113_549, 1, 1, 1}
  @sha256_with_rsa_oid {1, 2, 840, 113_549, 1, 1, 11}
  @validity_seconds 365 * 24 * 60 * 60
  @certificate_mode 0o644
  @key_mode 0o600

  @type t :: %__MODULE__{
          hostname: binary(),
          certificate_path: Path.t(),
          key_path: Path.t(),
          certificate_der: binary(),
          private_key: tuple()
        }

  defstruct [:hostname, :certificate_path, :key_path, :certificate_der, :private_key]

  @doc "Loads `<hostname>.crt/.key`, generating them first for a bare IP when absent."
  @spec load_or_create(Path.t(), binary()) :: {:ok, t()} | {:error, term()}
  def load_or_create(directory, hostname) when is_binary(directory) and is_binary(hostname) do
    safe_name = String.replace(hostname, ~r/[^a-zA-Z0-9-.]/, "")
    certificate_path = Path.join(directory, safe_name <> ".crt")
    key_path = Path.join(directory, safe_name <> ".key")

    with :ok <- ensure_files(certificate_path, key_path, hostname),
         {:ok, certificate_der} <- load_certificate(certificate_path),
         {:ok, private_key} <- load_private_key(key_path),
         :ok <- verify_hostname(certificate_der, hostname) do
      {:ok,
       %__MODULE__{
         hostname: hostname,
         certificate_path: certificate_path,
         key_path: key_path,
         certificate_der: certificate_der,
         private_key: private_key
       }}
    end
  end

  @doc "Returns OTP TLS options for the immutable certificate and key."
  @spec tls_options(t()) :: keyword()
  def tls_options(%__MODULE__{} = manual) do
    [
      certs_keys: [
        %{cert: [manual.certificate_der], key: tls_private_key(manual.private_key)}
      ],
      alpn_preferred_protocols: ["http/1.1"]
    ]
  end

  @doc "Returns the DERP-map pin for the leaf certificate."
  @spec raw_pin(t()) :: binary()
  def raw_pin(%__MODULE__{certificate_der: certificate_der}) do
    "sha256-raw:" <> Base.encode16(:crypto.hash(:sha256, certificate_der), case: :lower)
  end

  @doc "Generates an in-memory self-signed certificate and key for a bare IP."
  @spec generate_ip(binary()) :: {:ok, {binary(), tuple()}} | {:error, term()}
  def generate_ip(hostname) when is_binary(hostname) do
    case parse_ip(hostname) do
      {:ok, address} ->
        private_key = :public_key.generate_key({:rsa, 2_048, 65_537})
        public_key = {:RSAPublicKey, elem(private_key, 2), elem(private_key, 3)}
        name = distinguished_name(hostname)
        signature = signature_algorithm()
        serial = :crypto.strong_rand_bytes(16) |> :binary.decode_unsigned()

        tbs_certificate =
          {:OTPTBSCertificate, :v3, serial, signature, name, validity(), name,
           subject_public_key_info(public_key), :asn1_NOVALUE, :asn1_NOVALUE,
           [
             {:Extension, @basic_constraints_oid, false,
              {:BasicConstraints, false, :asn1_NOVALUE}},
             {:Extension, @subject_alt_name_oid, false, [iPAddress: address_bytes(address)]}
           ]}

        {:ok, {:public_key.pkix_sign(tbs_certificate, private_key), private_key}}

      :error ->
        {:error, {:invalid_ip_address, hostname}}
    end
  rescue
    error -> {:error, {:certificate_generation, error}}
  end

  @doc """
  Generates a self-signed certificate for an IP address or a DNS name.

  A relay that obtains its certificate from a certificate authority still has
  to bind its listen socket before the first order can finish, so this supplies
  something for it to bind that names the right identifier.
  """
  @spec generate_self_signed(binary()) :: {:ok, {binary(), tuple()}} | {:error, term()}
  def generate_self_signed(hostname) when is_binary(hostname) do
    case parse_ip(hostname) do
      {:ok, _address} -> generate_ip(hostname)
      :error -> generate_dns(hostname)
    end
  end

  defp generate_dns(""), do: {:error, {:invalid_hostname, ""}}

  defp generate_dns(hostname) do
    private_key = :public_key.generate_key({:rsa, 2_048, 65_537})
    public_key = {:RSAPublicKey, elem(private_key, 2), elem(private_key, 3)}
    name = distinguished_name(hostname)

    tbs_certificate =
      {:OTPTBSCertificate, :v3, serial(), signature_algorithm(), name, validity(), name,
       subject_public_key_info(public_key), :asn1_NOVALUE, :asn1_NOVALUE,
       [
         {:Extension, @basic_constraints_oid, false, {:BasicConstraints, false, :asn1_NOVALUE}},
         {:Extension, @subject_alt_name_oid, false, [dNSName: String.to_charlist(hostname)]}
       ]}

    {:ok, {:public_key.pkix_sign(tbs_certificate, private_key), private_key}}
  rescue
    error -> {:error, {:certificate_generation, error}}
  end

  defp serial, do: :crypto.strong_rand_bytes(16) |> :binary.decode_unsigned()

  @doc "Verifies that a DER certificate is valid for a DNS name or IP SAN."
  @spec verify_certificate(binary(), binary()) :: :ok | {:error, term()}
  def verify_certificate(certificate_der, hostname),
    do: verify_hostname(certificate_der, hostname)

  defp ensure_files(certificate_path, key_path, hostname) do
    case {File.exists?(certificate_path), File.exists?(key_path)} do
      {true, true} ->
        :ok

      {false, false} ->
        case parse_ip(hostname) do
          {:ok, _address} -> create_self_signed(certificate_path, key_path, hostname)
          :error -> {:error, {:certificate_files_not_found, hostname}}
        end

      _incomplete ->
        {:error, {:incomplete_certificate_pair, hostname}}
    end
  end

  defp create_self_signed(certificate_path, key_path, hostname) do
    with {:ok, {certificate_der, private_key}} <- generate_ip(hostname),
         certificate_pem =
           :public_key.pem_encode([{:Certificate, certificate_der, :not_encrypted}]),
         key_pem = encode_private_key(private_key),
         :ok <- AtomicFile.write(certificate_path, certificate_pem, mode: @certificate_mode) do
      AtomicFile.write(key_path, key_pem, mode: @key_mode)
    end
  rescue
    error -> {:error, {:certificate_generation, error}}
  end

  defp encode_private_key(private_key) do
    private_key
    |> then(&:public_key.pem_entry_encode(:RSAPrivateKey, &1))
    |> List.wrap()
    |> :public_key.pem_encode()
  end

  defp tls_private_key(private_key) do
    type = elem(private_key, 0)
    {type, :public_key.der_encode(type, private_key)}
  end

  defp load_certificate(path) do
    case path |> File.read!() |> :public_key.pem_decode() do
      [{:Certificate, certificate_der, :not_encrypted} | _rest] ->
        {:ok, certificate_der}

      _invalid ->
        {:error, {:invalid_certificate, path}}
    end
  rescue
    error -> {:error, {:certificate_read, error}}
  end

  defp load_private_key(path) do
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
      nil -> {:error, {:invalid_private_key, path}}
      entry -> {:ok, :public_key.pem_entry_decode(entry)}
    end
  rescue
    error -> {:error, {:private_key_read, error}}
  end

  defp verify_hostname(certificate_der, hostname) do
    certificate = :public_key.pkix_decode_cert(certificate_der, :otp)

    reference =
      case parse_ip(hostname) do
        {:ok, address} -> {:ip, address}
        :error -> {:dns_id, String.to_charlist(hostname)}
      end

    if :public_key.pkix_verify_hostname(certificate, [reference]) do
      :ok
    else
      {:error, {:certificate_hostname_mismatch, hostname}}
    end
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

  defp validity do
    now = Clock.system_time(:second)
    {:Validity, certificate_time(now - 60), certificate_time(now + @validity_seconds)}
  end

  defp certificate_time(unix_seconds) do
    datetime = DateTime.from_unix!(unix_seconds)

    if datetime.year in 1950..2049 do
      {:utcTime, datetime |> Calendar.strftime("%y%m%d%H%M%SZ") |> String.to_charlist()}
    else
      {:generalTime, datetime |> Calendar.strftime("%Y%m%d%H%M%SZ") |> String.to_charlist()}
    end
  end

  defp parse_ip(hostname) do
    case :inet.parse_address(String.to_charlist(hostname)) do
      {:ok, address} -> {:ok, address}
      {:error, _reason} -> :error
    end
  end

  defp address_bytes({a, b, c, d}), do: <<a, b, c, d>>

  defp address_bytes({a, b, c, d, e, f, g, h}) do
    <<a::16, b::16, c::16, d::16, e::16, f::16, g::16, h::16>>
  end
end
