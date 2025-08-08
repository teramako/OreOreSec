using System.Formats.Asn1;
using System.Management.Automation.Host;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography;
using MT.Asn1;
using MT.PowerShell;

namespace MT.Sec;

public class PrivateKey
{
    /// <summary>
    /// Get <see cref="AsymmetricAlgorithm"/> from Encrypted PKCS8 private key data
    /// </summary>
    public static AsymmetricAlgorithm GetEncryptedPkcs8PrivateKey(ReadOnlySpan<byte> source,
                                                                  KeyAlgorithm algorithm,
                                                                  SecureString password)
    {
        AsymmetricAlgorithm key = CreateKey(algorithm);
        key.ImportEncryptedPkcs8PrivateKey(SecureStringToString(password), source, out _);
        return key;
    }

    /// <inheritdoc cref="GetEncryptedPkcs8PrivateKey(ReadOnlySpan{byte}, KeyAlgorithm, SecureString)"/>
    public static AsymmetricAlgorithm GetEncryptedPkcs8PrivateKey(Asn1Data asn1Data,
                                                                  KeyAlgorithm? algorithm,
                                                                  SecureString? password,
                                                                  PSHost host)
    {
        if (algorithm is null or KeyAlgorithm.Unknown)
        {
            algorithm = UI.ChoicePrompt<KeyAlgorithm>(host.UI, "Choose Key Algorithm");
        }
        password ??= UI.PasswordPrompt(host.UI,
                                       "Passphrase",
                                       "Encrypted Private Key",
                                       "Passphrase is required for extracting private key");
        return GetEncryptedPkcs8PrivateKey(asn1Data.RawData.Span, algorithm.Value, password);
    }

    private static AsymmetricAlgorithm CreateKey(KeyAlgorithm algorithm)
    {
        return algorithm switch
        {
            KeyAlgorithm.DSA => DSA.Create(),
            KeyAlgorithm.RSA => RSA.Create(),
            KeyAlgorithm.ECDsa => ECDsa.Create(),
            _ => throw new ArgumentException($"Invalid KeyAlgorithm: {algorithm}", nameof(algorithm))
        };
    }

    private static RSA GetPkcs1RSA(ReadOnlySpan<byte> source)
    {
        var rsa = RSA.Create();
        rsa.ImportRSAPrivateKey(source, out _);
        return rsa;
    }

    private static ECDsa GetPkcs1ECDsa(ReadOnlySpan<byte> source)
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportECPrivateKey(source, out _);
        return ecdsa;
    }

    private static DSA GetPkcs1DSA(ReadOnlySpan<byte> source)
    {
        throw new NotSupportedException("DSA PKCS1 is not supported");
    }

    private static ReadOnlySpan<char> SecureStringToString(SecureString secureString)
    {
        return Marshal.PtrToStringUni(Marshal.SecureStringToBSTR(secureString));
    }

    /// <summary>
    /// Get <see cref="AsymmetricAlgorithm"/> from (not encrypted) PKCS8 private key data
    /// </summary>
    public static AsymmetricAlgorithm GetPkcs8PrivateKey(ReadOnlySpan<byte> source,
                                                         KeyAlgorithm algorithm)
    {
        AsymmetricAlgorithm key = CreateKey(algorithm);
        key.ImportPkcs8PrivateKey(source, out _);
        return key;
    }

    /// <inheritdoc cref="GetPkcs8PrivateKey(ReadOnlySpan{byte}, KeyAlgorithm)"/>
    public static AsymmetricAlgorithm GetPkcs8PrivateKey(Asn1Data asn1Data,
                                                         KeyAlgorithm? algorithm,
                                                         PSHost host)
    {
        if (algorithm is null or KeyAlgorithm.Unknown)
        {
            algorithm = UI.ChoicePrompt<KeyAlgorithm>(host.UI, "Choose Key Algorithm");
        }
        return GetPkcs8PrivateKey(asn1Data.RawData.Span, algorithm.Value);
    }

    /// <summary>
    /// Inspect ASN.1 data and returns <see cref="PrivateKeyType"/> and <see cref="KeyAlgorithm"/>
    /// </summary>
    /// <remarks>
    /// <code>
    /// Pkcs8 Private Key:
    ///   Constructed SequenceOf
    ///     Integer                Version
    ///     Constructed SequenceOf
    ///       ObjectIdentifier     { 'ECC' | 'RSA' | 'DSA' }
    ///       ObjectIdentifier     Optional
    ///     OctetString            [...OctetString]
    ///
    /// Pkcs8 Encrypted Private Key:
    ///   Constructed SequenceOf
    ///     Constructed SequenceOf     EncryptionAlgorithmIdentifier
    ///     OctetString
    /// </code>
    /// </remarks>
    public static (PrivateKeyType Type, KeyAlgorithm Algorithm) GetPrivateKeyType(Asn1Data asn1Data)
    {
        if (asn1Data is not ConstructedData root)
        {
            throw new ArgumentException("ASN.1 Data must be constructed data", nameof(asn1Data));
        }
        if (root.Children.Length == 2
            && root.Children[0] is ConstructedData c1
            && root.Children[1].Tag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString)
            && c1.Children[0].Tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))
        {
            return (PrivateKeyType.EncryptedPkcs8, KeyAlgorithm.Unknown);
        }
        if (root.Children.Length == 3
            && root.Children[0].Tag.HasSameClassAndValue(Asn1Tag.Integer)
            && root.Children[1] is ConstructedData c2
            && root.Children[2].Tag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString)
            && c2.Children[0].Tag.HasSameClassAndValue(Asn1Tag.ObjectIdentifier))

        {
            return (PrivateKeyType.Pkcs8, GetPkcs8KeyAlgorithm(root));
        }
        var keyAlgorithm = GetPkcs1KeyAlgorithm(root);
        if (keyAlgorithm == KeyAlgorithm.Unknown)
        {
            throw new InvalidDataException("ASN.1 Data is not private key or unknown key algorithm");
        }
        return (PrivateKeyType.Pkcs1, keyAlgorithm);
    }

    /// <remarks>
    /// <code>
    /// ECDsa:
    ///   Constructed SequenceOf
    ///     Integer                       Version
    ///     OctetString
    ///     Constructed ContextSpecific-0
    ///       ObjectIdentifier
    ///     Constructed ContextSpecific-1
    ///       BitString
    ///
    /// RSA:
    ///   Constructed SequenceOf
    ///     Integer              Version
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    ///
    /// DSA:
    ///   Constructed SequenceOf
    ///     Integer              Version
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    ///     Integer
    /// </code>
    /// </remarks>
    private static KeyAlgorithm GetPkcs1KeyAlgorithm(ConstructedData asn1Root)
    {
        return asn1Root.Children.Length switch
        {
            4 when asn1Root.Children[0].Tag.HasSameClassAndValue(Asn1Tag.Integer)
                && asn1Root.Children[1].Tag.HasSameClassAndValue(Asn1Tag.PrimitiveOctetString)
                && asn1Root.Children[2].Tag is { TagClass: TagClass.ContextSpecific, TagValue: 0 }
                && asn1Root.Children[3].Tag is { TagClass: TagClass.ContextSpecific, TagValue: 1 }
                => KeyAlgorithm.ECDsa,
            6 when asn1Root.Children.All(static asn1val => asn1val.Tag.HasSameClassAndValue(Asn1Tag.Integer))
                => KeyAlgorithm.DSA,
            9 when asn1Root.Children.All(static asn1val => asn1val.Tag.HasSameClassAndValue(Asn1Tag.Integer))
                => KeyAlgorithm.RSA,
            _ => KeyAlgorithm.Unknown
        };
    }

    /// <exception cref="ArgumentException"/>
    private static KeyAlgorithm GetPkcs8KeyAlgorithm(ConstructedData asn1Root)
    {
        if (asn1Root.Children.Length > 1
            && asn1Root.Children[1] is ConstructedData algorithmIdentifier)
        {
            if (algorithmIdentifier.Children.Length > 0
                && algorithmIdentifier.Children[0] is OidData oidData)
            {
                return oidData.Oid.Value switch
                {
                    "1.2.840.10045.2.1" => KeyAlgorithm.ECDsa,
                    "1.2.840.113549.1.1.1" => KeyAlgorithm.RSA,
                    "1.2.840.10040.4.1" => KeyAlgorithm.DSA,
                    _ => KeyAlgorithm.Unknown
                };
            }
        }
        throw new ArgumentException("ASN.1 data is invalid PKCS#8 data structure", nameof(asn1Root));
    }

    public static PrivateKey Decode(string pemString)
    {
        var pem = PemData.Parse(pemString)
                         .FirstOrDefault(static pem => pem.Label.EndsWith("PRIVATE KEY", StringComparison.Ordinal));
        ArgumentNullException.ThrowIfNull(pem, nameof(pemString));

        return Decode(pem.GetRawData());
    }

    public static PrivateKey Decode(byte[] source)
    {
        var asn1Data = Asn1Serializer.Deserialize(source)[0];
        return Decode(asn1Data);
    }

    public static PrivateKey Decode(Asn1Data asn1Data)
    {
        if (asn1Data is not ConstructedData constructedData)
        {
            throw new InvalidCastException("ASN.1 Data must be constructed data");
        }
        var typeAndAlgorithm = GetPrivateKeyType(constructedData);

        return new(constructedData, typeAndAlgorithm.Type, typeAndAlgorithm.Algorithm);
    }

    public PrivateKey(ConstructedData data, PrivateKeyType pkType, KeyAlgorithm algorithm)
    {
        Data = data;
        Type = pkType;
        Algorithm = algorithm;
    }

    public ConstructedData Data { get; }
    public PrivateKeyType Type { get; }
    public KeyAlgorithm Algorithm { get; }

    /// <summary>
    /// Get PrivateKey instance
    /// </summary>
    /// <remarks>
    /// Assumes use only from PowerShell
    /// </remarks>
    /// <param name="host"></param>
    /// <param name="password">Used only when Encrypted PKCS8, and input prompt will shown when value is null</param>
    /// <param name="algorithm">Used only when Encrypted PKCS8, and input prompt will shown when value is null</param>
    public AsymmetricAlgorithm GetPrivateKey(PSHost host,
                                             SecureString? password = null,
                                             KeyAlgorithm? algorithm = null)
    {
        switch (Type)
        {
            case PrivateKeyType.EncryptedPkcs8:
                return GetEncryptedPkcs8PrivateKey(Data, algorithm, password, host);
            case PrivateKeyType.Pkcs8:
                return GetPkcs8PrivateKey(Data, Algorithm, host);
            case PrivateKeyType.Pkcs1:
                return Algorithm switch
                {
                    KeyAlgorithm.RSA => GetPkcs1RSA(Data.RawData.Span),
                    KeyAlgorithm.ECDsa => GetPkcs1ECDsa(Data.RawData.Span),
                    KeyAlgorithm.DSA => GetPkcs1DSA(Data.RawData.Span),
                    _ => throw new InvalidDataException($"Not supported Key Algorithm: {Algorithm}"),
                };
            default:
                throw new InvalidDataException($"Data Type is unknown: {Type}");
        }
    }
}
