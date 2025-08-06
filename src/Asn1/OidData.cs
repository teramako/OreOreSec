using System.Formats.Asn1;
using System.Security.Cryptography;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) の OID ノード
/// </summary>
public class OidData : Asn1Data
{
    public OidData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
        : base(tag, rules, encodedValue, headerLength)
    {
        string oidValue = AsnDecoder.ReadObjectIdentifier(encodedValue.Span, rules, out _, tag);
        Oid = new Oid(oidValue);
    }
    public Oid Oid { get; }
    public override string Data => string.IsNullOrEmpty(Oid.FriendlyName)
                                   ? $"{Oid.Value}"
                                   : $"{Oid.FriendlyName} ({Oid.Value})";
}

