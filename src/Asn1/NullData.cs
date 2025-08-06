using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) の NULL ノード
/// </summary>
public class NullData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
    : Asn1Data(tag, rules, encodedValue, headerLength)
{
    public override string Data => string.Empty;
    public override string ToString()
    {
        return $"{Tag}";
    }
}

