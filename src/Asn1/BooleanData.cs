using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) の真偽値ノード
/// </summary>
public class BooleanData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
    : Asn1Data(tag, rules, encodedValue, headerLength)
{
    private readonly bool _data = AsnDecoder.ReadBoolean(encodedValue.Span, rules, out _, tag);
    public override string Data => $"{_data}";
}

