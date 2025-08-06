using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) の文字列ノード
/// </summary>
public class StringData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
    : Asn1Data(tag, rules, encodedValue, headerLength)
{
    private readonly Lazy<string> _data = new(() =>
    {
        return tag.TagValue switch
        {
            12 => AsnDecoder.ReadCharacterString(encodedValue.Span, rules, UniversalTagNumber.UTF8String, out _, tag),
            19 => AsnDecoder.ReadCharacterString(encodedValue.Span, rules, UniversalTagNumber.PrintableString, out _, tag),
            22 => AsnDecoder.ReadCharacterString(encodedValue.Span, rules, UniversalTagNumber.IA5String, out _, tag),
            _ => throw new AsnContentException($"Not supported Asn1Tag: {tag}")
        };
    });
    public override string Data => _data.Value;
}

