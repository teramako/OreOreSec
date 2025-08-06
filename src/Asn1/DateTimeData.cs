using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) の時刻ノード
/// </summary>
public class DateTimeData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
    : Asn1Data(tag, rules, encodedValue, headerLength)
{
    public DateTimeOffset DateTime { get; } = tag.TagValue switch
    {
        23 => AsnDecoder.ReadUtcTime(encodedValue.Span, rules, out _, expectedTag: tag),
        24 => AsnDecoder.ReadGeneralizedTime(encodedValue.Span, rules, out _, tag),
        _ => throw new AsnContentException($"Not supported Asn1Tag: {tag}")
    };
    public override string Data => DateTime.ToString("o");

}

