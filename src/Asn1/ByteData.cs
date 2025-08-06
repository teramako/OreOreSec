using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) のバイナリ値ノード
/// </summary>
public class ByteData : Asn1Data
{
    public ByteData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
        : base(tag, rules, encodedValue, headerLength)
    {
        ReadOnlySpan<byte> contents = tag.TagClass == TagClass.Universal
            ? tag.TagValue switch
            {
                2 => AsnDecoder.ReadIntegerBytes(encodedValue.Span, rules, out _, tag),
                3 => (ReadOnlySpan<byte>)AsnDecoder.ReadBitString(encodedValue.Span, rules, out _, out _, tag),
                4 => (ReadOnlySpan<byte>)AsnDecoder.ReadOctetString(encodedValue.Span, rules, out _, tag),
                _ => throw new AsnContentException($"Not supported Asn1Tag: {tag}"),
            }
            : (ReadOnlySpan<byte>)AsnDecoder.ReadOctetString(encodedValue.Span, rules, out _, tag);
        _data = encodedValue.Span.Overlaps(contents, out int offset)
            ? encodedValue.Slice(offset, contents.Length)
            : contents.ToArray();
        _stringData = new(() =>
        {
            System.Text.StringBuilder sb = new(_data.Length * 2);
            for (int i = 0; i < _data.Length; i++)
            {
                _ = sb.AppendFormat(null, "{0:X2}", _data.Span[i]);
            }
            return sb.ToString();
        });
    }
    private readonly ReadOnlyMemory<byte> _data;
    private readonly Lazy<string> _stringData;
    public override string Data => _stringData.Value;
    public Asn1Data[] Inspect(AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        return Asn1Serializer.Deserialize(Contents, ruleSet);
    }
}

