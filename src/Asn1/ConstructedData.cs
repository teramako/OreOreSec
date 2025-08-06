using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1) の構造化データのノード
/// </summary>
public class ConstructedData(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
    : Asn1Data(tag, rules, encodedValue, headerLength)
{
    private readonly Lazy<Asn1Data[]> _children = new(() => Asn1Serializer.Deserialize(encodedValue[headerLength..], rules));
    public Asn1Data[] Children => _children.Value;
    public override string Data { get; } = string.Empty;
    public override string ToString()
    {
        return $"{Tag}";
    }
}

