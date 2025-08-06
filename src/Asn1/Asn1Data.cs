using System.Formats.Asn1;

namespace MT.Asn1;

/// <summary>
/// Abstract Syntax Notation One (ASN.1)
/// <para>
/// ASN.1 データをデシリアライズした結果を入れる抽象クラス。
/// Abstract class to contain the result of deserializing the ASN.1 data
/// </para>
/// </summary>
public abstract class Asn1Data(Asn1Tag tag, AsnEncodingRules rules, ReadOnlyMemory<byte> encodedValue, int headerLength)
{
    public Asn1Tag Tag { get; } = tag;
    public AsnEncodingRules Rules { get; } = rules;
    /// <summary>
    /// For PowerShell. Property containing stringified information about a node.
    /// </summary>
    public abstract string Data { get; }
    public int HeaderLength { get; } = headerLength;
    public int ContentsLength { get; } = encodedValue.Length - headerLength;
    public ReadOnlyMemory<byte> RawData { get; } = encodedValue;
    public ReadOnlyMemory<byte> Contents => RawData[HeaderLength..];
    public string ToBase64String(bool insertLineBreaks = false)
    {
        return Convert.ToBase64String(Contents.Span,
                                      insertLineBreaks ? Base64FormattingOptions.InsertLineBreaks : Base64FormattingOptions.None);
    }
    public override string ToString()
    {
        return $"{Tag}: {Data}";
    }
}
