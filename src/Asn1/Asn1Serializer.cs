using System.Formats.Asn1;

namespace MT.Asn1;

public static class Asn1Serializer
{
    /// <summary>
    /// Abstract Syntax Notation One (ASN.1) のバイナリデータを読む
    /// </summary>
    public static Asn1Data[] Deserialize(ReadOnlyMemory<byte> data,
                                         AsnEncodingRules ruleSet = AsnEncodingRules.DER)
    {
        return Read(new AsnReader(data, ruleSet));
    }

    private static Asn1Data[] Read(AsnReader reader)
    {
        List<Asn1Data> results = [];
        while (reader.HasData)
        {
            Asn1Tag tag = reader.PeekTag();
            ReadOnlyMemory<byte> content = reader.PeekContentBytes();
            ReadOnlyMemory<byte> encodedValue = reader.ReadEncodedValue();
            int headerLength = encodedValue.Length - content.Length;
            Asn1Data? data = null;
            try
            {
                data = tag.IsConstructed
                    ? new ConstructedData(tag, reader.RuleSet, encodedValue, headerLength)
                    : tag.TagValue switch
                    {
                        // BOOLEAN
                        1 => new BooleanData(tag, reader.RuleSet, encodedValue, headerLength),
                        // INTEGER, BitString, OctetString
                        2 or 3 or 4 => new ByteData(tag, reader.RuleSet, encodedValue, headerLength),
                        // null
                        5 => new NullData(tag, reader.RuleSet, encodedValue, headerLength),
                        // Object Identifier
                        6 => new OidData(tag, reader.RuleSet, encodedValue, headerLength),
                        // UTF8String, PrintableString, IA5String
                        12 or 19 or 22 => new StringData(tag, reader.RuleSet, encodedValue, headerLength),
                        // Sequence, Set
                        16 or 17 => new ConstructedData(tag, reader.RuleSet, encodedValue, headerLength),
                        // UTCTime, GeneralizedTime
                        23 or 24 => new DateTimeData(tag, reader.RuleSet, encodedValue, headerLength),
                        // Others
                        _ => new ByteData(tag, reader.RuleSet, encodedValue, headerLength),
                    };
            }
            catch (Exception e)
            {
                Console.Error.WriteLine(e);
            }
            if (data is not null)
            {
                results.Add(data);
            }
        }
        return [.. results];
    }
}
