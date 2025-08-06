using System.Security.Cryptography;

namespace MT.Sec;

public class PemData(string label, string base64data)
{
    public PemData(string data, Range labelRange, Range base64Range)
        : this(data[labelRange], data[base64Range])
    {
    }
    public string Label => label;
    public string Base64Data => base64data;

    public override string ToString()
    {
        return $"""
               -----BEGIN {Label}-----
               {Base64Data}
               -----END {Label}-----
               """;
    }

    public byte[] GetRawData()
    {
        return Convert.FromBase64String(Base64Data);
    }

    /// <summary>
    /// Parse PEM data and returns <see cref="PemData"/>s
    /// </summary>
    /// <exception cref="ArgumentException">No PEM encoded data found.</exception>
    public static PemData[] Parse(string pemData)
    {
        var results = new List<PemData>();
        while (!string.IsNullOrWhiteSpace(pemData))
        {
            var fields = PemEncoding.Find(pemData);
            var start = fields.Location.Start.Value;
            results.Add(new(pemData[fields.Location],
                            new Range(fields.Label.Start.Value - start, fields.Label.End.Value - start),
                            new Range(fields.Base64Data.Start.Value - start, fields.Base64Data.End.Value - start)));
            pemData = pemData[fields.Location.End..];
        }
        return [.. results];
    }
}
