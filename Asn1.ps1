<#
Functions for Abstract Syntax Notation One (ASN.1)
#>

function ConvertTo-Asn1
{
    <#
    .SYNOPSIS
    バイナリデータを ASN.1 オブジェクトへ変換する

    .PARAMETER PEMs
    PEM 形式の文字列を変換した `PemData` オブジェクト

    .PARAMETER Data
    byte データ
    #>
    [CmdletBinding()]
    [OutputType([MT.Asn1.Asn1Data])]
    param(
        [Parameter(ParameterSetName = "PEM", Mandatory, ValueFromPipeline, Position = 0)]
        [MT.Sec.PemData[]] $PEMs
        ,
        [Parameter(ParameterSetName = "Binary", Mandatory, ValueFromPipeline, Position = 0)]
        [byte[]] $Data
        ,
        [Parameter()]
        [System.Formats.Asn1.AsnEncodingRules] $Type = [System.Formats.Asn1.AsnEncodingRules]::DER
    )

    $pipelineInput = $input
    switch ($PSCmdlet.ParameterSetName)
    {
        "PEM" {
            if ($pipelineInput.Count -gt 0)
            {
                $PEMs = [MT.Sec.PemData[]] $pipelineInput
            }
            foreach ($pemData in $PEMs)
            {
                Write-Verbose "Read from PEM data labeled: $($pemData.Label)";
                Write-Output ([MT.Asn1.Asn1Serializer]::Deserialize($pemData.GetRawData(), $Type))
            }
        }
        "Binary" {
            if ($pipelineInput.Count -gt 0)
            {
                $Data = [byte[]] $pipelineInput;
            }
            Write-Verbose "Read binary data: byte[$($Data.Length)]";
            Write-Output ([MT.Asn1.Asn1Serializer]::Deserialize($Data, $Type))
        }
    }
}

function Read-Asn1
{
    <#
    .SYNOPSIS
    ファイルから ASN1 を読む

    .PARAMETER Path
    ファイルパス

    .PARAMETER Type
    `PEM` => PEM形式のテキストファイルとして読む
    `Binary` => バイナリデータとして読む
    #>
    [CmdletBinding()]
    [OutputType([MT.Asn1.Asn1Data])]
    param(
        [Parameter(ParameterSetName = "Path", Mandatory, Position = 0)]
        [string] $Path
        ,
        [Parameter()]
        [ValidateSet("PEM", "Binary")]
        [string] $Type = "PEM"
    )

    Write-Verbose "Read as $Type";
    switch ($Type)
    {
        'PEM' {
            Read-PEM -Path $Path | ConvertTo-Asn1
        }
        'Binary' {
            $file = Get-Item -LiteralPath $Path
            ConvertTo-Asn1 -Data ([System.IO.File]::ReadAllBytes($file))
        }
    }
}
