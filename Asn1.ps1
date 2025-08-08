<#
Functions for Abstract Syntax Notation One (ASN.1)
#>
using namespace System.Formats.Asn1;
using namespace MT.Asn1;

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
        [AsnEncodingRules] $Type = [AsnEncodingRules]::DER
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
                Write-Output ([Asn1Serializer]::Deserialize($pemData.GetRawData(), $Type))
            }
        }
        "Binary" {
            if ($pipelineInput.Count -gt 0)
            {
                $Data = [byte[]] $pipelineInput;
            }
            Write-Verbose "Read binary data: byte[$($Data.Length)]";
            Write-Output ([Asn1Serializer]::Deserialize($Data, $Type))
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

function Write-Asn1Tree
{
    <#
    .SYNOPSIS
    Print out ASN.1 data recursively
    #>
    param(
        [Parameter(Mandatory, ValueFromPipeline)]
        [MT.Asn1.Asn1Data] $Data
        ,
        [Parameter()]
        [switch] $NoIndent
        ,
        [Parameter(DontShow)]
        [int] $Depth = 0
    )
    begin
    {
        $indent = if ($NoIndent) { "" } else { "  " * $Depth }
    }
    process
    {
        $result = [PSCustomObject]@{
            Name = "{0}{1}" -f $indent, $Data.Tag
            Value = $Data.Data;
        }
        Write-Output $result
        if ($Data.Tag.IsConstructed)
        {
            $childDepth = $Depth + 1
            foreach ($child in ([MT.Asn1.ConstructedData]$Data).Children)
            {
                Write-Asn1Tree -Data $child -NoIndent:$NoIndent -Depth $childDepth
            }
        }
    }
}

function Show-Asn1Tree
{
    <#
    .SYNOPSIS
    ASN.1 データの階層構造を出力
    .PARAMETER RuleSet
    `DER', `CER' 等のデータタイプ
    .PARAMETER NoIndent
    階層構造のインデントを出力しない
    .PARAMETER Asn1
    ASN.1 オブジェクト
    .PARAMETER PEM
    PEM オブジェクト
    .PARAMETER Base64
    Base64エンコードされた文字列
    .PARAMETER Data
    バイナリデータ
    #>
    param(
        [Parameter()]
        [switch] $NoIndent
        ,
        [Parameter()]
        [AsnEncodingRules] $RuleSet = 'DER'
        ,
        [Parameter(ParameterSetName = "ASN1", Mandatory, ValueFromPipeline)]
        [Asn1Data] $Asn1
        ,
        [Parameter(ParameterSetName = "PEM", Mandatory, ValueFromPipeline)]
        [MT.Sec.PemData] $PEM
        ,
        [Parameter(ParameterSetName = "Base64", Mandatory, ValueFromPipeLine)]
        [string] $Base64
        ,
        [Parameter(ParameterSetName = "Binary", Mandatory, ValueFromPipeLine)]
        [byte[]] $Data
    )
    $pipelineInput = $input
    $asnData = if ($pipelineInput.Count -gt 0)
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "PEM" {
                Write-Verbose "Read PEM from pipeline"
                ConvertTo-Asn1 -PEMs $pipelineInput
            }
            "Base64" {
                Write-Verbose "Read Base64 from pipeline"
                $pipelineInput | ForEach-Object { ConvertTo-Asn1 -Data ([Convert]::FromBase64String($_)) }
            }
            "Binary" {
                Write-Verbose "Read binary from pipeline"
                ConvertTo-Asn1 -Data ([byte[]]$pipelineInput)
            }
            "ASN1" {
                Write-Verbose "Read ASN1 from pipeline"
                $pipelineInput
            }
        }
    }
    else
    {
        switch ($PSCmdlet.ParameterSetName)
        {
            "PEM" {
                Write-Verbose "Read PEM"
                ConvertTo-Asn1 -Data $PEM.GetRawData()
            }
            "Base64" {
                Write-Verbose "Read Base64"
                ConvertTo-Asn1 -Data ([Convert]::FromBase64String($Base64))
            }
            "Binary" {
                Write-Verbose "Read Binary"
                ConvertTo-Asn1 -Data $Data
            }
            "ASN1" {
                Write-Verbose "Read ASN1"
                $Asn1
            }
        }
    }
    $asnData | 
        Write-Asn1Tree -NoIndent:$NoIndent |
            Format-Table -HideTableHeaders -Wrap
}
