<#
functions for Prvate Key
#>
using namespace System.Security.Cryptography;
using namespace MT.Asn1;
using namespace MT.Sec;
using namespace MT.PowerShell;

function New-ECDsaPrivateKey
{
    <#
    .SYNOPSIS
    Create ECDsa Key
    .DESCRIPTION
    Create ECDsa with curve name or EC Parameters
    .PARAMETER CurveName
    New key from the curve name
    .PARAMETER ECParameters
    with `System.Security.Cryptography.ECParameters`
    .PARAMETER Data
    with binary data formated DER.
    .PARAMETER Pkcs1
    The `Data` parameter must be specified if it is in PKCS1 format. (If converted to PEM format, it will be labeled `EC PRIVATE KEY`.)
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.ECDsa])]
    param(
        [Parameter(ParameterSetName = "New", Mandatory, Position = 0)]
        [ArgumentCompleter({
            param($commandName, $parameterName, $wordToComplete, $commandAst, $fakeBoundParameters)
            [System.Security.Cryptography.ECCurve+NamedCurves].
                GetProperties().
                Where({$_.Name.StartsWith($wordToComplete, [System.StringComparison]::OrdinalIgnoreCase)}).
                ForEach({$_.Name});
        })]
        [string] $CurveName
        ,
        [Parameter(ParameterSetName = "Params", Mandatory, Position = 0)]
        [ECParameters] $ECParameters
        ,
        [Parameter(ParameterSetName = "Binary", Mandatory, Position = 0)]
        [byte[]] $Data
        ,
        [Parameter(ParameterSetName = "Binary")]
        [switch] $Pkcs1
    )
    [ECDsa] $key = $null;
    switch ($PSCmdlet.ParameterSetName)
    {
        "New" {
            $curve = [ECCurve+NamedCurves]::$CurveName
            if ($null -eq $curve)
            {
                return;
            }
            $key = [ECDsa]::Create($curve)
        }
        "Params" {
            $key = [ECDsa]::Create($ECParameters);
        }
        "Binary" {
            [int] $bytesRead = $null;
            $key = [ECDsa]::Create();
            if ($Pkcs1)
            {
                $key.ImportECPrivateKey($Data, [ref] $bytesRead)
            }
            else
            {
                $key.ImportPkcs8PrivateKey($Data, [ref] $bytesRead);
            }
        }
    }
    Write-Output $key
}

function New-RSAPrivateKey
{
    <#
    .SYNOPSIS
    Create RSA Key
    .DESCRIPTION
    Create RSA with bit length or RSA Parameters
    .PARAMETER Bit
    Create new key with the bit length.
    .PARAMETER ECParameters
    with `System.Security.Cryptography.RSAParameters`
    .PARAMETER Data
    with binary data formated DER.
    Normally, the `Data` value assumes PKCS8 format; for PKCS1 format, specify the `Pkcs1` parameter.
    .PARAMETER Pkcs1
    The `Data` parameter must be specified if it is in PKCS1 format. (If converted to PEM format, it will be labeled `RSA PRIVATE KEY`.)
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.RSA])]
    param(
        [Parameter(ParameterSetName = "New", Mandatory, Position = 0)]
        [int] $Bit
        ,
        [Parameter(ParameterSetName = "Params", Mandatory, Position = 0)]
        [RSAParameters] $RSAParameters
        ,
        [Parameter(ParameterSetName = "Binary", Mandatory, Position = 0)]
        [byte[]] $Data
        ,
        [Parameter(ParameterSetName = "Binary")]
        [switch] $Pkcs1
    )
    [RSA] $key = $null;
    switch ($PSCmdlet.ParameterSetName)
    {
        "New" {
            $key = [RSA]::Create($Bit);
        }
        "Params" {
            $key = [RSA]::Create($RSAParameters);
        }
        "Binary" {
            [int] $bytesRead = $null;
            $key = [RSA]::Create();
            if ($Pkcs1)
            {
                $key.ImportRSAPrivateKey($Data, [ref] $bytesRead)
            }
            else
            {
                $key.ImportPkcs8PrivateKey($Data, [ref] $bytesRead);
            }
        }
    }
    Write-Output $key
}

function New-DSAPrivateKey
{
    <#
    .SYNOPSIS
    Create DSA Key
    .DESCRIPTION
    Create DSA with bit length or DSA Parameters
    .PARAMETER Bit
    Create new key with the bit length.
    .PARAMETER DSAParameters
    with `System.Security.Cryptography.RSAParameters`
    .PARAMETER Data
    with binary data formated DER.
    the `Data` value must be PKCS8 format. (Not supported PKCS1 format)
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.DSA])]
    param(
        [Parameter(ParameterSetName = "New", Mandatory, Position = 0)]
        [int] $Bit
        ,
        [Parameter(ParameterSetName = "Params", Mandatory, Position = 0)]
        [DSAParameters] $DSAParameters
        ,
        [Parameter(ParameterSetName = "Binary", Mandatory, Position = 0)]
        [byte[]] $Data
    )
    [DSA] $key = $null;
    switch ($PSCmdlet.ParameterSetName)
    {
        "New" {
            $key = [DSA]::Create($Bit);
        }
        "Params" {
            $key = [DSA]::Create($RSAParameters);
        }
        "Binary" {
            [int] $bytesRead = $null;
            $key = [DSA]::Create();
            $key.ImportPkcs8PrivateKey($Data, [ref] $bytesRead);
        }
    }
    Write-Output $key
}

function ConvertTo-PrivateKey
{
    <#
    .SYNOPSIS
    データを秘密鍵へ変換する

    .PARAMETER PEM
    PEM形式の文字列

    .PARAMETER Data
    バイナリデータ

    .PARAMETER KeyType
    鍵の形式。 (`Pkcs1` | `Pkcs8` | 'EncryptedPkcs8`)
    省略時、入力値がバイナリデータの場合は選択プロンプトが出ます。

    .PARAMETER Algorithm
    秘密鍵の種類。 (`RSA` | `ECDsa` | `DSA`)
    省略時、入力値がPEM形式で EncryptedPkcs8 の場合は、選択プロンプトが出ます。
    入力値がバイナリデータの場合にも選択プロンプトが出ます。

    .PARAMETER Password
    EncryptedPkcs8 形式から鍵の抽出に必要なパスワード
    #>
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.AsymmetricAlgorithm])]
    param(
        [Parameter(ParameterSetName = "PEM", Mandatory, ValueFromPipeline, Position = 0)]
        [string] $PEM
        ,
        [Parameter(ParameterSetName = "Binary", Mandatory, ValueFromPipeline, Position = 0)]
        [byte[]] $Data
        ,
        [Parameter()]
        [KeyAlgorithm] $Algorithm = [KeyAlgorithm]::Unknown
        ,
        [Parameter()]
        [securestring] $Password
    )
    $pipelineInput = $input
    $pk = switch ($PSCmdlet.ParameterSetName)
    {
        'PEM' {
            if ($pipelineInput.Count -gt 0)
            {
                $PEM = $pipelineInput -join "`n"
            }
            [PrivateKey]::Decode($PEM)
        }
        'Binary' {
            if ($pipelineInput.Count -gt 0)
            {
                $Data = [byte[]] $pipelineInput;
            }
            [PrivateKey]::Decode($Data)
        }
    }
    Write-Verbose ([Asn1Serializer]::EnumerateAsTree($pk.Data) | Out-String)
    Write-Verbose ("Load as {0}" -f $pk.Type)
    if ($pk.Algorithm -ne 'Unknown')
    {
        Write-Verbose ("Detected key algorithm: {0}" -f $pk.Algorithm)
        if ($Algorithm -ne [KeyAlgorithm]::Unknown -and $Algorithm -ne $pk.Algorithm)
        {
            Write-Warning "Specified Algorithm is '$Algorithm', but detected is '$($pk.Algorithm)'. Use detected algorithm"
        }
    }
    Write-Output $pk.GetPrivateKey($Host, $Password, $Algorithm)
}
