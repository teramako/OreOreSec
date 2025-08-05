<#
functions for Prvate Key
#>

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
