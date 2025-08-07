<#
functions for Prvate Key
#>
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

function ConvertFrom-Pkcs8EncryptedPrivateKey
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.AsymmetricAlgorithm])]
    param(
        [Parameter(ParameterSetName = "Data", Mandatory, Position = 0)]
        [byte[]] $Data
        ,
        [Parameter(ParameterSetName = "ASN1", Mandatory, Position = 0)]
        [Asn1Data] $Asn1Data
        ,
        [Parameter()]
        [securestring] $Password
        ,
        [Parameter()]
        [KeyAlgorithm] $Algorithm
    )
    $epkAsn = switch ($PSCmdlet.ParameterSetName)
    {
        "Data" {
            [Asn1Serializer]::Deserialize($Data)[0]
        }
        "ASN1" {
            $Asn1Data
        }
    }
    if ($null -eq $Algorithm)
    {
        $Algorithm = [UI]::ChoicePrompt[KeyAlgorithm]($Host.UI, 'Choose Key Algorithm')
    }
    $PasswordIsPresent = $null -ne $Password
    try
    {
        if (-not $PasswordIsPresent)
        {
            $Password = [UI]::PasswordPrompt($Host.UI,
                                             'Passphrase',
                                             'Encrypted Private Key',
                                             'Passphrase is required for extracting private key');
        }
        [AsymmetricAlgorithm] $key = switch ($Algorithm)
        {
            'ECDsa' {
                [ECDsa]::Create();
            }
            'RSA' {
                [RSA]::Create();
            }
            'DSA' {
                [DSA]::Create()
            }
            default {
                throw [System.IO.InvalidDataException]::new("Invalie Algorithm name: '$Algorithm'");
            }
        }
        [int] $bytesRead = $null
        $key.ImportEncryptedPkcs8PrivateKey((ConvertFrom-SecureString -SecureString $Password -AsPlainText),
                                            $epkAsn.RawData.ToArray(),
                                            [ref] $bytesRead)
        Write-Output $key
    }
    catch [CryptographicException]
    {
        throw
    }
    finally
    {
        if (-not $PasswordIsPresent)
        {
            $Password.Dispose()
        }
    }
}

function ConvertFrom-Pkcs8PrivateKey
{
    [CmdletBinding()]
    [OutputType([System.Security.Cryptography.AsymmetricAlgorithm])]
    param(
        [Parameter(ParameterSetName = "Data", Mandatory, Position = 0)]
        [byte[]] $Data
        ,
        [Parameter(ParameterSetName = "ASN1", Mandatory, Position = 0)]
        [MT.Asn1.Asn1Data] $Asn1Data
    )
    $pkAsn = switch ($PSCmdlet.ParameterSetName)
    {
        "Data" {
            [Asn1Serializer]::Deserialize($Data)[0]
        }
        "ASN1" {
            $Asn1Data
        }
    }
    # Pkcs8 Private Key:
    #   Constructed SequenceOf
    #     Integer                00
    #     Constructed SequenceOf
    #       ObjectIdentifier     { 'ECC' | 'RSA' | 'DSA' }   <--- GET
    #       ObjectIdentifier     Optional
    #     OctetString            [...OctetString]
    try
    {
        $pkAlgorithm = $pkAsn.Children[1].Children[0]
    }
    catch
    {
        throw [System.IO.InvalidDataException]::new("The data is not PKCS#8 Private Key format.");
    }
    if ($null -eq $pkAlgorithm -or $pkAlgorithm -isnot [OidData])
    {
        throw [System.IO.InvalidDataException]::new("The data is not PKCS#8 Private Key format.");
    }
    $privateKey = switch ($pkAlgorithm.Oid.Value)
    {
        "1.2.840.10045.2.1" # ECC
        {
            Write-Verbose "Load as Pkcs8 ECDsa PrivateKey"
            New-ECDsaPrivateKey -Data $pkAsn.RawData.ToArray()
        }
        "1.2.840.113549.1.1.1" # RSA
        {
            Write-Verbose "Load as Pkcs8 RSA PrivateKey"
            New-RSAPrivateKey -Data $pkAsn.RawData.ToArray()
        }
        "1.2.840.10040.4.1" # DSA
        {
            Write-Verbose "Load as Pkcs8 DSA PrivateKey"
            New-DSAPrivateKey -Data $pkAsn.RawData.ToArray()
        }
        default
        {
            throw [System.NotSupportedException]::new("Key Algorithm is not supported: $switch)")
        }
    }
    Write-Output $privateKey;
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
        [PrivateKeyType] $KeyType
        ,
        [Parameter()]
        [KeyAlgorithm] $Algorithm
    )
    $pipelineInput = $input
    switch ($PSCmdlet.ParameterSetName)
    {
        'PEM' {
            if ($pipelineInput.Count -gt 0)
            {
                $PEM = $pipelineInput -join "`n"
            }
            foreach ($pemData in $PEM | Read-PEM | Where-Object Label -Like '*PRIVATE KEY')
            {
                Write-Verbose "PEM Data`n$pemData";
                $bytes = $pemData.GetRawData();
                $asn1Data = [Asn1Serializer]::Deserialize($bytes)[0]
                $asn1Data | Write-Asn1Tree | Format-Table -HideTableHeaders -Wrap | Out-String -Width 80 | Write-Verbose
                $key = switch ($pemData.Label)
                {
                    "RSA PRIVATE KEY" {
                        Write-Verbose "Load as Pkcs1 RSA PrivateKey"
                        New-RSAPrivateKey -Data $bytes -Pkcs1
                    }
                    "EC PRIVATE KEY" {
                        Write-Verbose "Load as Pkcs1 ECDsa PrivateKey"
                        New-ECDsaPrivateKey -Data $bytes -Pkcs1
                    }
                    "PRIVATE KEY" {
                        Write-Verbose "Reading data labeled '$($pemData.Label)'"
                        ConvertFrom-Pkcs8PrivateKey -Asn1Data $asn1Data
                    }
                    "ENCRYPTED PRIVATE KEY" {
                        Write-Verbose "Reading data labeled '$($pemData.Label)'"
                        $params = @{ Asn1Data = $asn1Data }
                        if ($Algorithm)
                        {
                            $params['Algorithm'] = "$Algorithm"
                        }
                        ConvertFrom-Pkcs8EncryptedPrivateKey @params
                    }
                    default {
                        throw [System.NotSupportedException]::new("$($pemData.Label)) is not supported")
                    }
                }
                Write-Output $key
            }
        }
        'Binary' {
            if ($pipelineInput.Count -gt 0)
            {
                $Data = [byte[]] $pipelineInput;
            }
            $asn1Data = (ConvertTo-Asn1 -Data $Data)[0]
            $asn1Data | Write-Asn1Tree | Format-Table -HideTableHeaders -Wrap | Out-String -Width 80 | Write-Verbose
            if ($null -eq $asn1Data -or -not $asn1Data.Tag.IsConstructed)
            {
                return;
            }
            if ($null -eq $KeyType)
            {
                $KeyType = [UI]::ChoicePrompt[PrivateKeyType]($Host.UI, 'Data Type', 'Choose data type of the private key')
            }
            switch ($KeyType)
            {
                'EncryptedPkcs8' {
                    $params = @{ Asn1Data = $asn1Data; }
                    if ($Algorithm)
                    {
                        $params['Algorithm'] = $Algorithm.ToString();
                    }

                    ConvertFrom-Pkcs8EncryptedPrivateKey @params
                }
                'Pkcs8' {
                    ConvertFrom-Pkcs8PrivateKey -Asn1Data $asn1Data
                }
                default {
                    if ($null -eq $Algorithm)
                    {
                        $Algorithm = [UI]::ChoicePrompt[KeyAlgorithm]($Host.UI, 'Choose Key Algorithm');
                    }

                    switch ($Algorithm)
                    {
                        'DSA'
                        {
                            throw [System.NotSupportedException]::new('Pkcs1 DSA Key is not supported');
                        }
                        'RSA'
                        {
                            New-RSAPrivateKey -Data $asn1Data.RawData.ToArray() -Pkcs1
                        }
                        'ECDsa'
                        {
                            New-ECDsaPrivateKey -Data $asn1Data.RawData.ToArray() -Pkcs1
                        }
                    }
                }
            }
        }
    }
}
