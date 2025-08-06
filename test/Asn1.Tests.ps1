BeforeAll {
    $script:privateKeyDir = Join-Path -Path $PSScriptRoot -ChildPath 'PrivateKey'
}

Describe 'Asn1' {
    Context 'ConvertTo-Asn1' {
        It 'Convert PEM data to Asn1: <dir>/<name>' -ForEach @(
            @{ name = 'dsa.pkcs8.pem'; dir = 'PrivateKey' },
            @{ name = 'ecdsa.pkcs1.pem'; dir = 'PrivateKey' },
            @{ name = 'ecdsa.pkcs8.pem'; dir = 'PrivateKey' }
            @{ name = 'rsa.pkcs1.pem'; dir = 'PrivateKey' },
            @{ name = 'rsa.pkcs8.pem'; dir = 'PrivateKey' }
        ) {
            $PEMs = Read-PEM -Path (Join-Path -Path $privateKeyDir -ChildPath $name)

            # Apply PEM data from an argument
            ConvertTo-Asn1 -PEM $PEMs | Should -ExpectedType MT.Asn1.Asn1Data
            # Apply PEM data from pipeline
            $PEMs | ConvertTo-Asn1 | Should -ExpectedType MT.Asn1.Asn1Data
        }

        It 'Convert BINARY data to Asn1: <dir>/<name>' -ForEach @(
            @{ name = 'dsa.pkcs8.der'; dir = 'PrivateKey' },
            @{ name = 'ecdsa.pkcs1.der'; dir = 'PrivateKey' },
            @{ name = 'ecdsa.pkcs8.der'; dir = 'PrivateKey' }
            @{ name = 'rsa.pkcs1.der'; dir = 'PrivateKey' },
            @{ name = 'rsa.pkcs8.der'; dir = 'PrivateKey' }
        ) {
            $byteData = [IO.File]::ReadAllBytes((Join-Path -Path $privateKeyDir -ChildPath $name))

            # Apply BINARY data from an argument
            ConvertTo-Asn1 -Data $byteData | Should -ExpectedType MT.Asn1.Asn1Data
            # Apply BINARY data from pipeline
            $byteData | ConvertTo-Asn1 | Should -ExpectedType MT.Asn1.Asn1Data
        }
    }

    Context 'Show-Asn1Tree' {
        It 'From Asn1: <name>' -ForEach @(
            @{ name = 'ecdsa.pkcs1.der'; dir = 'PrivateKey' }
        ) {
            $asn1Data = ConvertTo-Asn1 -Data ([IO.File]::ReadAllBytes((Join-Path -Path $privateKeyDir -ChildPath $name)))
            Show-Asn1Tree -Asn1 $asn1Data
            $asn1Data | Show-Asn1Tree | Out-String -Width 120 | Write-Host -ForegroundColor DarkGray
        }

        It 'From PEM: <name>' -ForEach @(
            @{ name = 'ecdsa.pkcs1.pem'; dir = 'PrivateKey' }
        ) {
            $pemData = Read-PEM -Path (Join-Path -Path $privateKeyDir -ChildPath $name)
            Show-Asn1Tree -PEM $pemData
            $pemData | Show-Asn1Tree | Out-String -Width 120 | Write-Host -ForegroundColor DarkGray
        }

        It 'From Base64: <name>' -ForEach @(
            @{ name = 'ecdsa.pkcs8.pem'; dir = 'PrivateKey' }
        ) {
            $pemData = Read-PEM -Path (Join-Path -Path $privateKeyDir -ChildPath $name)
            Show-Asn1Tree -Base64 $pemData.Base64Data
            $pemData.Base64Data | Show-Asn1Tree | Out-String -Width 120 | Write-Host -ForegroundColor DarkGray
        }

        It 'From Binary: <name>' -ForEach @(
            @{ name = 'rsa.pkcs8.pem'; dir = 'PrivateKey' }
        ) {
            $pemData = Read-PEM -Path (Join-Path -Path $privateKeyDir -ChildPath $name)
            Show-Asn1Tree -Data $pemData.GetRawData()
            $pemData.GetRawData() | Show-Asn1Tree | Out-String -Width 120 | Write-Host -ForegroundColor DarkGray
        }
    }
}
