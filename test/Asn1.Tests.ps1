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
}
