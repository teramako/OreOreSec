BeforeAll {
    $script:PrivateKeysDir = Join-Path -Path $PSScriptRoot -ChildPath PrivateKey
    $script:unknownPEM = @(
        '-----BEGIN UNKNOWN-----',
        '44GG44KT44GT',
        '-----END UNKNOWN-----'
    )
}

Describe 'PEM' {
    Context 'Read-PEM' {
        It 'Read from <algorithm> PRIVATE KEY file (<pkcs>)' -ForEach @(
            @{ algorithm = 'RSA';   pkcs = 'pkcs1'; file = 'rsa.pkcs1.pem';   expectedLabel = 'RSA PRIVATE KEY'; expectedData = 'MIIBOwIBAAJBAJsO*xWgS4vYpU1X34w==' },
            @{ algorithm = 'RSA';   pkcs = 'pkcs8'; file = 'rsa.pkcs8.pem';   expectedLabel = 'PRIVATE KEY';     expectedData = 'MIIBVQIBADANBgkqhkiG*aBLi9ilTVffj' },
            @{ algorithm = 'ECDsa'; pkcs = 'pkcs1'; file = 'ecdsa.pkcs1.pem'; expectedLabel = 'EC PRIVATE KEY';  expectedData = 'MHcCAQEEIEACsXkn7*/s0e5kyWlg5FQ==' },
            @{ algorithm = 'ECDsa'; pkcs = 'pkcs8'; file = 'ecdsa.pkcs8.pem'; expectedLabel = 'PRIVATE KEY';     expectedData = 'MIGHAgEAMBMGByqGSM*qveXwD+zR7mTJaWDkV' },
            @{ algorithm = 'DSA';   pkcs = 'pkcs8'; file = 'dsa.pkcs8.pem';   expectedLabel = 'PRIVATE KEY';     expectedData = 'MIIBWgIBADCCATMGBy*tLl4LuWn2jL+ukEDhSc=' }
        ) {
            $pemFile = Join-Path -Path $PrivateKeysDir -ChildPath $file
            $pemData = Read-PEM -Path $pemFile
            Assert-Equal -Expected 1 -Actual $pemData.Count
            $pemData.Label | Should -BeLike $expectedLabel
            $pemData.Base64Data | Should -BeLike $expectedData
            $pemData.ToString() | Should -Be ([System.IO.File]::ReadAllText($pemFile).TrimEnd())
        }

        It 'Read from pipeile input (one string)' {
            $pemData = ($unknownPEM -join "`n") | Read-PEM
            $pemData.Label | Should -Be 'UNKNOWN'
            $pemData.Base64Data | Should -Be '44GG44KT44GT'
        }

        It 'Read from pipeile input (multiline string)' {
            $pemData = $unknownPEM | Read-PEM
            $pemData.Label | Should -Be 'UNKNOWN'
            $pemData.Base64Data | Should -Be '44GG44KT44GT'
        }

        It 'Should throw when invalid PEM format (unmatch label)' {
            Assert-Throw {
                (@('-----BEGIN MATCHED-----', '44GG44KT44GT', '------END UNMATCHED-----') -join "`n") | Read-PEM
            }
        }
    }
}
