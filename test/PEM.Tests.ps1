BeforeAll {
    $PrivateKeysDir = Join-Path -Path $PSScriptRoot -ChildPath PrivateKey

    function Test-PrivateKey([string] $File, [string] $ExpectLabel, [string] $ExpectBase64Data)
    {
        $pemData = Read-PEM -Path $File
        Assert-Equal -Expected 1 -Actual $pemData.Count
        $pemData.Label | Should -BeLike $ExpectLabel
        $pemData.Base64Data | Should -BeLike $ExpectBase64Data
        $pemData.ToString() | Should -Be ([System.IO.File]::ReadAllText($File).TrimEnd())
    }
}

Describe 'PEM' {
    Context 'Read-PEM' {
        It 'Read from RSA PRIVATE KEY file (pkcs1)' {
            Test-PrivateKey -File (Join-Path -Path $PrivateKeysDir -ChildPath 'rsa.pkcs1.pem') `
                            -ExpectLabel 'RSA PRIVATE KEY' `
                            -ExpectBase64Data 'MIIBOwIBAAJBAJsO*xWgS4vYpU1X34w=='
        }

        It 'Read from RSA PRIVATE KEY file (pkcs8)' {
            Test-PrivateKey -File (Join-Path -Path $PrivateKeysDir -ChildPath 'rsa.pkcs8.pem') `
                            -ExpectLabel 'PRIVATE KEY' `
                            -ExpectBase64Data 'MIIBVQIBADANBgkqhkiG*aBLi9ilTVffj'
        }

        It 'Read from ECDsa PRIVATE KEY file (pkcs1)' {
            Test-PrivateKey -File (Join-Path -Path $PrivateKeysDir -ChildPath 'ecdsa.pkcs1.pem') `
                            -ExpectLabel 'EC PRIVATE KEY' `
                            -ExpectBase64Data 'MHcCAQEEIEACsXkn7*/s0e5kyWlg5FQ=='
        }

        It 'Read from ECDsa PRIVATE KEY file (pkcs8)' {
            Test-PrivateKey -File (Join-Path -Path $PrivateKeysDir -ChildPath 'ecdsa.pkcs8.pem') `
                            -ExpectLabel 'PRIVATE KEY' `
                            -ExpectBase64Data 'MIGHAgEAMBMGByqGSM*qveXwD+zR7mTJaWDkV'
        }

        It 'Read from DSA PRIVATE KEY file (pkcs8)' {
            Test-PrivateKey -File (Join-Path -Path $PrivateKeysDir -ChildPath 'dsa.pkcs8.pem') `
                            -ExpectLabel 'PRIVATE KEY' `
                            -ExpectBase64Data 'MIIBWgIBADCCATMGBy*tLl4LuWn2jL+ukEDhSc='
        }
    }
}
