BeforeAll {
    $script:TestDir = Join-Path -Path $PSScriptRoot -ChildPath PrivateKey
    $script:Password = ConvertTo-SecureString -String 'P@ssw0rd' -AsPlainText -Force
}

Describe 'PrivateKey' {
    Context 'New-ECDsaPrivateKey' {
        It 'New' {
            $ecdsa = New-ECDsaPrivateKey -CurveName nistP256
            $ecdsa.KeySize | Should -Be 256
            $param = $ecdsa.ExportParameters($false)
            $param.Curve.Oid.FriendlyName | Should -Be 'ECDSA_P256'

            $ecdsa.ExportECPrivateKeyPem();
            $ecdsa.Dispose();
        }

        It 'Import Pkcs1-DER' {
            $derFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'ecdsa.pkcs1.der')
            $pemFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'ecdsa.pkcs1.pem')

            $ecdsa = New-ECDsaPrivateKey -Data ([System.IO.File]::ReadAllBytes($derFile)) -Pkcs1

            $ecdsa.ExportECPrivateKeyPem() | Should -Be ([System.IO.File]::ReadAllText($pemFile).Trim())
            $ecdsa.KeySize | Should -Be 256

            $ecdsa.Dispose();
        }

        It 'Import Pkcs8-DER' {
            $derFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'ecdsa.pkcs8.der')
            $pemFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'ecdsa.pkcs8.pem')

            $ecdsa = New-ECDsaPrivateKey -Data ([System.IO.File]::ReadAllBytes($derFile))

            $ecdsa.ExportPkcs8PrivateKeyPem() | Should -Be ([System.IO.File]::ReadAllText($pemFile).Trim())
            $ecdsa.KeySize | Should -Be 256

            $ecdsa.Dispose();
        }
    }

    Context 'New-RSAPrivateKey' {
        It 'New' {
            $rsa = New-RSAPrivateKey -Bit 1024
            $rsa.KeySize | Should -Be 1024

            $rsa.Dispose()
        }

        It 'Import Pkcs1-DER' {
            $derFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'rsa.pkcs1.der')
            $pemFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'rsa.pkcs1.pem')

            $rsa = New-RSAPrivateKey -Data ([System.IO.File]::ReadAllBytes($derFile)) -Pkcs1

            $rsa.ExportRSAPrivateKeyPem() | Should -Be ([System.IO.File]::ReadAllText($pemFile).Trim())
            $rsa.KeySize | Should -Be 512

            $rsa.Dispose();
        }

        It 'Import Pkcs8-DER' {
            $derFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'rsa.pkcs8.der')
            $pemFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'rsa.pkcs8.pem')

            $rsa = New-RSAPrivateKey -Data ([System.IO.File]::ReadAllBytes($derFile))

            $rsa.ExportPkcs8PrivateKeyPem() | Should -Be ([System.IO.File]::ReadAllText($pemFile).Trim())
            $rsa.KeySize | Should -Be 512

            $rsa.Dispose();
        }
    }

    Context 'New-DSAPrivateKey' {
        It 'New' {
            $rsa = New-DSAPrivateKey -Bit 1024
            $rsa.KeySize | Should -Be 1024

            $rsa.Dispose()
        }

        It 'Import Pkcs8-DER' {
            $derFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'dsa.pkcs8.der')
            $pemFile = Get-Item -Path (Join-Path -Path $TestDir -ChildPath 'dsa.pkcs8.pem')

            $dsa = New-DSAPrivateKey -Data ([System.IO.File]::ReadAllBytes($derFile))

            $dsa.ExportPkcs8PrivateKeyPem() | Should -Be ([System.IO.File]::ReadAllText($pemFile).Trim())
            $dsa.KeySize | Should -Be 1024

            $dsa.Dispose();
        }
    }

    Context 'ConvertTo-PrivateKey <algorithm> <type>' -ForEach @(
        @{ algorithm = 'RSA';   expected = 'rsa.pkcs8.pem';   targets = @(
            @{ type = 'Pkcs1';  fileSuffix = 'pkcs1.pem';  }
          , @{ type = 'Pkcs8';  fileSuffix = 'pkcs8.pem';  }
          , @{ type = 'EncryptedPkcs8'; fileSuffix = 'pkcs8.encrypted.pem'; }
        )}
      , @{ algorithm = 'ECDsa'; expected = 'ecdsa.pkcs8.pem';   targets = @(
            @{ type = 'Pkcs1';  fileSuffix = 'pkcs1.pem';  }
          , @{ type = 'Pkcs8';  fileSuffix = 'pkcs8.pem';  }
          , @{ type = 'EncryptedPkcs8'; fileSuffix = 'pkcs8.encrypted.pem'; }
        )}
      , @{ algorithm = 'DSA';   expected = 'dsa.pkcs8.pem';   targets = @(
          , @{ type = 'Pkcs8';  fileSuffix = 'pkcs8.pem';  }
          , @{ type = 'EncryptedPkcs8'; fileSuffix = 'pkcs8.encrypted.pem'; }
        )}
    ) {
        BeforeAll {
            $script:expectedPemData = (Get-Content -Raw -Path (Join-Path -Path $TestDir -ChildPath $expected)).Trim()
        }
        It 'From PEM argument <type>' -ForEach $targets {
            $pem = Read-PEM -Path (Join-Path -Path $TestDir -ChildPath ("{0}.{1}" -f $algorithm.ToLowerInvariant(), $fileSuffix))
            $params = @{ PEM = $pem }
            if ($type -eq 'EncryptedPkcs8')
            {
                $params['Algorithm'] = $algorithm
                $params['Password'] = $Password
            }
            $key = ConvertTo-PrivateKey @params
            $key.ExportPkcs8PrivateKeyPem() | Should -Be $expectedPemData
        }

        It 'From PEM pipeline <type>' -ForEach $targets {
            $pem = Read-PEM -Path (Join-Path -Path $TestDir -ChildPath ("{0}.{1}" -f $algorithm.ToLowerInvariant(), $fileSuffix))
            $params = @{}
            if ($type -eq 'EncryptedPkcs8')
            {
                $params['Algorithm'] = $algorithm
                $params['Password'] = $Password
            }
            $key = $pem | ConvertTo-PrivateKey @params
            $key.ExportPkcs8PrivateKeyPem() | Should -Be $expectedPemData
        }

        It 'From Binary argument <type>' -ForEach $targets {
            $pem = Read-PEM -Path (Join-Path -Path $TestDir -ChildPath ("{0}.{1}" -f $algorithm.ToLowerInvariant(), $fileSuffix))
            $params = @{ Data = $pem.GetRawData(); KeyType = $type; Algorithm = $algorithm; }
            if ($type -eq 'EncryptedPkcs8')
            {
                $params['Password'] = $Password
            }
            $key = ConvertTo-PrivateKey @params
            $key.ExportPkcs8PrivateKeyPem() | Should -Be $expectedPemData
        }

        It 'From Binary pipeline <type>' -ForEach $targets {
            $pem = Read-PEM -Path (Join-Path -Path $TestDir -ChildPath ("{0}.{1}" -f $algorithm.ToLowerInvariant(), $fileSuffix))
            $params = @{ KeyType = $type; Algorithm = $algorithm; }
            if ($type -eq 'EncryptedPkcs8')
            {
                $params['Password'] = $Password
            }
            $key = $pem.GetRawData() | ConvertTo-PrivateKey @params
            $key.ExportPkcs8PrivateKeyPem() | Should -Be $expectedPemData
        }
    }
}
