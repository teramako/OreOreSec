<#
.SYNOPSIS
Test OreOreSec
#>
param()

$ParnetDir = Join-Path -Path $PSScriptRoot -ChildPath .. -Resolve
Import-Module (Join-Path -Path $ParnetDir -ChildPath OreOreSec.psd1)
Import-Module -Name Pester

$conf = New-PesterConfiguration
$conf.Run.Path = $PSScriptRoot
# $conf.Debug.ReturnRawResultObject = $true
# $conf.Debug.WriteDebugMessages = 
$conf.Output.Verbosity = 'Detailed'

Invoke-Pester -Configuration $conf 

