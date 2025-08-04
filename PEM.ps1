<#
PEM フォーマット系
#>
function Read-PEM
{
    <#
    .SYNOPSIS
    PEM形式のファイルまたはデータを読む

    .DESCRIPTION
    PEM形式のデータを解析し、ラベル(`Label`)とコンテンツ(`Base64Data`)を持つオブジェクトを返す

    .PARAMETER Path
    ファイルパスから読む

    .PARAMETER InputObject
    文字列から読む。
    パイプラインから複数行の値が渡された場合は全て改行(`LF`)で連結して解析されます。

    #>
    [CmdletBinding()]
    [OutputType([Certs.PemData])]
    param(
        [Parameter(ParameterSetName = "File", Mandatory, Position = 0)]
        [string] $Path
        ,
        [Parameter(ParameterSetName = "Data", Mandatory, ValueFromPipeline)]
        [string] $InputObject
    )
    $data = switch ($PSCmdlet.ParameterSetName)
    {
        "File" {
            Write-Verbose $Path
            Get-Content -Raw -Path $Path;
        }
        "Data" {
            $pipelineInput = $input
            if ($pipelineInput.Count -gt 0)
            {
                $pipelineInput -join "`n"
            }
            else
            {
                $InputObject
            }
        }
    }
    if ([string]::IsNullOrEmpty($data))
    {
        Write-Warning "Input data is empty"
        return;
    }
    Write-Output ([Certs.PemData]::Parse($data))
}
