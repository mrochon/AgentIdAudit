function Export-AgentIdSnapshot {
    <#
    .SYNOPSIS
    Saves a snapshot to a JSON file.

    .DESCRIPTION
    A snapshot holds configuration metadata only: object names and IDs, permission grants, sponsors, and
    credential metadata (names, types and validity dates). It never contains secret values, certificate
    contents or tokens, so it can be analyzed on another machine or shared with an adviser. It does contain
    names, including the names and user principal names of sponsors and owners, so handle it accordingly.

    .EXAMPLE
    Get-AgentIdInventory | Export-AgentIdSnapshot -Path .\agents-2026-09-18.json
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][PSTypeName('AgentIdAudit.Snapshot')]$Snapshot,
        [Parameter(Mandatory)][string]$Path
    )
    process {
        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        if ($PSCmdlet.ShouldProcess($full, 'Write agent identity snapshot')) {
            $Snapshot | ConvertTo-Json -Depth 32 | Set-Content -LiteralPath $full -Encoding utf8
            Get-Item -LiteralPath $full
        }
    }
}

function Import-AgentIdSnapshot {
    <#
    .SYNOPSIS
    Loads a snapshot saved with Export-AgentIdSnapshot.

    .EXAMPLE
    Import-AgentIdSnapshot .\agents-2026-09-18.json | Get-AgentIdFinding
    #>
    [CmdletBinding()]
    [OutputType('AgentIdAudit.Snapshot')]
    param([Parameter(Mandatory, Position = 0)][string]$Path)
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    ConvertTo-AgentIdSnapshotObject (Get-Content -LiteralPath $full -Raw -Encoding utf8)
}
