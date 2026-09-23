function ConvertTo-AgentIdSnapshotObject {
    param([Parameter(Mandatory)][string]$Json)
    $obj = $Json | ConvertFrom-Json -Depth 64
    if ($obj.Tool -ne 'AgentIdAudit' -or -not $obj.SchemaVersion) {
        throw 'The input is not an AgentIdAudit snapshot.'
    }
    if ([int]$obj.SchemaVersion -gt $script:AgentIdSchemaVersion) {
        throw "The snapshot uses schema version $($obj.SchemaVersion), which is newer than this version of AgentIdAudit supports ($script:AgentIdSchemaVersion). Update the module."
    }
    $obj.PSObject.TypeNames.Insert(0, 'AgentIdAudit.Snapshot')
    return $obj
}

function New-AgentIdOptions {
    param(
        [int]$MaxCredentialLifetimeDays = 180,
        [int]$StaleAfterDays = 90,
        [int]$ExpiringWithinDays = 30,
        [string[]]$RequiredSecurityAttribute,
        [string[]]$OptionalSecurityAttribute
    )
    # An attribute named in both lists is required.
    $required = @($RequiredSecurityAttribute | Where-Object { $_ } | Sort-Object -Unique)
    $optional = @($OptionalSecurityAttribute | Where-Object { $_ -and $_ -notin $required } | Sort-Object -Unique)
    return @{
        MaxCredentialLifetimeDays = $MaxCredentialLifetimeDays
        StaleAfterDays            = $StaleAfterDays
        ExpiringWithinDays        = $ExpiringWithinDays
        RequiredSecurityAttribute = $required
        OptionalSecurityAttribute = $optional
    }
}
