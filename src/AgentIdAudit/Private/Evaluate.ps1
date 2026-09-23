$script:AgentIdGraphAppId = '00000003-0000-0000-c000-000000000000'
$script:AgentIdSeverityRank = @{ Critical = 4; High = 3; Medium = 2; Low = 1; Info = 0 }
$script:AgentIdWellKnownResources = @{
    '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
    '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
    '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
}

function New-AgentIdContext {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][datetimeoffset]$AsOf,
        [Parameter(Mandatory)][hashtable]$Options
    )
    $ctx = @{
        Snapshot                  = $Snapshot
        AsOf                      = $AsOf
        Options                   = $Options
        Blocked                   = $script:AgentIdBlockedPermissions
        Sensitive                 = $script:AgentIdSensitivePermissions
        AccessRows                = @(Get-AgentIdAccessRow -Snapshot $Snapshot)
        BlueprintByAppId          = @{}
        BlueprintPrincipalByAppId = @{}
        AgentById                 = @{}
        AgentsByBlueprintAppId    = @{}
        ResourceByAppId           = @{}
        SignInByAppId             = @{}
    }
    foreach ($b in @($Snapshot.Blueprints)) { if ($b) { $ctx.BlueprintByAppId[$b.appId] = $b } }
    foreach ($p in @($Snapshot.BlueprintPrincipals)) { if ($p) { $ctx.BlueprintPrincipalByAppId[$p.appId] = $p } }
    foreach ($a in @($Snapshot.AgentIdentities)) {
        if (-not $a) { continue }
        $ctx.AgentById[$a.id] = $a
        $key = "$($a.agentIdentityBlueprintId)"
        if (-not $ctx.AgentsByBlueprintAppId.ContainsKey($key)) { $ctx.AgentsByBlueprintAppId[$key] = [System.Collections.Generic.List[object]]::new() }
        $ctx.AgentsByBlueprintAppId[$key].Add($a)
    }
    foreach ($r in @($Snapshot.Resources)) { if ($r -and $r.appId) { $ctx.ResourceByAppId[$r.appId] = $r } }
    foreach ($s in @($Snapshot.SignInActivity)) { if ($s -and $s.appId) { $ctx.SignInByAppId[$s.appId] = $s } }
    return $ctx
}

function New-AgentIdFinding {
    param(
        [Parameter(Mandatory)]$Rule,
        [Parameter(Mandatory)][string]$ObjectType,
        [string]$ObjectId,
        [string]$ObjectName,
        [Parameter(Mandatory)][string]$Detail,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$Severity
    )
    [pscustomobject]@{
        PSTypeName  = 'AgentIdAudit.Finding'
        RuleId      = $Rule.Id
        Severity    = if ($Severity) { $Severity } else { $Rule.Severity }
        Category    = $Rule.Category
        Title       = $Rule.Title
        ObjectType  = $ObjectType
        ObjectName  = $ObjectName
        ObjectId    = $ObjectId
        Detail      = $Detail
        Remediation = $Rule.Remediation
        Reference   = $Rule.Reference
    }
}

function Get-AgentIdSeverityRank {
    param([string]$Severity)
    if ($script:AgentIdSeverityRank.ContainsKey("$Severity")) { return $script:AgentIdSeverityRank[$Severity] }
    return -1
}

function Get-AgentIdActiveCredential {
    param([Parameter(Mandatory)]$Ctx, $Credentials)
    foreach ($c in @($Credentials)) {
        if (-not $c) { continue }
        $end = ConvertTo-AgentIdDate $c.endDateTime
        if ($null -eq $end -or $end -gt $Ctx.AsOf) { $c }
    }
}

function Get-AgentIdExpiredCredential {
    param([Parameter(Mandatory)]$Ctx, $Credentials)
    foreach ($c in @($Credentials)) {
        if (-not $c) { continue }
        $end = ConvertTo-AgentIdDate $c.endDateTime
        if ($null -ne $end -and $end -le $Ctx.AsOf) { $c }
    }
}

function Format-AgentIdDate {
    param($Value)
    $d = ConvertTo-AgentIdDate $Value
    if ($null -eq $d) { return 'unknown' }
    return $d.UtcDateTime.ToString('yyyy-MM-dd')
}

function Format-AgentIdCredential {
    param($Credential)
    $name = if ($Credential.displayName) { "'$($Credential.displayName)'" } else { "key $($Credential.keyId)" }
    $kind = if ($Credential.kind -eq 'Secret') { 'secret' } else { 'certificate' }
    return "$name ($kind)"
}

function Test-AgentIdCoverageUsable {
    param([Parameter(Mandatory)]$Snapshot, [Parameter(Mandatory)][string]$Key)
    $entry = $Snapshot.Coverage.$Key
    return ($null -ne $entry -and $entry.Status -in 'Ok', 'Partial')
}

function Get-AgentIdBlueprintAgentText {
    # Describes who a blueprint credential or permission affects, without overstating what we know.
    param([Parameter(Mandatory)]$Ctx, [string]$BlueprintAppId)
    if (-not (Test-AgentIdCoverageUsable $Ctx.Snapshot 'AgentIdentities')) {
        return 'every agent identity created from this blueprint'
    }
    $count = 0
    if ($Ctx.AgentsByBlueprintAppId.ContainsKey("$BlueprintAppId")) { $count = $Ctx.AgentsByBlueprintAppId["$BlueprintAppId"].Count }
    switch ($count) {
        0 { return 'any agent identity created from this blueprint (none exist yet)' }
        1 { return 'the 1 agent identity created from this blueprint, and any created later' }
        default { return "the $count agent identities created from this blueprint, and any created later" }
    }
}

function Get-AgentIdResourceName {
    param([Parameter(Mandatory)]$Ctx, [string]$ResourceAppId)
    if ($Ctx.ResourceByAppId.ContainsKey("$ResourceAppId")) { return $Ctx.ResourceByAppId[$ResourceAppId].displayName }
    if ($script:AgentIdWellKnownResources.ContainsKey("$ResourceAppId")) { return $script:AgentIdWellKnownResources[$ResourceAppId] }
    return "resource $ResourceAppId"
}

function Test-AgentIdBlockedPermission {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$Row)
    if ($Row.ResourceAppId -ne $script:AgentIdGraphAppId) { return $false }
    $list = if ($Row.PermissionType -eq 'Application') { $Ctx.Blocked.Application } else { $Ctx.Blocked.Delegated }
    return (@($list) -contains $Row.Permission)
}

function Test-AgentIdSensitivePermission {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)][string]$PermissionType, [string]$ResourceAppId, [string]$Permission)
    if (-not $ResourceAppId) { return $false }
    $table = $Ctx.Sensitive[$PermissionType]
    if (-not $table -or -not $table.ContainsKey($ResourceAppId)) { return $false }
    return (@($table[$ResourceAppId]) -contains $Permission)
}

function Get-AgentIdEvaluatedAccessRow {
    # Rows the permission rules should judge. An agent's inherited rows are skipped when its blueprint
    # principal is in the snapshot, because the same access is reported once, on the blueprint principal,
    # rather than repeated for every agent created from it.
    param([Parameter(Mandatory)]$Ctx)
    foreach ($row in $Ctx.AccessRows) {
        if ($row.Source -eq 'Inherited' -and $Ctx.BlueprintPrincipalByAppId.ContainsKey("$($row.BlueprintAppId)")) { continue }
        $row
    }
}

function Get-AgentIdPrincipalLabel {
    param([Parameter(Mandatory)][string]$Kind)
    switch ($Kind) {
        'AgentIdentity' { 'Agent identity' }
        'BlueprintPrincipal' { 'Blueprint principal' }
        'AgentUser' { 'Agent user' }
        default { $Kind }
    }
}

function Format-AgentIdPermissionList {
    param([Parameter(Mandatory)]$Ctx, [Parameter(Mandatory)]$Rows)
    $parts = foreach ($r in $Rows) {
        $resource = if ($r.ResourceName) { $r.ResourceName } else { Get-AgentIdResourceName $Ctx $r.ResourceAppId }
        $suffix = if ($r.Source -eq 'Inherited') { ', inherited' } else { '' }
        "$($r.Permission) ($resource$suffix)"
    }
    return (@($parts) | Sort-Object -Unique) -join ', '
}

function Get-AgentIdAgentMissingSecurityAttribute {
    # For each agent identity, the given 'Set.Attribute' names it holds no value for. An agent whose attributes
    # could not be read ($null) is skipped: unknown is not the same as missing.
    param([Parameter(Mandatory)]$Ctx, [string[]]$Name)
    foreach ($agent in @($Ctx.Snapshot.AgentIdentities)) {
        if (-not $agent -or $null -eq $agent.securityAttributes) { continue }
        $missing = @($Name | Where-Object { $_ -notin @($agent.securityAttributes) })
        if ($missing) { [pscustomobject]@{ Agent = $agent; Missing = $missing } }
    }
}

function Invoke-AgentIdRuleEvaluation {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [datetimeoffset]$AsOf,
        [Parameter(Mandatory)][hashtable]$Options,
        [string[]]$IncludeRuleId,
        [string[]]$ExcludeRuleId
    )
    if (-not $AsOf) {
        $collected = ConvertTo-AgentIdDate $Snapshot.CollectedAt
        $AsOf = if ($collected) { $collected } else { [datetimeoffset]::UtcNow }
    }
    $ctx = New-AgentIdContext -Snapshot $Snapshot -AsOf $AsOf -Options $Options
    $findings = [System.Collections.Generic.List[object]]::new()
    $notEvaluated = [System.Collections.Generic.List[object]]::new()

    foreach ($rule in $script:AgentIdRules) {
        if ($IncludeRuleId -and -not ($IncludeRuleId | Where-Object { $rule.Id -like $_ })) { continue }
        if ($ExcludeRuleId -and ($ExcludeRuleId | Where-Object { $rule.Id -like $_ })) { continue }
        # A rule that needs configuration (e.g. a list of attribute names) is left out entirely, not reported as
        # not evaluated, until it has been configured.
        if ($rule.ContainsKey('Applies') -and -not (& $rule.Applies $ctx)) { continue }

        $blocking = foreach ($key in $rule.Requires) {
            $entry = $Snapshot.Coverage.$key
            $status = if ($entry) { $entry.Status } else { 'NotCollected' }
            if ($status -notin 'Ok', 'Partial') {
                $text = "$key $status"
                if ($entry.Detail) { $text += " ($($entry.Detail))" }
                $text
            }
        }
        if ($blocking) {
            $notEvaluated.Add([pscustomobject]@{
                    PSTypeName = 'AgentIdAudit.NotEvaluated'
                    RuleId     = $rule.Id
                    Title      = $rule.Title
                    Reason     = ($blocking -join '; ')
                })
            continue
        }
        try {
            foreach ($f in @(& $rule.Evaluate $ctx $rule)) { if ($f) { $findings.Add($f) } }
        } catch {
            $notEvaluated.Add([pscustomobject]@{
                    PSTypeName = 'AgentIdAudit.NotEvaluated'
                    RuleId     = $rule.Id
                    Title      = $rule.Title
                    Reason     = "Rule failed: $($_.Exception.Message)"
                })
        }
    }

    $sorted = @($findings | Sort-Object -Property @{ Expression = { Get-AgentIdSeverityRank $_.Severity }; Descending = $true }, RuleId, ObjectName)
    return @{
        Findings     = $sorted
        NotEvaluated = @($notEvaluated)
        Context      = $ctx
    }
}
