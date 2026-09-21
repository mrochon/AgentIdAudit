function Get-AgentIdInventory {
    <#
    .SYNOPSIS
    Collects a read-only snapshot of the agent identities in the connected tenant.

    .DESCRIPTION
    Reads agent identity blueprints, blueprint principals, agent identities and agent users, together with
    their credentials (metadata only - never secret values), sponsors, owners, direct and inherited permission
    grants, directory role assignments, recent sign-in activity and Identity Protection risk.

    Every call is a GET. Anything that can't be read (missing permission, feature not available in the tenant)
    is recorded in the snapshot's Coverage section, and checks that depend on it are reported as not evaluated.

    The snapshot is plain data: save it with Export-AgentIdSnapshot and analyze it later, on another machine,
    with Get-AgentIdFinding or Export-AgentIdReport.

    .PARAMETER GraphVersion
    Microsoft Graph API version. The Agent ID APIs are documented under beta. Default: beta.

    .PARAMETER SkipSignInActivity
    Don't read sign-in activity (needs AuditLog.Read.All and a Microsoft Entra ID P1 or P2 license).

    .PARAMETER SkipRisk
    Don't read Identity Protection risky agents (needs IdentityRiskyAgent.Read.All).

    .EXAMPLE
    Connect-AgentIdAudit
    $snapshot = Get-AgentIdInventory
    Export-AgentIdSnapshot -Snapshot $snapshot -Path .\contoso-agents.json
    #>
    [CmdletBinding()]
    [OutputType('AgentIdAudit.Snapshot')]
    param(
        [ValidateSet('beta', 'v1.0')][string]$GraphVersion = 'beta',
        [switch]$SkipSignInActivity,
        [switch]$SkipRisk
    )

    Test-AgentIdConnection
    $script:AgentIdGraphVersion = $GraphVersion
    $cov = New-AgentIdCoverage
    $activity = 'Collecting agent identity inventory'

    # ---------------------------------------------------------------- Tenant
    $tenantId = $null; $tenantName = $null
    $r = Invoke-AgentIdStep $cov 'Tenant' { Invoke-AgentIdGraphRequest -All -Uri 'organization?$select=id,displayName' }
    if ($r.Ok -and $r.Value.Count) { $tenantId = $r.Value[0].id; $tenantName = $r.Value[0].displayName }
    if (-not $tenantId -and -not $script:AgentIdGraphHandler) { $tenantId = (Get-MgContext).TenantId }

    # ---------------------------------------------------------------- Blueprints
    Write-Progress -Activity $activity -Status 'Blueprints'
    $blueprintKeys = 'BlueprintFederatedCredentials', 'BlueprintInheritablePermissions', 'BlueprintSponsors', 'BlueprintOwners'
    $blueprints = @()
    $r = Invoke-AgentIdStep $cov 'Blueprints' { Invoke-AgentIdGraphRequest -All -Uri 'applications/microsoft.graph.agentIdentityBlueprint' }
    if ($r.Ok) {
        Initialize-AgentIdCoverage $cov $blueprintKeys
        $i = 0
        $blueprints = @(foreach ($raw in $r.Value) {
                $i++
                Write-Progress -Activity $activity -Status "Blueprint $i of $($r.Value.Count): $($raw.displayName)" -PercentComplete (100 * $i / [math]::Max(1, $r.Value.Count))
                $id = $raw.id
                $fic = Invoke-AgentIdStep $cov 'BlueprintFederatedCredentials' { Invoke-AgentIdGraphRequest -All -Uri "applications/$id/federatedIdentityCredentials" }
                $inh = Invoke-AgentIdStep $cov 'BlueprintInheritablePermissions' { Invoke-AgentIdGraphRequest -All -Uri "applications/$id/microsoft.graph.agentIdentityBlueprint/inheritablePermissions" }
                $spn = Invoke-AgentIdStep $cov 'BlueprintSponsors' { Invoke-AgentIdGraphRequest -All -Uri "applications/$id/microsoft.graph.agentIdentityBlueprint/sponsors" }
                $own = Invoke-AgentIdStep $cov 'BlueprintOwners' { Invoke-AgentIdGraphRequest -All -Uri "applications/$id/owners" }
                [ordered]@{
                    id                           = $id
                    appId                        = $raw.appId
                    displayName                  = $raw.displayName
                    createdDateTime              = ConvertTo-AgentIdDateString $raw.createdDateTime
                    signInAudience               = $raw.signInAudience
                    disabledByMicrosoftStatus    = $raw.disabledByMicrosoftStatus
                    identifierUris               = @($raw.identifierUris)
                    tags                         = @($raw.tags)
                    managerApplications          = @($raw.managerApplications | Where-Object { $_ })
                    passwordCredentials          = @(ConvertTo-AgentIdCredential $raw.passwordCredentials -Kind Secret)
                    keyCredentials               = @(ConvertTo-AgentIdCredential $raw.keyCredentials -Kind Certificate)
                    federatedIdentityCredentials = if ($fic.Ok) { ,@(ConvertTo-AgentIdFederatedCredential $fic.Value) } else { $null }
                    inheritablePermissions       = if ($inh.Ok) { ,@(ConvertTo-AgentIdInheritablePermission $inh.Value) } else { $null }
                    sponsors                     = if ($spn.Ok) { ,@(ConvertTo-AgentIdDirectoryObjectRef $spn.Value) } else { $null }
                    owners                       = if ($own.Ok) { ,@(ConvertTo-AgentIdDirectoryObjectRef $own.Value) } else { $null }
                }
            })
    } else {
        foreach ($k in $blueprintKeys) { Add-AgentIdCoverage $cov $k Skipped 'Blueprints could not be read.' }
    }

    # ---------------------------------------------------------------- Blueprint principals
    Write-Progress -Activity $activity -Status 'Blueprint principals'
    $blueprintPrincipals = @()
    $r = Invoke-AgentIdStep $cov 'BlueprintPrincipals' { Invoke-AgentIdGraphRequest -All -Uri 'servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal' }
    if ($r.Ok) {
        Initialize-AgentIdCoverage $cov 'BlueprintPrincipalGrants'
        $blueprintPrincipals = @(foreach ($raw in $r.Value) {
                $id = $raw.id
                $ara = Invoke-AgentIdStep $cov 'BlueprintPrincipalGrants' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/$id/appRoleAssignments" }
                $grt = Invoke-AgentIdStep $cov 'BlueprintPrincipalGrants' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/$id/oauth2PermissionGrants" }
                [ordered]@{
                    id                     = $id
                    appId                  = $raw.appId
                    displayName            = $raw.displayName
                    accountEnabled         = $raw.accountEnabled
                    createdDateTime        = ConvertTo-AgentIdDateString $raw.createdDateTime
                    appRoleAssignments     = if ($ara.Ok) { ,@(ConvertTo-AgentIdAppRoleAssignment $ara.Value) } else { $null }
                    oauth2PermissionGrants = if ($grt.Ok) { ,@(ConvertTo-AgentIdPermissionGrant $grt.Value) } else { $null }
                }
            })
    } else {
        Add-AgentIdCoverage $cov 'BlueprintPrincipalGrants' Skipped 'Blueprint principals could not be read.'
    }

    # ---------------------------------------------------------------- Agent identities
    Write-Progress -Activity $activity -Status 'Agent identities'
    $agentKeys = 'AgentSponsors', 'AgentOwners', 'AgentGrants', 'AgentInheritedGrants'
    $agents = @()
    # Try to fetch sponsors in the same call. Any failure of the $expand variant - unsupported, or denied because
    # sponsors need more privilege than the list - falls back to the plain list, which must not be lost.
    $expanded = $null
    try {
        $expanded = @(Invoke-AgentIdGraphRequest -All -Uri 'servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors')
    } catch {
        Write-Verbose "Listing agent identities with sponsors expanded failed; retrying without. $($_.Exception.Message)"
    }
    if ($null -ne $expanded) {
        Add-AgentIdCoverage $cov 'AgentIdentities' Ok
        $r = @{ Ok = $true; Value = $expanded }
    } else {
        $r = Invoke-AgentIdStep $cov 'AgentIdentities' { Invoke-AgentIdGraphRequest -All -Uri 'servicePrincipals/microsoft.graph.agentIdentity' }
    }
    if ($r.Ok) {
        Initialize-AgentIdCoverage $cov $agentKeys
        $i = 0
        $agents = @(foreach ($raw in $r.Value) {
                $i++
                Write-Progress -Activity $activity -Status "Agent identity $i of $($r.Value.Count): $($raw.displayName)" -PercentComplete (100 * $i / [math]::Max(1, $r.Value.Count))
                $id = $raw.id
                if (Test-AgentIdProperty $raw 'sponsors') {
                    Add-AgentIdCoverage $cov 'AgentSponsors' Ok
                    $sponsors = @(ConvertTo-AgentIdDirectoryObjectRef $raw.sponsors)
                } else {
                    # Microsoft documents this call as requiring AgentIdentity.ReadWrite.All; a read-only
                    # connection may be denied, in which case sponsor checks are reported as not evaluated.
                    $spn = Invoke-AgentIdStep $cov 'AgentSponsors' {
                        Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/$id/microsoft.graph.agentIdentity/sponsors?`$select=id,displayName,userPrincipalName,accountEnabled", "servicePrincipals/$id/microsoft.graph.agentIdentity/sponsors"
                    }
                    $sponsors = if ($spn.Ok) { ,@(ConvertTo-AgentIdDirectoryObjectRef $spn.Value) } else { $null }
                }
                $own = Invoke-AgentIdStep $cov 'AgentOwners' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/$id/owners" }
                $ara = Invoke-AgentIdStep $cov 'AgentGrants' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/$id/appRoleAssignments" }
                $grt = Invoke-AgentIdStep $cov 'AgentGrants' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/$id/oauth2PermissionGrants" }
                $iar = Invoke-AgentIdStep $cov 'AgentInheritedGrants' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedAppRoleAssignments" }
                $igr = Invoke-AgentIdStep $cov 'AgentInheritedGrants' { Invoke-AgentIdGraphRequest -All -Uri "servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedOauth2PermissionGrants" }
                # appId is inherited from servicePrincipal; some responses have also carried 'agentAppId'.
                $appId = if ($raw.appId) { $raw.appId } else { $raw.agentAppId }
                [ordered]@{
                    id                              = $id
                    appId                           = $appId
                    displayName                     = $raw.displayName
                    agentIdentityBlueprintId        = $raw.agentIdentityBlueprintId
                    accountEnabled                  = $raw.accountEnabled
                    createdDateTime                 = ConvertTo-AgentIdDateString $raw.createdDateTime
                    createdByAppId                  = $raw.createdByAppId
                    disabledByMicrosoftStatus       = $raw.disabledByMicrosoftStatus
                    servicePrincipalType            = $raw.servicePrincipalType
                    tags                            = @($raw.tags)
                    passwordCredentials             = if (Test-AgentIdProperty $raw 'passwordCredentials') { ,@(ConvertTo-AgentIdCredential $raw.passwordCredentials -Kind Secret) } else { $null }
                    keyCredentials                  = if (Test-AgentIdProperty $raw 'keyCredentials') { ,@(ConvertTo-AgentIdCredential $raw.keyCredentials -Kind Certificate) } else { $null }
                    sponsors                        = $sponsors
                    owners                          = if ($own.Ok) { ,@(ConvertTo-AgentIdDirectoryObjectRef $own.Value) } else { $null }
                    appRoleAssignments              = if ($ara.Ok) { ,@(ConvertTo-AgentIdAppRoleAssignment $ara.Value) } else { $null }
                    oauth2PermissionGrants          = if ($grt.Ok) { ,@(ConvertTo-AgentIdPermissionGrant $grt.Value) } else { $null }
                    inheritedAppRoleAssignments     = if ($iar.Ok) { ,@(ConvertTo-AgentIdAppRoleAssignment $iar.Value) } else { $null }
                    inheritedOauth2PermissionGrants = if ($igr.Ok) { ,@(ConvertTo-AgentIdPermissionGrant $igr.Value) } else { $null }
                }
            })
    } else {
        foreach ($k in $agentKeys) { Add-AgentIdCoverage $cov $k Skipped 'Agent identities could not be read.' }
    }

    # ---------------------------------------------------------------- Agent users
    Write-Progress -Activity $activity -Status 'Agent users'
    $agentUsers = @()
    $r = Invoke-AgentIdStep $cov 'AgentUsers' {
        Invoke-AgentIdGraphRequest -All -Uri @(
            'users/microsoft.graph.agentUser?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,identityParentId'
            'users/microsoft.graph.agentUser'
            'users/microsoft.graph.AgentUser'
        )
    }
    if ($r.Ok) {
        Initialize-AgentIdCoverage $cov 'AgentUserSponsors'
        $agentUsers = @(foreach ($raw in $r.Value) {
                $id = $raw.id
                $spn = Invoke-AgentIdStep $cov 'AgentUserSponsors' {
                    Invoke-AgentIdGraphRequest -All -Uri "users/$id/sponsors?`$select=id,displayName,userPrincipalName,accountEnabled", "users/$id/sponsors"
                }
                [ordered]@{
                    id                = $id
                    displayName       = $raw.displayName
                    userPrincipalName = $raw.userPrincipalName
                    accountEnabled    = $raw.accountEnabled
                    createdDateTime   = ConvertTo-AgentIdDateString $raw.createdDateTime
                    identityParentId  = $raw.identityParentId
                    sponsors          = if ($spn.Ok) { ,@(ConvertTo-AgentIdDirectoryObjectRef $spn.Value) } else { $null }
                }
            })
    } else {
        Add-AgentIdCoverage $cov 'AgentUserSponsors' Skipped 'Agent users could not be read.'
    }

    # ---------------------------------------------------------------- Directory roles
    Write-Progress -Activity $activity -Status 'Directory role assignments'
    $principalIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($o in @($agents) + @($agentUsers) + @($blueprintPrincipals)) { if ($o) { [void]$principalIds.Add($o.id) } }
    $roleAssignments = @()
    if ($principalIds.Count -eq 0) {
        Initialize-AgentIdCoverage $cov 'DirectoryRoles'
    } else {
        $r = Invoke-AgentIdStep $cov 'DirectoryRoles' { Invoke-AgentIdGraphRequest -All -Uri 'roleManagement/directory/roleAssignments?$expand=roleDefinition' }
        if ($r.Ok) {
            $roleAssignments = @(foreach ($ra in $r.Value) {
                    if (-not $principalIds.Contains("$($ra.principalId)")) { continue }
                    [ordered]@{
                        id               = $ra.id
                        principalId      = $ra.principalId
                        roleDefinitionId = $ra.roleDefinitionId
                        roleName         = $ra.roleDefinition.displayName
                        roleTemplateId   = $ra.roleDefinition.templateId
                        isPrivileged     = $ra.roleDefinition.isPrivileged
                        isBuiltIn        = $ra.roleDefinition.isBuiltIn
                        directoryScopeId = $ra.directoryScopeId
                    }
                })
        }
    }

    # ---------------------------------------------------------------- Resources named in grants
    Write-Progress -Activity $activity -Status 'Resolving permission names'
    $resourceIds = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($o in @($agents) + @($blueprintPrincipals)) {
        if (-not $o) { continue }
        foreach ($list in $o.appRoleAssignments, $o.oauth2PermissionGrants, $o.inheritedAppRoleAssignments, $o.inheritedOauth2PermissionGrants) {
            foreach ($item in @($list)) { if ($item -and $item.resourceId) { [void]$resourceIds.Add($item.resourceId) } }
        }
    }
    Initialize-AgentIdCoverage $cov 'Resources'
    $resources = @(foreach ($rid in $resourceIds) {
            $res = Invoke-AgentIdStep $cov 'Resources' { Invoke-AgentIdGraphRequest -Uri "servicePrincipals/$($rid)?`$select=id,appId,displayName,appRoles" }
            if ($res.Ok -and $res.Value.Count) { ConvertTo-AgentIdResource $res.Value[0] }
        })

    # ---------------------------------------------------------------- Sign-in activity
    $signIns = @()
    if ($SkipSignInActivity) {
        Add-AgentIdCoverage $cov 'SignInActivity' Skipped 'Skipped with -SkipSignInActivity.'
    } else {
        Write-Progress -Activity $activity -Status 'Sign-in activity'
        Initialize-AgentIdCoverage $cov 'SignInActivity'
        $appIds = @(@($agents) | Where-Object { $_ -and $_.appId } | ForEach-Object { $_.appId } | Sort-Object -Unique)
        $signIns = @(foreach ($appId in $appIds) {
                $filter = [uri]::EscapeDataString("appId eq '$appId'")
                $s = Invoke-AgentIdStep $cov 'SignInActivity' { Invoke-AgentIdGraphRequest -All -Uri "reports/servicePrincipalSignInActivities?`$filter=$filter" }
                if (-not $s.Ok) { continue }
                # An entry is written for every successful lookup, so "no entry" means "unknown", while an entry with
                # a null date means "looked, and found no sign-in".
                $dates = foreach ($entry in $s.Value) {
                    foreach ($prop in 'lastSignInActivity', 'applicationAuthenticationClientSignInActivity', 'delegatedClientSignInActivity', 'applicationAuthenticationResourceSignInActivity', 'delegatedResourceSignInActivity') {
                        $d = ConvertTo-AgentIdDate $entry.$prop.lastSignInDateTime
                        if ($d) { $d }
                    }
                }
                $latest = $dates | Sort-Object -Descending | Select-Object -First 1
                [ordered]@{ appId = $appId; lastSignInDateTime = if ($latest) { $latest.UtcDateTime.ToString('o') } else { $null } }
            })
    }

    # ---------------------------------------------------------------- Identity Protection
    $risky = @()
    if ($SkipRisk) {
        Add-AgentIdCoverage $cov 'RiskyAgents' Skipped 'Skipped with -SkipRisk.'
    } else {
        Write-Progress -Activity $activity -Status 'Identity Protection'
        $r = Invoke-AgentIdStep $cov 'RiskyAgents' { Invoke-AgentIdGraphRequest -All -Uri 'identityProtection/riskyAgents' -Headers @{ Prefer = 'include-unknown-enum-members' } }
        if ($r.Ok) {
            $risky = @(foreach ($x in $r.Value) {
                    [ordered]@{
                        id                       = $x.id
                        agentDisplayName         = $x.agentDisplayName
                        identityType             = $x.identityType
                        blueprintId              = $x.blueprintId
                        riskLevel                = $x.riskLevel
                        riskState                = $x.riskState
                        riskDetail               = $x.riskDetail
                        riskLastModifiedDateTime = ConvertTo-AgentIdDateString $x.riskLastModifiedDateTime
                        isEnabled                = $x.isEnabled
                        isDeleted                = $x.isDeleted
                    }
                })
        }
    }
    Write-Progress -Activity $activity -Completed

    $snapshot = [ordered]@{
        SchemaVersion            = $script:AgentIdSchemaVersion
        Tool                     = 'AgentIdAudit'
        ToolVersion              = $script:AgentIdModuleVersion
        GraphVersion             = $GraphVersion
        TenantId                 = $tenantId
        TenantName               = $tenantName
        CollectedAt              = [datetime]::UtcNow.ToString('o')
        Coverage                 = Complete-AgentIdCoverage $cov
        Blueprints               = $blueprints
        BlueprintPrincipals      = $blueprintPrincipals
        AgentIdentities          = $agents
        AgentUsers               = $agentUsers
        DirectoryRoleAssignments = $roleAssignments
        Resources                = $resources
        SignInActivity           = $signIns
        RiskyAgents              = $risky
    }
    # A JSON round trip gives a live snapshot exactly the same shape as one loaded with Import-AgentIdSnapshot,
    # so the rules only ever have to handle one form.
    return ConvertTo-AgentIdSnapshotObject ($snapshot | ConvertTo-Json -Depth 32 -Compress)
}
