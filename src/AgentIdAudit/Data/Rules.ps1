# Audit rules. Each rule declares the coverage keys it needs (Requires); if any of them wasn't collected, the
# rule is reported as not evaluated rather than run on incomplete data. Severity is the rule's maximum; some
# rules emit individual findings at a lower severity. Evaluate receives ($Ctx, $Rule) and writes findings
# created with New-AgentIdFinding.

$ref = @{
    BlueprintCredentials = 'https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/create-blueprint?tabs=microsoft-graph-api#configure-credentials-for-the-agent-identity-blueprint'
    BlockedPermissions   = 'https://learn.microsoft.com/en-us/graph/api/resources/agentid-platform-overview?view=graph-rest-beta#microsoft-graph-permissions-blocked-for-agents'
    Sponsors             = 'https://learn.microsoft.com/en-us/entra/agent-id/identity-platform/agent-owners-sponsors-managers'
    Governance           = 'https://learn.microsoft.com/en-us/entra/id-governance/agent-id-governance-overview'
    Inheritable          = 'https://learn.microsoft.com/en-us/graph/api/resources/inheritablepermission?view=graph-rest-beta'
    Risk                 = 'https://learn.microsoft.com/en-us/graph/api/resources/riskyagent?view=graph-rest-beta'
    PrivilegedRoles      = 'https://learn.microsoft.com/en-us/entra/identity/role-based-access-control/privileged-roles-permissions'
    Consent              = 'https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/manage-application-permissions'
    Blueprint            = 'https://learn.microsoft.com/en-us/graph/api/resources/agentidentityblueprint?view=graph-rest-beta'
    AgentUser            = 'https://learn.microsoft.com/en-us/graph/api/resources/agentuser?view=graph-rest-beta'
}

@(
    # ------------------------------------------------------------------ Credentials
    @{
        Id          = 'AID-CRED-001'
        Severity    = 'High'
        Category    = 'Credentials'
        Title       = 'Blueprint authenticates with a client secret'
        Requires    = @('Blueprints')
        Reference   = $ref.BlueprintCredentials
        Remediation = 'Replace the secret with a federated identity credential (for example, a managed identity) or a certificate kept in a key vault, then remove the secret.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                $active = @(Get-AgentIdActiveCredential $Ctx $bp.passwordCredentials)
                if (-not $active) { continue }
                $who = Get-AgentIdBlueprintAgentText $Ctx $bp.appId
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ("{0} active client secret(s). A blueprint credential is a master key: anyone holding a copy of the secret can request tokens for {1}." -f $active.Count, $who)
            }
        }
    }
    @{
        Id          = 'AID-CRED-002'
        Severity    = 'Medium'
        Category    = 'Credentials'
        Title       = 'Long-lived blueprint credential'
        Requires    = @('Blueprints')
        Reference   = $ref.BlueprintCredentials
        Remediation = 'Issue credentials with a lifetime that matches your rotation policy, or move to a federated identity credential, which has no expiry to manage.'
        Evaluate    = {
            param($Ctx, $Rule)
            $max = $Ctx.Options.MaxCredentialLifetimeDays
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                $long = foreach ($c in @(Get-AgentIdActiveCredential $Ctx (@($bp.passwordCredentials) + @($bp.keyCredentials)))) {
                    $start = ConvertTo-AgentIdDate $c.startDateTime
                    $end = ConvertTo-AgentIdDate $c.endDateTime
                    if ($start -and $end) {
                        $days = [int][math]::Floor(($end - $start).TotalDays)
                        if ($days -gt $max) { '{0}, valid for {1:N0} days until {2}' -f (Format-AgentIdCredential $c), $days, (Format-AgentIdDate $c.endDateTime) }
                    }
                }
                if (-not $long) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ("Credential lifetime exceeds {0} days: {1}." -f $max, ($long -join '; '))
            }
        }
    }
    @{
        Id          = 'AID-CRED-003'
        Severity    = 'Low'
        Category    = 'Credentials'
        Title       = 'Expired credentials still attached to blueprint'
        Requires    = @('Blueprints')
        Reference   = $ref.BlueprintCredentials
        Remediation = 'Remove expired credentials so the credential list shows only what is actually in use.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                $expired = @(Get-AgentIdExpiredCredential $Ctx (@($bp.passwordCredentials) + @($bp.keyCredentials)))
                if (-not $expired) { continue }
                $list = ($expired | ForEach-Object { '{0}, expired {1}' -f (Format-AgentIdCredential $_), (Format-AgentIdDate $_.endDateTime) }) -join '; '
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ("{0} expired credential(s): {1}." -f $expired.Count, $list)
            }
        }
    }
    @{
        Id          = 'AID-CRED-004'
        Severity    = 'Low'
        Category    = 'Credentials'
        Title       = 'Blueprint has multiple active credentials'
        Requires    = @('Blueprints')
        Reference   = $ref.BlueprintCredentials
        Remediation = 'Keep one active credential, plus a second only during a planned rotation.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                $secrets = @(Get-AgentIdActiveCredential $Ctx $bp.passwordCredentials)
                $certs = @(Get-AgentIdActiveCredential $Ctx $bp.keyCredentials)
                $total = $secrets.Count + $certs.Count
                if ($total -le 1) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ("{0} active credentials ({1} secret(s), {2} certificate(s)). Each one is an independent way to act as {3}." -f $total, $secrets.Count, $certs.Count, (Get-AgentIdBlueprintAgentText $Ctx $bp.appId))
            }
        }
    }
    @{
        Id          = 'AID-CRED-005'
        Severity    = 'Medium'
        Category    = 'Credentials'
        Title       = 'Agent identity has its own credentials'
        Requires    = @('AgentIdentities')
        Reference   = $ref.BlueprintCredentials
        Remediation = 'Confirm why the agent identity carries its own credential. Agents normally obtain tokens through their blueprint; remove credentials that are not required.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($agent in @($Ctx.Snapshot.AgentIdentities)) {
                $active = @(Get-AgentIdActiveCredential $Ctx (@($agent.passwordCredentials) + @($agent.keyCredentials)))
                if (-not $active) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent identity' -ObjectId $agent.id -ObjectName $agent.displayName `
                    -Detail ("{0} active credential(s) on the agent identity itself: {1}. This is a way to act as the agent that bypasses its blueprint." -f $active.Count, (($active | ForEach-Object { Format-AgentIdCredential $_ }) -join ', '))
            }
        }
    }
    @{
        Id          = 'AID-CRED-006'
        Severity    = 'Info'
        Category    = 'Credentials'
        Title       = 'Blueprint credentials expire soon'
        Requires    = @('Blueprints', 'BlueprintFederatedCredentials')
        Reference   = $ref.BlueprintCredentials
        Remediation = 'Add a replacement credential before the current ones expire, or switch to a federated identity credential.'
        Evaluate    = {
            param($Ctx, $Rule)
            $horizon = $Ctx.AsOf.AddDays($Ctx.Options.ExpiringWithinDays)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                if ($null -eq $bp.federatedIdentityCredentials -or @($bp.federatedIdentityCredentials).Count -gt 0) { continue }
                $active = @(Get-AgentIdActiveCredential $Ctx (@($bp.passwordCredentials) + @($bp.keyCredentials)))
                if (-not $active) { continue }
                $ends = @($active | ForEach-Object { ConvertTo-AgentIdDate $_.endDateTime })
                if ($ends -contains $null) { continue }
                $last = ($ends | Measure-Object -Maximum).Maximum
                if ($last -gt $horizon) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ("Every credential expires by {0}. After that, {1} can no longer get tokens." -f $last.UtcDateTime.ToString('yyyy-MM-dd'), (Get-AgentIdBlueprintAgentText $Ctx $bp.appId))
            }
        }
    }

    # ------------------------------------------------------------------ Permissions
    @{
        Id          = 'AID-PERM-001'
        Severity    = 'Critical'
        Category    = 'Permissions'
        Title       = 'Agent holds a permission Microsoft blocks for agents'
        Requires    = @('AgentIdentities', 'AgentGrants', 'BlueprintPrincipals', 'BlueprintPrincipalGrants')
        Reference   = $ref.BlockedPermissions
        Remediation = 'Remove the grant, then establish how it was made: Microsoft blocks these permissions for agents, so the grant predates the block or was made through a path the block does not cover.'
        Evaluate    = {
            param($Ctx, $Rule)
            $rows = @(Get-AgentIdEvaluatedAccessRow $Ctx | Where-Object { Test-AgentIdBlockedPermission $Ctx $_ })
            foreach ($group in ($rows | Group-Object PrincipalId)) {
                $first = $group.Group[0]
                $detail = 'Holds {0}.' -f (Format-AgentIdPermissionList $Ctx $group.Group)
                if ($first.PrincipalKind -eq 'BlueprintPrincipal') { $detail += ' Access granted to a blueprint principal can be inherited by ' + (Get-AgentIdBlueprintAgentText $Ctx $first.BlueprintAppId) + '.' }
                New-AgentIdFinding -Rule $Rule -ObjectType (Get-AgentIdPrincipalLabel $first.PrincipalKind) -ObjectId $first.PrincipalId -ObjectName $first.PrincipalName -Detail $detail
            }
        }
    }
    @{
        Id          = 'AID-PERM-002'
        Severity    = 'High'
        Category    = 'Permissions'
        Title       = 'Agent holds a sensitive application permission'
        Requires    = @('AgentIdentities', 'AgentGrants', 'BlueprintPrincipals', 'BlueprintPrincipalGrants')
        Reference   = $ref.Consent
        Remediation = 'Replace tenant-wide application permissions with delegated access (on behalf of a user), or scope the access down (for example, an Exchange application access policy or SharePoint Sites.Selected).'
        Evaluate    = {
            param($Ctx, $Rule)
            $rows = @(Get-AgentIdEvaluatedAccessRow $Ctx | Where-Object {
                    $_.PermissionType -eq 'Application' -and
                    -not (Test-AgentIdBlockedPermission $Ctx $_) -and
                    (Test-AgentIdSensitivePermission $Ctx 'Application' $_.ResourceAppId $_.Permission)
                })
            foreach ($group in ($rows | Group-Object PrincipalId)) {
                $first = $group.Group[0]
                $detail = 'Application permissions {0}. These apply across the whole tenant, with no user present.' -f (Format-AgentIdPermissionList $Ctx $group.Group)
                if ($first.PrincipalKind -eq 'BlueprintPrincipal') { $detail += ' Access granted to a blueprint principal can be inherited by ' + (Get-AgentIdBlueprintAgentText $Ctx $first.BlueprintAppId) + '.' }
                New-AgentIdFinding -Rule $Rule -ObjectType (Get-AgentIdPrincipalLabel $first.PrincipalKind) -ObjectId $first.PrincipalId -ObjectName $first.PrincipalName -Detail $detail
            }
        }
    }
    @{
        Id          = 'AID-PERM-003'
        Severity    = 'Medium'
        Category    = 'Permissions'
        Title       = 'Sensitive delegated permission consented for all users'
        Requires    = @('AgentIdentities', 'AgentGrants', 'BlueprintPrincipals', 'BlueprintPrincipalGrants')
        Reference   = $ref.Consent
        Remediation = 'Confirm the agent needs these permissions for every user. Where it does not, replace the tenant-wide (AllPrincipals) grant with per-user consent or narrower scopes.'
        Evaluate    = {
            param($Ctx, $Rule)
            $rows = @(Get-AgentIdEvaluatedAccessRow $Ctx | Where-Object {
                    $_.PermissionType -eq 'Delegated' -and $_.ConsentType -eq 'AllPrincipals' -and
                    -not (Test-AgentIdBlockedPermission $Ctx $_) -and
                    (Test-AgentIdSensitivePermission $Ctx 'Delegated' $_.ResourceAppId $_.Permission)
                })
            foreach ($group in ($rows | Group-Object PrincipalId)) {
                $first = $group.Group[0]
                $detail = 'Delegated permissions {0}, consented for all users. The agent can use them on behalf of any user, without that user being asked.' -f (Format-AgentIdPermissionList $Ctx $group.Group)
                if ($first.PrincipalKind -eq 'BlueprintPrincipal') { $detail += ' Access granted to a blueprint principal can be inherited by ' + (Get-AgentIdBlueprintAgentText $Ctx $first.BlueprintAppId) + '.' }
                New-AgentIdFinding -Rule $Rule -ObjectType (Get-AgentIdPrincipalLabel $first.PrincipalKind) -ObjectId $first.PrincipalId -ObjectName $first.PrincipalName -Detail $detail
            }
        }
    }
    @{
        Id          = 'AID-PERM-004'
        Severity    = 'High'
        Category    = 'Permissions'
        Title       = 'Blueprint lets agents inherit broad delegated permissions'
        Requires    = @('Blueprints', 'BlueprintInheritablePermissions')
        Reference   = $ref.Inheritable
        Remediation = 'List the specific scopes agents need (enumerated) instead of allowing all of them, and keep sensitive scopes off the inheritable list.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                if ($null -eq $bp.inheritablePermissions) { continue }
                $who = Get-AgentIdBlueprintAgentText $Ctx $bp.appId
                foreach ($p in @($bp.inheritablePermissions)) {
                    if (-not $p) { continue }
                    $resource = Get-AgentIdResourceName $Ctx $p.resourceAppId
                    if ($p.kind -eq 'allAllowed') {
                        New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName -Severity 'High' `
                            -Detail ("Inherits all delegated permissions of {0} that the blueprint is granted, without further consent, for {1}." -f $resource, $who)
                        continue
                    }
                    $sensitive = @($p.scopes | Where-Object { Test-AgentIdSensitivePermission $Ctx 'Delegated' $p.resourceAppId $_ })
                    if ($sensitive) {
                        New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName -Severity 'Medium' `
                            -Detail ("Sensitive inheritable scopes of {0}: {1}, inherited without further consent by {2}." -f $resource, ($sensitive -join ', '), $who)
                    }
                }
            }
        }
    }
    @{
        Id          = 'AID-PERM-005'
        Severity    = 'Critical'
        Category    = 'Permissions'
        Title       = 'Agent holds a directory role'
        Requires    = @('AgentIdentities', 'BlueprintPrincipals', 'AgentUsers', 'DirectoryRoles')
        Reference   = $ref.PrivilegedRoles
        Remediation = 'Remove directory roles from agents. Where an agent must administer something, use the narrowest role available, scope it to an administrative unit, and make the assignment time-bound.'
        Evaluate    = {
            param($Ctx, $Rule)
            $principals = @{}
            foreach ($a in @($Ctx.Snapshot.AgentIdentities)) { if ($a) { $principals[$a.id] = @('Agent identity', $a.displayName) } }
            foreach ($u in @($Ctx.Snapshot.AgentUsers)) { if ($u) { $principals[$u.id] = @('Agent user', $u.displayName) } }
            foreach ($p in @($Ctx.Snapshot.BlueprintPrincipals)) { if ($p) { $principals[$p.id] = @('Blueprint principal', $p.displayName) } }
            $fallback = $Ctx.Sensitive.PrivilegedRoleTemplateIds
            $assignments = @($Ctx.Snapshot.DirectoryRoleAssignments | Where-Object { $_ -and $principals.ContainsKey("$($_.principalId)") })
            foreach ($group in ($assignments | Group-Object principalId)) {
                $info = $principals[$group.Name]
                $privileged = $false
                $roles = foreach ($ra in $group.Group) {
                    $isPriv = ($ra.isPrivileged -eq $true) -or ($ra.roleTemplateId -and $fallback.ContainsKey("$($ra.roleTemplateId)"))
                    if ($isPriv) { $privileged = $true }
                    $scope = if (-not $ra.directoryScopeId -or $ra.directoryScopeId -eq '/') { 'tenant-wide' } else { "scope $($ra.directoryScopeId)" }
                    $label = if ($isPriv) { 'privileged, ' } else { '' }
                    "$($ra.roleName) ($label$scope)"
                }
                $sev = if ($privileged) { 'Critical' } else { 'Medium' }
                New-AgentIdFinding -Rule $Rule -ObjectType $info[0] -ObjectId $group.Name -ObjectName $info[1] -Severity $sev `
                    -Detail ('Directory roles: {0}.' -f ($roles -join ', '))
            }
        }
    }

    # ------------------------------------------------------------------ Governance
    @{
        Id          = 'AID-GOV-001'
        Severity    = 'Medium'
        Category    = 'Governance'
        Title       = 'Agent identity has no sponsor'
        Requires    = @('AgentIdentities', 'AgentSponsors')
        Reference   = $ref.Sponsors
        Remediation = 'Assign a sponsor: a person accountable for the agent''s access and lifecycle. If no one will take that on, disable the agent.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($agent in @($Ctx.Snapshot.AgentIdentities)) {
                if ($null -eq $agent.sponsors -or @($agent.sponsors).Count -gt 0) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent identity' -ObjectId $agent.id -ObjectName $agent.displayName `
                    -Detail 'No sponsor is assigned, so no person is accountable for this agent. A sponsor is required when an agent identity is created, so the original sponsor was most likely removed or deleted.'
            }
        }
    }
    @{
        Id          = 'AID-GOV-002'
        Severity    = 'Medium'
        Category    = 'Governance'
        Title       = 'Sponsor account is disabled'
        Requires    = @('AgentSponsors')
        Reference   = $ref.Sponsors
        Remediation = 'Transfer sponsorship to an active person, for example the former sponsor''s manager. Lifecycle workflows can automate this when people leave.'
        Evaluate    = {
            param($Ctx, $Rule)
            $sets = @(
                @('Agent identity', $Ctx.Snapshot.AgentIdentities),
                @('Blueprint', $Ctx.Snapshot.Blueprints),
                @('Agent user', $Ctx.Snapshot.AgentUsers)
            )
            foreach ($set in $sets) {
                foreach ($obj in @($set[1])) {
                    if (-not $obj -or $null -eq $obj.sponsors) { continue }
                    $disabled = @($obj.sponsors | Where-Object { $_ -and $_.accountEnabled -eq $false })
                    if (-not $disabled) { continue }
                    $names = ($disabled | ForEach-Object { if ($_.userPrincipalName) { "$($_.displayName) <$($_.userPrincipalName)>" } else { $_.displayName } }) -join ', '
                    $others = @($obj.sponsors).Count - $disabled.Count
                    $tail = if ($others -eq 0) { ' No active sponsor remains.' } else { " $others other sponsor(s) remain." }
                    New-AgentIdFinding -Rule $Rule -ObjectType $set[0] -ObjectId $obj.id -ObjectName $obj.displayName `
                        -Detail ("Disabled sponsor(s): {0}.{1}" -f $names, $tail)
                }
            }
        }
    }
    @{
        Id          = 'AID-GOV-003'
        Severity    = 'Medium'
        Category    = 'Governance'
        Title       = 'Blueprint has no sponsor'
        Requires    = @('Blueprints', 'BlueprintSponsors')
        Reference   = $ref.Sponsors
        Remediation = 'Assign a sponsor to the blueprint: the person accountable for every agent created from it.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                if ($null -eq $bp.sponsors -or @($bp.sponsors).Count -gt 0) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ('No sponsor is assigned. No person is accountable for {0}.' -f (Get-AgentIdBlueprintAgentText $Ctx $bp.appId))
            }
        }
    }
    @{
        Id          = 'AID-GOV-004'
        Severity    = 'Medium'
        Category    = 'Governance'
        Title       = 'Agent identity''s blueprint is not in this tenant'
        Requires    = @('AgentIdentities', 'BlueprintPrincipals')
        Reference   = $ref.Blueprint
        Remediation = 'Establish whether the agent is still in use. If its blueprint was removed deliberately, delete the agent identity as well.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($agent in @($Ctx.Snapshot.AgentIdentities)) {
                $bpAppId = "$($agent.agentIdentityBlueprintId)"
                if (-not $bpAppId -or $Ctx.BlueprintPrincipalByAppId.ContainsKey($bpAppId)) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent identity' -ObjectId $agent.id -ObjectName $agent.displayName `
                    -Detail ("References blueprint appId {0}, but no blueprint principal with that appId exists in this tenant. The agent is likely orphaned." -f $bpAppId)
            }
        }
    }
    @{
        Id          = 'AID-GOV-005'
        Severity    = 'Low'
        Category    = 'Governance'
        Title       = 'Other applications can create agents from this blueprint'
        Requires    = @('Blueprints')
        Reference   = $ref.Blueprint
        Remediation = 'Confirm each manager application is expected. A manager application can create agent identities and agent users from the blueprint, so treat it as privileged.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                $managers = @($bp.managerApplications | Where-Object { $_ })
                if (-not $managers) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ('{0} manager application(s) can create agent identities from this blueprint: {1}.' -f $managers.Count, ($managers -join ', '))
            }
        }
    }
    @{
        Id          = 'AID-GOV-006'
        Severity    = 'Info'
        Category    = 'Governance'
        Title       = 'Blueprint is available to other tenants'
        Requires    = @('Blueprints')
        Reference   = $ref.Blueprint
        Remediation = 'If agents from this blueprint are only meant for this organization, set signInAudience to AzureADMyOrg.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($bp in @($Ctx.Snapshot.Blueprints)) {
                if (-not $bp.signInAudience -or $bp.signInAudience -eq 'AzureADMyOrg') { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Blueprint' -ObjectId $bp.id -ObjectName $bp.displayName `
                    -Detail ("signInAudience is {0}, so the blueprint can be added to other tenants." -f $bp.signInAudience)
            }
        }
    }
    @{
        Id          = 'AID-GOV-007'
        Severity    = 'High'
        Category    = 'Governance'
        Title       = 'Microsoft has disabled this object'
        Requires    = @('Blueprints')
        Reference   = $ref.Blueprint
        Remediation = 'Investigate the agent''s behavior before taking any other action. Microsoft sets this status for violations of its service agreement, which can include suspicious or malicious activity.'
        Evaluate    = {
            param($Ctx, $Rule)
            $sets = @(@('Blueprint', $Ctx.Snapshot.Blueprints), @('Agent identity', $Ctx.Snapshot.AgentIdentities))
            foreach ($set in $sets) {
                foreach ($obj in @($set[1])) {
                    if (-not $obj -or -not $obj.disabledByMicrosoftStatus -or $obj.disabledByMicrosoftStatus -eq 'NotDisabled') { continue }
                    New-AgentIdFinding -Rule $Rule -ObjectType $set[0] -ObjectId $obj.id -ObjectName $obj.displayName `
                        -Detail ("disabledByMicrosoftStatus is {0}." -f $obj.disabledByMicrosoftStatus)
                }
            }
        }
    }

    # ------------------------------------------------------------------ Agent users
    @{
        Id          = 'AID-USER-001'
        Severity    = 'Medium'
        Category    = 'Agent users'
        Title       = 'Agent user has no sponsor'
        Requires    = @('AgentUsers', 'AgentUserSponsors')
        Reference   = $ref.Sponsors
        Remediation = 'Assign a sponsor to the agent user, or remove the agent user if it is no longer needed.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($u in @($Ctx.Snapshot.AgentUsers)) {
                if ($null -eq $u.sponsors -or @($u.sponsors).Count -gt 0) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent user' -ObjectId $u.id -ObjectName $u.displayName `
                    -Detail ("No sponsor is assigned to agent user {0}." -f $u.userPrincipalName)
            }
        }
    }
    @{
        Id          = 'AID-USER-002'
        Severity    = 'Medium'
        Category    = 'Agent users'
        Title       = 'Agent user''s parent agent identity not found'
        Requires    = @('AgentUsers', 'AgentIdentities')
        Reference   = $ref.AgentUser
        Remediation = 'Establish whether the agent user is still in use. An agent user whose agent identity is gone should be disabled and removed.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($u in @($Ctx.Snapshot.AgentUsers)) {
                $parent = "$($u.identityParentId)"
                if (-not $parent -or $Ctx.AgentById.ContainsKey($parent)) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent user' -ObjectId $u.id -ObjectName $u.displayName `
                    -Detail ("identityParentId {0} does not match any agent identity in this tenant; the agent user is likely orphaned. Enabled: {1}." -f $parent, $u.accountEnabled)
            }
        }
    }

    # ------------------------------------------------------------------ Lifecycle
    @{
        Id          = 'AID-LIFE-001'
        Severity    = 'Medium'
        Category    = 'Lifecycle'
        Title       = 'Agent identity has not signed in recently'
        Requires    = @('AgentIdentities', 'SignInActivity')
        Reference   = $ref.Governance
        Remediation = 'Confirm with the sponsor whether the agent is still needed. Disable or delete unused agents; their permissions remain usable for as long as they exist.'
        Evaluate    = {
            param($Ctx, $Rule)
            $days = $Ctx.Options.StaleAfterDays
            $threshold = $Ctx.AsOf.AddDays(-$days)
            foreach ($agent in @($Ctx.Snapshot.AgentIdentities)) {
                if (-not $agent.appId -or -not $Ctx.SignInByAppId.ContainsKey("$($agent.appId)")) { continue }
                $created = ConvertTo-AgentIdDate $agent.createdDateTime
                if ($created -and $created -gt $threshold) { continue }
                $last = ConvertTo-AgentIdDate $Ctx.SignInByAppId[$agent.appId].lastSignInDateTime
                if ($last -and $last -gt $threshold) { continue }
                $lastText = if ($last) { "last sign-in $($last.UtcDateTime.ToString('yyyy-MM-dd'))" } else { 'no sign-in recorded' }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent identity' -ObjectId $agent.id -ObjectName $agent.displayName `
                    -Detail ("No sign-in in the last {0} days ({1}). Enabled: {2}." -f $days, $lastText, $agent.accountEnabled)
            }
        }
    }
    @{
        Id          = 'AID-LIFE-002'
        Severity    = 'Low'
        Category    = 'Lifecycle'
        Title       = 'Disabled agent identity still holds permissions'
        Requires    = @('AgentIdentities', 'AgentGrants')
        Reference   = $ref.Governance
        Remediation = 'Remove permissions from agents being retired. Re-enabling a disabled agent restores all of its access at once.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($agent in @($Ctx.Snapshot.AgentIdentities)) {
                if ($agent.accountEnabled -ne $false) { continue }
                $direct = @($Ctx.AccessRows | Where-Object { $_.PrincipalId -eq $agent.id -and $_.Source -eq 'Direct' })
                if (-not $direct) { continue }
                New-AgentIdFinding -Rule $Rule -ObjectType 'Agent identity' -ObjectId $agent.id -ObjectName $agent.displayName `
                    -Detail ("Disabled, but still holds {0} direct permission(s): {1}." -f $direct.Count, (Format-AgentIdPermissionList $Ctx $direct))
            }
        }
    }
    @{
        Id          = 'AID-LIFE-003'
        Severity    = 'Critical'
        Category    = 'Lifecycle'
        Title       = 'Identity Protection flags this agent as risky'
        Requires    = @('RiskyAgents')
        Reference   = $ref.Risk
        Remediation = 'Investigate the risk detections for this agent. Disable it while investigating if the risk is confirmed, then confirm or dismiss the risk so policies respond correctly.'
        Evaluate    = {
            param($Ctx, $Rule)
            foreach ($r in @($Ctx.Snapshot.RiskyAgents)) {
                if (-not $r -or $r.riskState -notin 'atRisk', 'confirmedCompromised') { continue }
                $sev = if ($r.riskState -eq 'confirmedCompromised') { 'Critical' } elseif ($r.riskLevel -eq 'high') { 'High' } else { 'Medium' }
                $type = switch ($r.identityType) { 'agentUser' { 'Agent user' } 'agentIdentityBlueprintPrincipal' { 'Blueprint principal' } default { 'Agent identity' } }
                New-AgentIdFinding -Rule $Rule -ObjectType $type -ObjectId $r.id -ObjectName $r.agentDisplayName -Severity $sev `
                    -Detail ("Risk state {0}, risk level {1}, last updated {2}. Detail: {3}." -f $r.riskState, $r.riskLevel, (Format-AgentIdDate $r.riskLastModifiedDateTime), $r.riskDetail)
            }
        }
    }
)
