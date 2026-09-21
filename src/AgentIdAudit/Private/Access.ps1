function Get-AgentIdAccessRow {
    # Flattens the grants in a snapshot into one row per (principal, resource, permission):
    #   - agent identities: direct app role assignments and delegated grants, plus those inherited from the
    #     agent's blueprint principal (Source = 'Inherited')
    #   - blueprint principals: their own assignments and grants, which agent identities can inherit
    param([Parameter(Mandatory)]$Snapshot)

    $resources = @{}
    foreach ($r in @($Snapshot.Resources)) { if ($r) { $resources[$r.id] = $r } }

    $resolveRole = {
        param($resourceId, $appRoleId)
        if ($appRoleId -eq '00000000-0000-0000-0000-000000000000') { return '(default access)' }
        $res = $resources[$resourceId]
        if ($res) {
            $role = @($res.appRoles) | Where-Object { $_.id -eq $appRoleId } | Select-Object -First 1
            if ($role -and $role.value) { return $role.value }
        }
        return "(app role $appRoleId)"
    }

    $emit = {
        param($kind, $principal, $blueprintAppId, $source, $assignments, $grants)
        foreach ($a in @($assignments)) {
            if (-not $a) { continue }
            $res = $resources[$a.resourceId]
            [pscustomobject]@{
                PSTypeName     = 'AgentIdAudit.AccessRow'
                PrincipalKind  = $kind
                PrincipalId    = $principal.id
                PrincipalName  = $principal.displayName
                BlueprintAppId = $blueprintAppId
                PermissionType = 'Application'
                ResourceId     = $a.resourceId
                ResourceAppId  = $res.appId
                ResourceName   = if ($res.displayName) { $res.displayName } else { $a.resourceDisplayName }
                Permission     = & $resolveRole $a.resourceId $a.appRoleId
                ConsentType    = $null
                OnBehalfOf     = $null
                Source         = $source
            }
        }
        foreach ($g in @($grants)) {
            if (-not $g) { continue }
            $res = $resources[$g.resourceId]
            foreach ($scope in ("$($g.scope)" -split '\s+' | Where-Object { $_ })) {
                [pscustomobject]@{
                    PSTypeName     = 'AgentIdAudit.AccessRow'
                    PrincipalKind  = $kind
                    PrincipalId    = $principal.id
                    PrincipalName  = $principal.displayName
                    BlueprintAppId = $blueprintAppId
                    PermissionType = 'Delegated'
                    ResourceId     = $g.resourceId
                    ResourceAppId  = $res.appId
                    ResourceName   = $res.displayName
                    Permission     = $scope
                    ConsentType    = $g.consentType
                    OnBehalfOf     = if ($g.consentType -eq 'Principal') { $g.principalId } else { $null }
                    Source         = $source
                }
            }
        }
    }

    foreach ($bp in @($Snapshot.BlueprintPrincipals)) {
        if (-not $bp) { continue }
        & $emit 'BlueprintPrincipal' $bp $bp.appId 'Direct' $bp.appRoleAssignments $bp.oauth2PermissionGrants
    }
    foreach ($agent in @($Snapshot.AgentIdentities)) {
        if (-not $agent) { continue }
        & $emit 'AgentIdentity' $agent $agent.agentIdentityBlueprintId 'Direct' $agent.appRoleAssignments $agent.oauth2PermissionGrants
        & $emit 'AgentIdentity' $agent $agent.agentIdentityBlueprintId 'Inherited' $agent.inheritedAppRoleAssignments $agent.inheritedOauth2PermissionGrants
    }
}
