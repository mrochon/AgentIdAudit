# A fake Microsoft Graph for tests and sample reports. New-FakeTenant returns routes (relative URI -> response
# or HTTP status code) modeling a small tenant that deliberately contains one instance of most problems the
# rules look for, alongside objects that are clean, so tests catch false positives as well as misses.
#
# Scenarios:
#   A - everything readable; $expand=sponsors unsupported (400), so sponsors are read per agent
#   B - sponsors, Identity Protection and custom security attributes denied (403); the agent list must still be collected
#   C - $expand=sponsors supported, so no per-agent sponsor calls should be made

$script:GraphAppId = '00000003-0000-0000-c000-000000000000'
$script:SpoAppId = '00000003-0000-0ff1-ce00-000000000000'

function ConvertTo-FakeGraphObject {
    # Round-trip through JSON so responses have the same shape Invoke-MgGraphRequest -OutputType PSObject returns.
    param($InputObject)
    $InputObject | ConvertTo-Json -Depth 30 | ConvertFrom-Json -Depth 30
}

function New-FakeTenant {
    param([ValidateSet('A', 'B', 'C')][string]$Scenario = 'A')

    $alice = @{ '@odata.type' = '#microsoft.graph.user'; id = 'user-alice'; displayName = 'Alice Admin'; userPrincipalName = 'alice@contoso.example'; accountEnabled = $true }
    $bob = @{ '@odata.type' = '#microsoft.graph.user'; id = 'user-bob'; displayName = 'Bob Leaver'; userPrincipalName = 'bob@contoso.example'; accountEnabled = $false }

    $blueprints = @(
        @{  # Problems: secret (with a 2299 expiry), expired secret, long-lived cert, manager app, multi-tenant,
            # allAllowed inheritance, no sponsor
            id = 'bp1'; appId = 'bp1-app'; displayName = 'Sales Blueprint'; createdDateTime = '2026-01-01T00:00:00Z'
            signInAudience = 'AzureADMultipleOrgs'; managerApplications = @('mgr-app-1'); identifierUris = @('api://bp1'); tags = @()
            passwordCredentials = @(
                @{ keyId = 'k-secret-1'; displayName = 'my-secret'; hint = 'Q7x'; secretText = 'SUPERSECRET'; startDateTime = '2026-01-01T00:00:00Z'; endDateTime = '2299-12-31T23:59:59Z' }
                @{ keyId = 'k-secret-old'; displayName = 'old-secret'; hint = 'Zz9'; startDateTime = '2025-01-01T00:00:00Z'; endDateTime = '2025-06-01T00:00:00Z' }
            )
            keyCredentials = @(
                @{ keyId = 'k-cert-1'; displayName = 'CN=sales'; type = 'AsymmetricX509Cert'; usage = 'Verify'; key = 'MIIBASE64CERTDATA'; startDateTime = '2026-06-01T00:00:00Z'; endDateTime = '2026-12-01T00:00:00Z' }
            )
        }
        @{  # Clean: one certificate under the lifetime limit, a federated credential, a sponsor, enumerated inheritance
            id = 'bp2'; appId = 'bp2-app'; displayName = 'HR Blueprint'; createdDateTime = '2026-02-01T00:00:00Z'
            signInAudience = 'AzureADMyOrg'; managerApplications = @(); identifierUris = @('api://bp2'); tags = @()
            passwordCredentials = @()
            keyCredentials = @(@{ keyId = 'k-cert-2'; displayName = 'CN=hr'; type = 'AsymmetricX509Cert'; usage = 'Verify'; startDateTime = '2026-06-01T00:00:00Z'; endDateTime = '2026-11-01T00:00:00Z' })
        }
        @{  # Only problem: its only credential expires within 30 days of the evaluation date
            id = 'bp3'; appId = 'bp3-app'; displayName = 'Expiring Blueprint'; createdDateTime = '2026-05-01T00:00:00Z'
            signInAudience = 'AzureADMyOrg'; managerApplications = @(); identifierUris = @(); tags = @()
            passwordCredentials = @()
            keyCredentials = @(@{ keyId = 'k-cert-3'; displayName = 'CN=exp'; type = 'AsymmetricX509Cert'; usage = 'Verify'; startDateTime = '2026-05-01T00:00:00Z'; endDateTime = '2026-10-01T00:00:00Z' })
        }
    )

    $agents = @(
        @{  # Problems: blocked permission, tenant-wide Mail.Read, Global Administrator, no sponsor, stale, risky
            id = 'a1'; appId = 'a1-app'; displayName = 'Sales Agent'; agentIdentityBlueprintId = 'bp1-app'; accountEnabled = $true
            createdDateTime = '2026-01-10T00:00:00Z'; createdByAppId = 'bp1-app'; servicePrincipalType = 'ServiceIdentity'; tags = @()
            passwordCredentials = @(); keyCredentials = @()
        }
        @{  # Clean
            id = 'a2'; appId = 'a2-app'; displayName = 'HR Agent'; agentIdentityBlueprintId = 'bp2-app'; accountEnabled = $true
            createdDateTime = '2026-02-01T00:00:00Z'; servicePrincipalType = 'ServiceIdentity'; tags = @()
            passwordCredentials = @(); keyCredentials = @()
        }
        @{  # Problems: disabled but holds SharePoint Sites.FullControl.All, own credential, disabled sponsor, never signed in
            id = 'a3'; appId = 'a3-app'; displayName = 'Old Agent'; agentIdentityBlueprintId = 'bp2-app'; accountEnabled = $false
            createdDateTime = '2025-01-01T00:00:00Z'; servicePrincipalType = 'ServiceIdentity'; tags = @()
            passwordCredentials = @(@{ keyId = 'k-agent-secret'; displayName = 'agent-secret'; hint = 'Q7x'; startDateTime = '2026-01-01T00:00:00Z'; endDateTime = '2026-12-01T00:00:00Z' })
            keyCredentials = @()
        }
        @{  # Problems: blueprint missing from tenant, disabled by Microsoft. Name is hostile markup (report encoding test).
            id = 'a4'; appId = 'a4-app'; displayName = '<script>alert(1)</script> Orphan Agent'; agentIdentityBlueprintId = 'gone-app'; accountEnabled = $true
            createdDateTime = '2026-08-01T00:00:00Z'; disabledByMicrosoftStatus = 'DisabledDueToViolationOfServicesAgreement'; servicePrincipalType = 'ServiceIdentity'; tags = @()
            passwordCredentials = @(); keyCredentials = @()
        }
    )
    $sponsorsByAgent = @{ a1 = @(); a2 = @($alice); a3 = @($bob); a4 = @($alice) }

    $page = { param($items, $next) $o = @{ value = @($items) }; if ($next) { $o['@odata.nextLink'] = $next }; $o }
    $none = & $page @()
    $role = { param($id, $value) @{ id = $id; value = $value; isEnabled = $true } }

    $r = @{}
    $r['organization?$select=id,displayName'] = & $page @(@{ id = 'tenant-1'; displayName = 'Contoso (sample data)' })

    # Blueprints and their related collections
    $r['applications/microsoft.graph.agentIdentityBlueprint'] = & $page $blueprints
    $r['applications/bp1/federatedIdentityCredentials'] = $none
    $r['applications/bp2/federatedIdentityCredentials'] = & $page @(@{ id = 'fic-1'; name = 'hr-mi'; issuer = 'https://login.microsoftonline.com/tenant-1/v2.0'; subject = 'mi-object-id'; audiences = @('api://AzureADTokenExchange') })
    $r['applications/bp3/federatedIdentityCredentials'] = $none
    $r['applications/bp1/microsoft.graph.agentIdentityBlueprint/inheritablePermissions'] = & $page @(@{ resourceAppId = $script:GraphAppId; inheritableScopes = @{ '@odata.type' = '#microsoft.graph.allAllowedScopes'; kind = 'allAllowed' } })
    $r['applications/bp2/microsoft.graph.agentIdentityBlueprint/inheritablePermissions'] = & $page @(@{ resourceAppId = $script:GraphAppId; inheritableScopes = @{ '@odata.type' = '#microsoft.graph.enumeratedScopes'; kind = 'enumerated'; scopes = @('User.Read') } })
    $r['applications/bp3/microsoft.graph.agentIdentityBlueprint/inheritablePermissions'] = $none
    $r['applications/bp1/microsoft.graph.agentIdentityBlueprint/sponsors'] = $none
    $r['applications/bp2/microsoft.graph.agentIdentityBlueprint/sponsors'] = & $page @($alice)
    $r['applications/bp3/microsoft.graph.agentIdentityBlueprint/sponsors'] = & $page @($alice)
    foreach ($b in 'bp1', 'bp2', 'bp3') { $r["applications/$b/owners"] = & $page @($alice) }

    # Blueprint principals: bp1's principal holds Mail.Send, which its agents inherit
    $r['servicePrincipals/microsoft.graph.agentIdentityBlueprintPrincipal'] = & $page @(
        @{ id = 'bpp1'; appId = 'bp1-app'; displayName = 'Sales Blueprint'; accountEnabled = $true; createdDateTime = '2026-01-01T00:00:00Z' }
        @{ id = 'bpp2'; appId = 'bp2-app'; displayName = 'HR Blueprint'; accountEnabled = $true; createdDateTime = '2026-02-01T00:00:00Z' }
        @{ id = 'bpp3'; appId = 'bp3-app'; displayName = 'Expiring Blueprint'; accountEnabled = $true; createdDateTime = '2026-05-01T00:00:00Z' }
    )
    $mailSend = @{ id = 'ara-bpp1'; principalId = 'bpp1'; principalType = 'ServicePrincipal'; resourceId = 'sp-graph'; resourceDisplayName = 'Microsoft Graph'; appRoleId = 'r-mailsend'; createdDateTime = '2026-01-02T00:00:00Z' }
    $r['servicePrincipals/bpp1/appRoleAssignments'] = & $page @($mailSend)
    foreach ($p in 'bpp1', 'bpp2', 'bpp3') { $r["servicePrincipals/$p/oauth2PermissionGrants"] = $none }
    foreach ($p in 'bpp2', 'bpp3') { $r["servicePrincipals/$p/appRoleAssignments"] = $none }

    # Agent identities, split over two pages to exercise paging
    $page2 = 'https://graph.microsoft.com/beta/servicePrincipals/microsoft.graph.agentIdentity?$skiptoken=page2'
    $agentsWithSponsors = foreach ($a in $agents) { $x = $a.Clone(); $x.sponsors = @($sponsorsByAgent[$a.id]); $x }
    switch ($Scenario) {
        'A' {
            $r['servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors'] = 400
        }
        'B' {
            $r['servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors'] = 403
        }
        'C' {
            $r['servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors'] = & $page $agentsWithSponsors
        }
    }
    $r['servicePrincipals/microsoft.graph.agentIdentity'] = & $page $agents[0..1] $page2
    $r[$page2] = & $page $agents[2..3]

    foreach ($a in $agents) {
        $id = $a.id
        $sponsorStatus = if ($Scenario -eq 'B') { 403 } else { & $page $sponsorsByAgent[$id] }
        $r["servicePrincipals/$id/microsoft.graph.agentIdentity/sponsors?`$select=id,displayName,userPrincipalName,accountEnabled"] = $sponsorStatus
        $r["servicePrincipals/$id/microsoft.graph.agentIdentity/sponsors"] = $sponsorStatus
        $r["servicePrincipals/$id/owners"] = $none
        $r["servicePrincipals/$id/appRoleAssignments"] = $none
        $r["servicePrincipals/$id/oauth2PermissionGrants"] = $none
        $r["servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedAppRoleAssignments"] = $none
        $r["servicePrincipals/microsoft.graph.agentIdentity/$id/inheritedOauth2PermissionGrants"] = $none
    }
    # Custom security attributes (only requested with -IncludeSecurityAttributes). Attribute names are
    # Engineering.CostCenter, Engineering.Project and Engineering.DataClass.
    #   a1: CostCenter + Project (annotation keys present, as Graph returns them)   a2: all three
    #   a3: no attributes at all (null)   a4: CostCenter only - Project is an empty string, plus an unrelated set
    $csaType = '#Microsoft.DirectoryServices.CustomSecurityAttributeValue'
    $csa = @{
        a1 = @{ Engineering = @{ '@odata.type' = $csaType; 'Project@odata.type' = '#Collection(String)'; Project = @('Baker'); CostCenter = 1001 } }
        a2 = @{ Engineering = @{ '@odata.type' = $csaType; Project = @('Cascade'); CostCenter = 1002; DataClass = 'Internal' } }
        a3 = $null
        a4 = @{ Engineering = @{ '@odata.type' = $csaType; Project = ''; CostCenter = 1003 }; Finance = @{ '@odata.type' = $csaType; Region = 'EMEA' } }
    }
    foreach ($a in $agents) {
        $r["servicePrincipals/$($a.id)?`$select=id,customSecurityAttributes"] = if ($Scenario -eq 'B') { 403 } else { @{ id = $a.id; customSecurityAttributes = $csa[$a.id] } }
    }

    # a1: blocked Directory.ReadWrite.All (direct), Mail.Read + User.Read for all users, Mail.Send inherited from bpp1
    $r['servicePrincipals/a1/appRoleAssignments'] = & $page @(@{ id = 'ara-a1'; principalId = 'a1'; principalType = 'ServicePrincipal'; resourceId = 'sp-graph'; resourceDisplayName = 'Microsoft Graph'; appRoleId = 'r-dirrw' })
    $r['servicePrincipals/a1/oauth2PermissionGrants'] = & $page @(@{ id = 'g-a1'; clientId = 'a1'; consentType = 'AllPrincipals'; principalId = $null; resourceId = 'sp-graph'; scope = 'Mail.Read User.Read' })
    $r['servicePrincipals/microsoft.graph.agentIdentity/a1/inheritedAppRoleAssignments'] = & $page @($mailSend)
    # a2: User.Read for one user only (clean); a default-access app role on Graph
    $r['servicePrincipals/a2/oauth2PermissionGrants'] = & $page @(@{ id = 'g-a2'; clientId = 'a2'; consentType = 'Principal'; principalId = 'user-alice'; resourceId = 'sp-graph'; scope = 'User.Read' })
    $r['servicePrincipals/a2/appRoleAssignments'] = & $page @(@{ id = 'ara-a2'; principalId = 'a2'; resourceId = 'sp-graph'; appRoleId = '00000000-0000-0000-0000-000000000000' })
    # a3: SharePoint's own Sites.FullControl.All - not covered by the Graph block list
    $r['servicePrincipals/a3/appRoleAssignments'] = & $page @(@{ id = 'ara-a3'; principalId = 'a3'; resourceId = 'sp-spo'; resourceDisplayName = 'Office 365 SharePoint Online'; appRoleId = 'r-spofull' })

    # Agent users: the $select variant is rejected, so the collector must fall back
    $r['users/microsoft.graph.agentUser?$select=id,displayName,userPrincipalName,accountEnabled,createdDateTime,identityParentId'] = 400
    $r['users/microsoft.graph.agentUser'] = & $page @(
        @{ id = 'u1'; displayName = 'Sales Agent User'; userPrincipalName = 'salesagent@contoso.example'; accountEnabled = $true; createdDateTime = '2026-01-15T00:00:00Z'; identityParentId = 'a1' }
        @{ id = 'u2'; displayName = 'Ghost Agent User'; userPrincipalName = 'ghost@contoso.example'; accountEnabled = $true; createdDateTime = '2026-03-01T00:00:00Z'; identityParentId = 'missing-agent' }
    )
    $r['users/u1/sponsors?$select=id,displayName,userPrincipalName,accountEnabled'] = $none
    $r['users/u2/sponsors?$select=id,displayName,userPrincipalName,accountEnabled'] = & $page @($alice)

    # Directory roles: a1 is Global Administrator, u2 is Reports Reader; a human GA must be ignored
    $r['roleManagement/directory/roleAssignments?$expand=roleDefinition'] = & $page @(
        @{ id = 'ra1'; principalId = 'a1'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/'; roleDefinition = @{ displayName = 'Global Administrator'; templateId = '62e90394-69f5-4237-9190-012177145e10'; isPrivileged = $true; isBuiltIn = $true } }
        @{ id = 'ra2'; principalId = 'user-alice'; roleDefinitionId = 'rd-ga'; directoryScopeId = '/'; roleDefinition = @{ displayName = 'Global Administrator'; templateId = '62e90394-69f5-4237-9190-012177145e10'; isPrivileged = $true; isBuiltIn = $true } }
        @{ id = 'ra3'; principalId = 'u2'; roleDefinitionId = 'rd-rr'; directoryScopeId = '/'; roleDefinition = @{ displayName = 'Reports Reader'; templateId = '4a5d8f65-41da-4de4-8968-e035b65339cf'; isPrivileged = $false; isBuiltIn = $true } }
    )

    # Resources named in grants
    $r['servicePrincipals/sp-graph?$select=id,appId,displayName,appRoles'] = @{
        id = 'sp-graph'; appId = $script:GraphAppId; displayName = 'Microsoft Graph'
        appRoles = @((& $role 'r-mailsend' 'Mail.Send'), (& $role 'r-dirrw' 'Directory.ReadWrite.All'), (& $role 'r-userreadall' 'User.Read.All'))
    }
    $r['servicePrincipals/sp-spo?$select=id,appId,displayName,appRoles'] = @{
        id = 'sp-spo'; appId = $script:SpoAppId; displayName = 'Office 365 SharePoint Online'; appRoles = @(& $role 'r-spofull' 'Sites.FullControl.All')
    }

    # Sign-in activity: a1 stale, a2 recent, a3 never, a4 recent
    $signIn = { param($appId, $when) & $page @(@{ appId = $appId; lastSignInActivity = @{ lastSignInDateTime = $when }; applicationAuthenticationClientSignInActivity = @{ lastSignInDateTime = $when } }) }
    $r["reports/servicePrincipalSignInActivities?`$filter=appId eq 'a1-app'"] = & $signIn 'a1-app' '2026-03-01T00:00:00Z'
    $r["reports/servicePrincipalSignInActivities?`$filter=appId eq 'a2-app'"] = & $signIn 'a2-app' '2026-09-10T00:00:00Z'
    $r["reports/servicePrincipalSignInActivities?`$filter=appId eq 'a3-app'"] = $none
    $r["reports/servicePrincipalSignInActivities?`$filter=appId eq 'a4-app'"] = & $signIn 'a4-app' '2026-09-15T00:00:00Z'

    # Identity Protection
    $r['identityProtection/riskyAgents'] = if ($Scenario -eq 'B') { 403 } else {
        & $page @(
            @{ id = 'a1'; agentDisplayName = 'Sales Agent'; identityType = 'agentIdentity'; riskLevel = 'high'; riskState = 'atRisk'; riskDetail = 'none'; riskLastModifiedDateTime = '2026-09-01T00:00:00Z'; isEnabled = $true; isDeleted = $false }
            @{ id = 'a2'; agentDisplayName = 'HR Agent'; identityType = 'agentIdentity'; riskLevel = 'none'; riskState = 'dismissed'; riskDetail = 'adminDismissedAllRiskForAgent'; riskLastModifiedDateTime = '2026-08-01T00:00:00Z'; isEnabled = $true; isDeleted = $false }
        )
    }

    $routes = @{}
    foreach ($key in $r.Keys) {
        $value = $r[$key]
        $routes[$key] = if ($value -is [int]) { $value } else { ConvertTo-FakeGraphObject $value }
    }
    return $routes
}

function New-FakeGraphHandler {
    # Returns @{ Handler; Calls; Unrouted }. The handler matches the request URI (version prefix removed,
    # percent-decoded) against the routes, returning the response or throwing the error Invoke-MgGraphRequest
    # would. Requests with no route fail as 404 and are recorded in Unrouted, so tests can spot typos.
    param([Parameter(Mandatory)][hashtable]$Routes)
    $calls = [System.Collections.Generic.List[string]]::new()
    $unrouted = [System.Collections.Generic.List[string]]::new()
    $handler = {
        param($Uri, $Headers)
        $key = [uri]::UnescapeDataString("$Uri")
        if (-not $Routes.ContainsKey($key)) { $key = $key -replace '^https://graph\.microsoft\.com/', '' -replace '^(beta|v1\.0)/', '' }
        $calls.Add($key)
        if (-not $Routes.ContainsKey($key)) {
            $unrouted.Add($key)
            throw 'Response status code does not indicate success: NotFound (Not Found).'
        }
        $value = $Routes[$key]
        if ($value -is [int]) {
            $text = switch ($value) { 400 { 'BadRequest (Bad Request)' } 403 { 'Forbidden (Forbidden)' } 404 { 'NotFound (Not Found)' } default { "InternalServerError ($value)" } }
            throw "Response status code does not indicate success: $text."
        }
        return $value
    }.GetNewClosure()
    return @{ Handler = $handler; Calls = $calls; Unrouted = $unrouted }
}

function Set-FakeGraph {
    param($Handler)
    & (Get-Module AgentIdAudit) { param($h) $script:AgentIdGraphHandler = $h } $Handler
}
