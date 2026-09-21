# Every object stored in a snapshot is rebuilt from an explicit allowlist of properties. This keeps secret
# material out of snapshots (a passwordCredential's 'hint' holds the first characters of the secret; Graph never
# returns 'secretText' on read, but it is dropped here regardless) and keeps the snapshot schema stable when
# Microsoft adds properties.

function Test-AgentIdProperty {
    param($InputObject, [Parameter(Mandatory)][string]$Name)
    return ($null -ne $InputObject -and $null -ne $InputObject.PSObject.Properties[$Name])
}

function ConvertTo-AgentIdDateString {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    $date = ConvertTo-AgentIdDate $Value
    if ($null -eq $date) { return "$Value" }
    return $date.UtcDateTime.ToString('o')
}

function ConvertTo-AgentIdDate {
    # Accepts DateTime, DateTimeOffset or an ISO 8601 string; returns a DateTimeOffset or $null.
    param($Value)
    if ($null -eq $Value) { return $null }
    if ($Value -is [datetimeoffset]) { return $Value }
    if ($Value -is [datetime]) {
        $utc = if ($Value.Kind -eq [DateTimeKind]::Unspecified) { [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc) } else { $Value.ToUniversalTime() }
        return [datetimeoffset]$utc
    }
    $parsed = [datetimeoffset]::MinValue
    $styles = [System.Globalization.DateTimeStyles]::AssumeUniversal
    if ([datetimeoffset]::TryParse("$Value", [System.Globalization.CultureInfo]::InvariantCulture, $styles, [ref]$parsed)) {
        return $parsed
    }
    return $null
}

function ConvertTo-AgentIdCredential {
    param($InputObject, [Parameter(Mandatory)][ValidateSet('Secret', 'Certificate')][string]$Kind)
    foreach ($c in @($InputObject)) {
        if ($null -eq $c) { continue }
        [ordered]@{
            keyId         = $c.keyId
            kind          = $Kind
            displayName   = $c.displayName
            type          = $c.type
            usage         = $c.usage
            startDateTime = ConvertTo-AgentIdDateString $c.startDateTime
            endDateTime   = ConvertTo-AgentIdDateString $c.endDateTime
        }
    }
}

function ConvertTo-AgentIdFederatedCredential {
    param($InputObject)
    foreach ($f in @($InputObject)) {
        if ($null -eq $f) { continue }
        [ordered]@{
            id        = $f.id
            name      = $f.name
            issuer    = $f.issuer
            subject   = $f.subject
            audiences = @($f.audiences)
        }
    }
}

function ConvertTo-AgentIdDirectoryObjectRef {
    # Sponsors and owners: users, groups or service principals.
    param($InputObject)
    foreach ($o in @($InputObject)) {
        if ($null -eq $o) { continue }
        $ref = [ordered]@{
            id                = $o.id
            odataType         = $o.'@odata.type'
            displayName       = $o.displayName
            userPrincipalName = $o.userPrincipalName
        }
        # Only record accountEnabled when Graph returned it: $null means unknown, not disabled.
        $ref.accountEnabled = if (Test-AgentIdProperty $o 'accountEnabled') { $o.accountEnabled } else { $null }
        $ref
    }
}

function ConvertTo-AgentIdAppRoleAssignment {
    param($InputObject)
    foreach ($a in @($InputObject)) {
        if ($null -eq $a) { continue }
        [ordered]@{
            id                   = $a.id
            principalId          = $a.principalId
            principalType        = $a.principalType
            principalDisplayName = $a.principalDisplayName
            resourceId           = $a.resourceId
            resourceDisplayName  = $a.resourceDisplayName
            appRoleId            = $a.appRoleId
            createdDateTime      = ConvertTo-AgentIdDateString $a.createdDateTime
        }
    }
}

function ConvertTo-AgentIdPermissionGrant {
    param($InputObject)
    foreach ($g in @($InputObject)) {
        if ($null -eq $g) { continue }
        [ordered]@{
            id          = $g.id
            clientId    = $g.clientId
            consentType = $g.consentType
            principalId = $g.principalId
            resourceId  = $g.resourceId
            scope       = $g.scope
        }
    }
}

function ConvertTo-AgentIdInheritablePermission {
    param($InputObject)
    foreach ($p in @($InputObject)) {
        if ($null -eq $p) { continue }
        $scopes = $p.inheritableScopes
        $kind = $scopes.kind
        if (-not $kind -and $scopes.'@odata.type') {
            # e.g. '#microsoft.graph.enumeratedScopes' -> 'enumerated'
            $kind = ($scopes.'@odata.type' -replace '^#?microsoft\.graph\.', '') -replace 'Scopes$', ''
        }
        [ordered]@{
            resourceAppId = $p.resourceAppId
            kind          = $kind
            scopes        = @($scopes.scopes | Where-Object { $_ })
        }
    }
}

function ConvertTo-AgentIdResource {
    param($InputObject)
    [ordered]@{
        id          = $InputObject.id
        appId       = $InputObject.appId
        displayName = $InputObject.displayName
        appRoles    = @(foreach ($r in @($InputObject.appRoles)) { if ($r) { [ordered]@{ id = $r.id; value = $r.value } } })
    }
}
