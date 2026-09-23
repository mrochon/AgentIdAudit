function Connect-AgentIdAudit {
    <#
    .SYNOPSIS
    Connects to Microsoft Graph with the read-only permissions the audit needs.

    .DESCRIPTION
    Wraps Connect-MgGraph from the Microsoft.Graph.Authentication module. Every scope requested is read-only.
    An administrator must consent to them the first time.

    You can also connect yourself - for example app-only, with a certificate - using Connect-MgGraph; the
    other commands use whatever Graph connection is current.

    .PARAMETER TenantId
    Tenant to sign in to (ID or verified domain).

    .PARAMETER UseDeviceCode
    Sign in with a device code, for sessions without a browser.

    .PARAMETER SkipOptionalScopes
    Request only the core scopes. Sign-in activity (AuditLog.Read.All) and Identity Protection
    (IdentityRiskyAgent.Read.All) checks will then be reported as not evaluated.

    .PARAMETER IncludeSecurityAttributes
    Also request CustomSecAttributeAssignment.Read.All, needed to read agents' custom security attributes
    (Get-AgentIdInventory -IncludeSecurityAttributes). The signed-in account must also hold the Attribute
    Assignment Reader role.

    .EXAMPLE
    Connect-AgentIdAudit -TenantId contoso.onmicrosoft.com
    #>
    [CmdletBinding()]
    param(
        [string]$TenantId,
        [switch]$UseDeviceCode,
        [switch]$SkipOptionalScopes,
        [switch]$IncludeSecurityAttributes
    )

    if (-not (Get-Command Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw 'The Microsoft.Graph.Authentication module is required. Install it with: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    $scopes = @($script:AgentIdCoreScopes)
    if (-not $SkipOptionalScopes) { $scopes += $script:AgentIdOptionalScopes }
    if ($IncludeSecurityAttributes) { $scopes += $script:AgentIdSecurityAttributeScope }

    $params = @{ Scopes = $scopes; NoWelcome = $true; ErrorAction = 'Stop' }
    if ($TenantId) { $params.TenantId = $TenantId }
    if ($UseDeviceCode) { $params.UseDeviceCode = $true }
    Connect-MgGraph @params

    $context = Get-MgContext
    [pscustomobject]@{
        Account  = $context.Account
        TenantId = $context.TenantId
        Scopes   = $context.Scopes
    }
}
