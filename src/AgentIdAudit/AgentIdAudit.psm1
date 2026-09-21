$script:AgentIdSchemaVersion = 1
$script:AgentIdGraphVersion = 'beta'
$script:AgentIdGraphHandler = $null   # test hook; see Invoke-AgentIdRawRequest

# Read-only Microsoft Graph permissions. Optional scopes feed the sign-in activity and Identity Protection checks.
$script:AgentIdCoreScopes = @(
    'AgentIdentity.Read.All'
    'AgentIdentityBlueprint.Read.All'
    'AgentIdentityBlueprintPrincipal.Read.All'
    'Application.Read.All'
    'Directory.Read.All'
    'RoleManagement.Read.Directory'
)
$script:AgentIdOptionalScopes = @(
    'AuditLog.Read.All'
    'IdentityRiskyAgent.Read.All'
)

foreach ($folder in 'Private', 'Public') {
    foreach ($file in Get-ChildItem -Path (Join-Path $PSScriptRoot $folder) -Filter '*.ps1') {
        . $file.FullName
    }
}

# Read from the manifest: the module object's Version isn't populated yet while the .psm1 is running.
$manifestData = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'AgentIdAudit.psd1')
$script:AgentIdModuleVersion = $manifestData.ModuleVersion
if ($manifestData.PrivateData.PSData.Prerelease) { $script:AgentIdModuleVersion += "-$($manifestData.PrivateData.PSData.Prerelease)" }
Remove-Variable manifestData
$script:AgentIdBlockedPermissions = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'Data\BlockedPermissions.psd1')
$script:AgentIdSensitivePermissions = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'Data\SensitivePermissions.psd1')
$script:AgentIdBranding = Import-PowerShellDataFile (Join-Path $PSScriptRoot 'Data\Branding.psd1')
$script:AgentIdRules = @(. (Join-Path $PSScriptRoot 'Data\Rules.ps1'))

# Fail at import, not mid-audit, if a rule definition is malformed.
$ruleIds = @{}
foreach ($rule in $script:AgentIdRules) {
    foreach ($key in 'Id', 'Severity', 'Category', 'Title', 'Requires', 'Remediation', 'Evaluate') {
        if (-not $rule.ContainsKey($key)) { throw "AgentIdAudit rule '$($rule.Id)' is missing '$key'." }
    }
    if ($rule.Severity -notin 'Critical', 'High', 'Medium', 'Low', 'Info') { throw "AgentIdAudit rule '$($rule.Id)' has invalid severity '$($rule.Severity)'." }
    if ($rule.Evaluate -isnot [scriptblock]) { throw "AgentIdAudit rule '$($rule.Id)': Evaluate must be a scriptblock." }
    if ($ruleIds.ContainsKey($rule.Id)) { throw "Duplicate AgentIdAudit rule id '$($rule.Id)'." }
    $ruleIds[$rule.Id] = $true
}
Remove-Variable ruleIds, rule, key, folder, file -ErrorAction SilentlyContinue

Export-ModuleMember -Function @(
    'Connect-AgentIdAudit'
    'Get-AgentIdInventory'
    'Export-AgentIdSnapshot'
    'Import-AgentIdSnapshot'
    'Get-AgentIdFinding'
    'Get-AgentIdRule'
    'Get-AgentIdEffectiveAccess'
    'Export-AgentIdReport'
    'Invoke-AgentIdAudit'
)
