@{
    RootModule           = 'AgentIdAudit.psm1'
    ModuleVersion        = '0.1.0'
    GUID                 = '06a01476-dc25-4b24-8096-bf15dd2f5b9c'
    Author               = 'mrochon'
    Copyright            = '(c) 2026 MariusR. MIT License.'
    Description          = 'Read-only security audit of Microsoft Entra Agent ID: blueprint credentials, effective (direct and inherited) agent permissions, blocked and sensitive grants, directory roles, sponsors, stale and risky agents. Produces a findings list and a self-contained HTML report; snapshots contain no secrets and can be analyzed offline.'
    PowerShellVersion    = '7.2'
    CompatiblePSEditions = @('Core')
    FunctionsToExport    = @(
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
    CmdletsToExport      = @()
    VariablesToExport    = @()
    AliasesToExport      = @()
    PrivateData          = @{
        PSData = @{
            Tags                       = @('Entra', 'AgentID', 'AgentIdentity', 'AIAgents', 'Security', 'Audit', 'Identity', 'MicrosoftGraph', 'OAuth')
            LicenseUri                 = 'https://github.com/mrochon/AgentIdAudit/blob/main/LICENSE'
            ProjectUri                 = 'https://github.com/mrochon/AgentIdAudit'
            Prerelease                 = 'preview'
            ExternalModuleDependencies = @('Microsoft.Graph.Authentication')
            ReleaseNotes               = 'First preview. See CHANGELOG.md.'
        }
    }
}
