function Get-AgentIdFinding {
    <#
    .SYNOPSIS
    Evaluates a snapshot against the audit rules and returns the findings.

    .DESCRIPTION
    Findings are sorted by severity, most severe first. Rules whose input data wasn't collected are not run;
    each is reported with a warning (and listed in the HTML report) so that "no findings" is never mistaken
    for "checked and clean".

    Time-based checks are evaluated as of the moment the snapshot was collected, unless -AsOf is given.

    .PARAMETER MinimumSeverity
    Return only findings at or above this severity.

    .PARAMETER RuleId
    Run only these rules. Wildcards are allowed, e.g. 'AID-CRED-*'.

    .PARAMETER ExcludeRuleId
    Skip these rules. Wildcards are allowed.

    .PARAMETER RequiredSecurityAttribute
    Custom security attributes, as AttributeSet.AttributeName, that every agent identity must have a value for
    (AID-GOV-008). The snapshot must have been collected with Get-AgentIdInventory -IncludeSecurityAttributes.
    The rule is not run when this is omitted.

    .PARAMETER OptionalSecurityAttribute
    Custom security attributes an agent identity should have a value for if they apply (AID-GOV-009, Info).
    An attribute named in both lists is treated as required.

    .EXAMPLE
    Get-AgentIdInventory | Get-AgentIdFinding -MinimumSeverity High | Format-Table Severity, Title, ObjectName

    .EXAMPLE
    Get-AgentIdInventory -IncludeSecurityAttributes | Get-AgentIdFinding -RuleId 'AID-GOV-00[89]' -RequiredSecurityAttribute Engineering.CostCenter, Engineering.Owner -OptionalSecurityAttribute Engineering.DataClass

    .EXAMPLE
    Import-AgentIdSnapshot .\contoso.json | Get-AgentIdFinding -RuleId 'AID-PERM-*' | Export-Csv .\perm.csv
    #>
    [CmdletBinding()]
    [OutputType('AgentIdAudit.Finding')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][PSTypeName('AgentIdAudit.Snapshot')]$Snapshot,
        [ValidateSet('Critical', 'High', 'Medium', 'Low', 'Info')][string]$MinimumSeverity = 'Info',
        [string[]]$RuleId,
        [string[]]$ExcludeRuleId,
        [datetimeoffset]$AsOf,
        [ValidateRange(1, 36500)][int]$MaxCredentialLifetimeDays = 180,
        [ValidateRange(1, 3650)][int]$StaleAfterDays = 90,
        [ValidateRange(1, 365)][int]$ExpiringWithinDays = 30,
        [ValidatePattern('^\w+\.\w+$', ErrorMessage = 'Use the form AttributeSet.AttributeName, for example Engineering.CostCenter.')][string[]]$RequiredSecurityAttribute,
        [ValidatePattern('^\w+\.\w+$', ErrorMessage = 'Use the form AttributeSet.AttributeName, for example Engineering.CostCenter.')][string[]]$OptionalSecurityAttribute
    )
    process {
        $options = New-AgentIdOptions -MaxCredentialLifetimeDays $MaxCredentialLifetimeDays -StaleAfterDays $StaleAfterDays -ExpiringWithinDays $ExpiringWithinDays `
            -RequiredSecurityAttribute $RequiredSecurityAttribute -OptionalSecurityAttribute $OptionalSecurityAttribute
        $params = @{ Snapshot = $Snapshot; Options = $options; IncludeRuleId = $RuleId; ExcludeRuleId = $ExcludeRuleId }
        if ($PSBoundParameters.ContainsKey('AsOf')) { $params.AsOf = $AsOf }
        $result = Invoke-AgentIdRuleEvaluation @params

        foreach ($n in $result.NotEvaluated) {
            Write-Warning "$($n.RuleId) '$($n.Title)' not evaluated: $($n.Reason)"
        }
        $floor = Get-AgentIdSeverityRank $MinimumSeverity
        $result.Findings | Where-Object { (Get-AgentIdSeverityRank $_.Severity) -ge $floor }
    }
}

function Get-AgentIdRule {
    <#
    .SYNOPSIS
    Lists the audit rules.

    .DESCRIPTION
    Severity is each rule's maximum; some rules report individual findings at a lower severity. Requires lists
    the data each rule needs - if any of it can't be collected, the rule is reported as not evaluated.

    .EXAMPLE
    Get-AgentIdRule | Format-Table Id, Severity, Title
    #>
    [CmdletBinding()]
    param([string[]]$Id)
    foreach ($rule in $script:AgentIdRules) {
        if ($Id -and -not ($Id | Where-Object { $rule.Id -like $_ })) { continue }
        [pscustomobject]@{
            PSTypeName  = 'AgentIdAudit.Rule'
            Id          = $rule.Id
            Severity    = $rule.Severity
            Category    = $rule.Category
            Title       = $rule.Title
            Requires    = $rule.Requires
            Remediation = $rule.Remediation
            Reference   = $rule.Reference
        }
    }
}

function Get-AgentIdEffectiveAccess {
    <#
    .SYNOPSIS
    Lists what each agent can access: direct grants plus those inherited from its blueprint.

    .DESCRIPTION
    Returns one row per principal and permission. Rows for agent identities are marked Direct or Inherited;
    rows for blueprint principals show access that agent identities created from the blueprint can inherit.

    .PARAMETER Name
    Filter by principal display name. Wildcards are allowed.

    .EXAMPLE
    Get-AgentIdInventory | Get-AgentIdEffectiveAccess -Name 'Sales*' | Format-Table PrincipalName, PermissionType, Permission, Source
    #>
    [CmdletBinding()]
    [OutputType('AgentIdAudit.AccessRow')]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][PSTypeName('AgentIdAudit.Snapshot')]$Snapshot,
        [string]$Name = '*',
        [ValidateSet('AgentIdentity', 'BlueprintPrincipal')][string[]]$PrincipalKind = @('AgentIdentity', 'BlueprintPrincipal')
    )
    process {
        Get-AgentIdAccessRow -Snapshot $Snapshot | Where-Object { $_.PrincipalName -like $Name -and $_.PrincipalKind -in $PrincipalKind }
    }
}
