function Export-AgentIdReport {
    <#
    .SYNOPSIS
    Writes a self-contained HTML report for a snapshot.

    .DESCRIPTION
    The report lists findings by severity, the checks that could not run and why, an inventory of blueprints,
    agent identities and agent users, and every agent's effective access. It is a single HTML file with no
    external resources, safe to email or archive.

    .EXAMPLE
    Get-AgentIdInventory | Export-AgentIdReport -Path .\agent-audit.html

    .EXAMPLE
    Import-AgentIdSnapshot .\contoso.json | Export-AgentIdReport -Path .\contoso.html -StaleAfterDays 60
    #>
    [CmdletBinding(SupportsShouldProcess)]
    [OutputType([System.IO.FileInfo])]
    param(
        [Parameter(Mandatory, ValueFromPipeline)][PSTypeName('AgentIdAudit.Snapshot')]$Snapshot,
        [Parameter(Mandatory)][string]$Path,
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
        $params = @{ Snapshot = $Snapshot; Options = $options }
        if ($PSBoundParameters.ContainsKey('AsOf')) { $params.AsOf = $AsOf }
        $evaluation = Invoke-AgentIdRuleEvaluation @params
        $html = ConvertTo-AgentIdReportHtml -Snapshot $Snapshot -Evaluation $evaluation -Branding $script:AgentIdBranding

        $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
        if ($PSCmdlet.ShouldProcess($full, 'Write agent identity audit report')) {
            Set-Content -LiteralPath $full -Value $html -Encoding utf8
            Get-Item -LiteralPath $full
        }
    }
}

function Invoke-AgentIdAudit {
    <#
    .SYNOPSIS
    Runs a complete audit: collects the inventory, evaluates it, and writes a snapshot, findings and a report.

    .DESCRIPTION
    Connects first if there is no Microsoft Graph connection. Writes three files to -OutputPath:
      agentid-snapshot-<date>.json   the raw snapshot, for later analysis
      agentid-findings-<date>.csv    one row per finding
      agentid-report-<date>.html     the human-readable report
    and returns a summary.

    .PARAMETER RequiredSecurityAttribute
    Custom security attributes (AttributeSet.AttributeName) every agent identity must have a value for. Naming
    any implies -IncludeSecurityAttributes.

    .PARAMETER OptionalSecurityAttribute
    Custom security attributes an agent identity should have a value for if they apply (reported as Info).

    .PARAMETER IncludeSecurityAttributes
    Read agents' custom security attributes into the snapshot even when no attribute names are given, so they can
    be checked later. Needs CustomSecAttributeAssignment.Read.All and the Attribute Assignment Reader role.

    .EXAMPLE
    Invoke-AgentIdAudit -TenantId contoso.onmicrosoft.com -OutputPath .\audit

    .EXAMPLE
    Invoke-AgentIdAudit -RequiredSecurityAttribute Engineering.CostCenter, Engineering.Owner -OptionalSecurityAttribute Engineering.DataClass
    #>
    [CmdletBinding()]
    param(
        [string]$OutputPath = '.',
        [string]$TenantId,
        [switch]$UseDeviceCode,
        [switch]$SkipSignInActivity,
        [switch]$SkipRisk,
        [switch]$IncludeSecurityAttributes,
        [ValidateRange(1, 36500)][int]$MaxCredentialLifetimeDays = 180,
        [ValidateRange(1, 3650)][int]$StaleAfterDays = 90,
        [ValidateRange(1, 365)][int]$ExpiringWithinDays = 30,
        [ValidatePattern('^\w+\.\w+$', ErrorMessage = 'Use the form AttributeSet.AttributeName, for example Engineering.CostCenter.')][string[]]$RequiredSecurityAttribute,
        [ValidatePattern('^\w+\.\w+$', ErrorMessage = 'Use the form AttributeSet.AttributeName, for example Engineering.CostCenter.')][string[]]$OptionalSecurityAttribute
    )

    $collectAttributes = $IncludeSecurityAttributes -or $RequiredSecurityAttribute -or $OptionalSecurityAttribute
    if (-not $script:AgentIdGraphHandler) {
        $connected = (Get-Command Get-MgContext -ErrorAction SilentlyContinue) -and (Get-MgContext)
        if (-not $connected) {
            $connect = @{ SkipOptionalScopes = ($SkipSignInActivity -and $SkipRisk); IncludeSecurityAttributes = [bool]$collectAttributes }
            if ($TenantId) { $connect.TenantId = $TenantId }
            if ($UseDeviceCode) { $connect.UseDeviceCode = $true }
            Connect-AgentIdAudit @connect | Out-Null
        }
    }

    $dir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputPath)
    New-Item -ItemType Directory -Force -Path $dir | Out-Null
    $stamp = [datetime]::UtcNow.ToString('yyyyMMdd-HHmm')

    $snapshot = Get-AgentIdInventory -SkipSignInActivity:$SkipSignInActivity -SkipRisk:$SkipRisk -IncludeSecurityAttributes:$collectAttributes
    $snapshotFile = Export-AgentIdSnapshot -Snapshot $snapshot -Path (Join-Path $dir "agentid-snapshot-$stamp.json")

    $options = New-AgentIdOptions -MaxCredentialLifetimeDays $MaxCredentialLifetimeDays -StaleAfterDays $StaleAfterDays -ExpiringWithinDays $ExpiringWithinDays `
        -RequiredSecurityAttribute $RequiredSecurityAttribute -OptionalSecurityAttribute $OptionalSecurityAttribute
    $evaluation = Invoke-AgentIdRuleEvaluation -Snapshot $snapshot -Options $options
    $findingsFile = Join-Path $dir "agentid-findings-$stamp.csv"
    $evaluation.Findings | Select-Object Severity, RuleId, Title, ObjectType, ObjectName, ObjectId, Detail, Remediation, Reference |
        Export-Csv -LiteralPath $findingsFile -NoTypeInformation -Encoding utf8
    $reportFile = Join-Path $dir "agentid-report-$stamp.html"
    Set-Content -LiteralPath $reportFile -Value (ConvertTo-AgentIdReportHtml -Snapshot $snapshot -Evaluation $evaluation -Branding $script:AgentIdBranding) -Encoding utf8

    foreach ($n in $evaluation.NotEvaluated) {
        Write-Warning "$($n.RuleId) '$($n.Title)' not evaluated: $($n.Reason)"
    }
    $bySeverity = { param($s) @($evaluation.Findings | Where-Object Severity -EQ $s).Count }
    [pscustomobject]@{
        PSTypeName      = 'AgentIdAudit.Summary'
        Tenant          = if ($snapshot.TenantName) { $snapshot.TenantName } else { $snapshot.TenantId }
        Blueprints      = @($snapshot.Blueprints).Count
        AgentIdentities = @($snapshot.AgentIdentities).Count
        AgentUsers      = @($snapshot.AgentUsers).Count
        Critical        = & $bySeverity 'Critical'
        High            = & $bySeverity 'High'
        Medium          = & $bySeverity 'Medium'
        Low             = & $bySeverity 'Low'
        Info            = & $bySeverity 'Info'
        NotEvaluated    = $evaluation.NotEvaluated.Count
        Report          = $reportFile
        Findings        = $findingsFile
        Snapshot        = $snapshotFile.FullName
    }
}
