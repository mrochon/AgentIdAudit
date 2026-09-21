function ConvertTo-AgentIdHtmlText {
    # Everything placed in the report goes through here: display names are set by whoever creates an agent,
    # so they must never be interpreted as markup.
    param($Value)
    if ($null -eq $Value) { return '' }
    return [System.Net.WebUtility]::HtmlEncode("$Value")
}

function ConvertTo-AgentIdHtmlLink {
    param([string]$Url, [string]$Text)
    if ($Url -notmatch '^https://') { return (ConvertTo-AgentIdHtmlText $Text) }
    return '<a href="{0}" rel="noopener noreferrer">{1}</a>' -f (ConvertTo-AgentIdHtmlText $Url), (ConvertTo-AgentIdHtmlText $Text)
}

function Get-AgentIdReportCss {
    return @'
:root {
  --bg: #f6f6f3; --panel: #ffffff; --text: #1d1d1f; --muted: #5d6166; --line: #e2e2dd; --accent: #2b5d8a;
  --crit: #a1261d; --crit-bg: #fbe8e5; --high: #b54708; --high-bg: #fdf0e3; --med: #8a6100; --med-bg: #fbf3d6;
  --low: #2b5d8a; --low-bg: #e7eff7; --info: #5d6166; --info-bg: #ededea; --ok: #2e7d4f; --ok-bg: #e5f3ea;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #141517; --panel: #1d1e21; --text: #e9e9e6; --muted: #a3a5aa; --line: #34363a; --accent: #8cb8e0;
    --crit: #f2a097; --crit-bg: #3d1c19; --high: #f3b27a; --high-bg: #3b2615; --med: #e6c66e; --med-bg: #362d12;
    --low: #9cc1e4; --low-bg: #1b2a38; --info: #b7b9bd; --info-bg: #2a2b2e; --ok: #8fd1a8; --ok-bg: #1a3325;
  }
}
* { box-sizing: border-box; }
body { margin: 0; background: var(--bg); color: var(--text); font: 15px/1.5 -apple-system, "Segoe UI", system-ui, sans-serif; }
.wrap { max-width: 1120px; margin: 0 auto; padding: 32px 20px 48px; }
header h1 { font-size: 26px; margin: 0 0 4px; letter-spacing: -0.01em; }
header p { margin: 0; color: var(--muted); }
h2 { font-size: 19px; margin: 40px 0 12px; }
h3 { font-size: 16px; margin: 24px 0 10px; }
a { color: var(--accent); }
.tiles { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 10px; margin-top: 24px; }
.tile { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 12px 14px; }
.tile b { display: block; font-size: 24px; font-variant-numeric: tabular-nums; }
.tile span { color: var(--muted); font-size: 13px; }
.tile.sev-Critical b { color: var(--crit); } .tile.sev-High b { color: var(--high); } .tile.sev-Medium b { color: var(--med); }
.tile.sev-Low b { color: var(--low); } .tile.sev-Info b { color: var(--info); }
.callout { background: var(--med-bg); border: 1px solid var(--line); border-left: 4px solid var(--med); border-radius: 8px; padding: 12px 16px; margin-top: 20px; }
.callout p { margin: 0 0 6px; }
.callout ul { margin: 0; padding-left: 20px; }
.finding { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 14px 16px; margin-bottom: 10px; }
.finding .head { display: flex; flex-wrap: wrap; align-items: baseline; gap: 8px; }
.finding .title { font-weight: 600; }
.finding .rule { color: var(--muted); font-size: 12px; font-family: ui-monospace, Consolas, monospace; }
.finding .object { color: var(--muted); font-size: 13px; margin-top: 2px; overflow-wrap: anywhere; }
.finding p { margin: 8px 0 0; overflow-wrap: anywhere; }
.finding .fix { color: var(--muted); }
.chip { display: inline-block; border-radius: 999px; padding: 1px 9px; font-size: 12px; font-weight: 600; white-space: nowrap; }
.chip.Critical { color: var(--crit); background: var(--crit-bg); } .chip.High { color: var(--high); background: var(--high-bg); }
.chip.Medium { color: var(--med); background: var(--med-bg); } .chip.Low { color: var(--low); background: var(--low-bg); }
.chip.Info { color: var(--info); background: var(--info-bg); } .chip.Ok { color: var(--ok); background: var(--ok-bg); }
.chip.Partial { color: var(--med); background: var(--med-bg); }
.chip.Denied, .chip.Error, .chip.NotSupported, .chip.Skipped, .chip.NotCollected { color: var(--crit); background: var(--crit-bg); }
.scroll { overflow-x: auto; background: var(--panel); border: 1px solid var(--line); border-radius: 10px; }
table { border-collapse: collapse; width: 100%; font-size: 13.5px; }
th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid var(--line); vertical-align: top; }
th { color: var(--muted); font-weight: 600; white-space: nowrap; }
tr:last-child td { border-bottom: 0; }
td.num { text-align: right; font-variant-numeric: tabular-nums; }
td.date { white-space: nowrap; }
.mono { font-family: ui-monospace, Consolas, monospace; font-size: 12px; color: var(--muted); }
.unknown { color: var(--muted); font-style: italic; }
.empty { color: var(--muted); padding: 12px 16px; margin: 0; }
footer { margin-top: 48px; padding-top: 16px; border-top: 1px solid var(--line); color: var(--muted); font-size: 13px; }
footer p { margin: 2px 0; }
@media print { body { background: #fff; } .finding, .scroll, .tile { break-inside: avoid; } }
'@
}

function ConvertTo-AgentIdReportHtml {
    param(
        [Parameter(Mandatory)]$Snapshot,
        [Parameter(Mandatory)][hashtable]$Evaluation,
        [Parameter(Mandatory)][hashtable]$Branding
    )
    $ctx = $Evaluation.Context
    $h = { param($v) ConvertTo-AgentIdHtmlText $v }
    $unknown = '<span class="unknown">unknown</span>'
    $count = { param($list) if ($null -eq $list) { $unknown } else { @($list).Count } }
    $sb = [System.Text.StringBuilder]::new()
    $add = { param([string]$s) [void]$sb.AppendLine($s) }
    $table = {
        param([string[]]$Headers, $Rows, [string]$Empty)
        if (-not @($Rows).Count) { & $add "<div class=""scroll""><p class=""empty"">$(& $h $Empty)</p></div>"; return }
        & $add '<div class="scroll"><table><thead><tr>'
        foreach ($col in $Headers) { & $add "<th>$(& $h $col)</th>" }
        & $add '</tr></thead><tbody>'
        foreach ($row in $Rows) { & $add "<tr>$($row -join '')</tr>" }
        & $add '</tbody></table></div>'
    }
    $td = { param($html, [string]$class) if ($class) { "<td class=""$class"">$html</td>" } else { "<td>$html</td>" } }

    $tenant = if ($Snapshot.TenantName) { $Snapshot.TenantName } else { 'Unknown tenant' }
    $collected = Format-AgentIdDate $Snapshot.CollectedAt
    $collectedTime = (ConvertTo-AgentIdDate $Snapshot.CollectedAt)
    $collectedText = if ($collectedTime) { $collectedTime.UtcDateTime.ToString('yyyy-MM-dd HH:mm') + ' UTC' } else { 'unknown' }

    & $add '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
    & $add "<title>Agent identity audit - $(& $h $tenant) - $(& $h $collected)</title>"
    & $add "<style>$(Get-AgentIdReportCss)</style></head><body><div class=""wrap"">"

    # ---- Header and summary
    & $add '<header><h1>Agent identity audit</h1>'
    & $add "<p>$(& $h $tenant) &middot; <span class=""mono"">$(& $h $Snapshot.TenantId)</span></p>"
    & $add "<p>Collected $(& $h $collectedText) &middot; evaluated as of $(& $h $ctx.AsOf.UtcDateTime.ToString('yyyy-MM-dd')) &middot; $(& $h $Snapshot.Tool) $(& $h $Snapshot.ToolVersion) &middot; Graph $(& $h $Snapshot.GraphVersion)</p></header>"

    & $add '<div class="tiles">'
    & $add "<div class=""tile""><b>$(@($Snapshot.Blueprints).Count)</b><span>Blueprints</span></div>"
    & $add "<div class=""tile""><b>$(@($Snapshot.AgentIdentities).Count)</b><span>Agent identities</span></div>"
    & $add "<div class=""tile""><b>$(@($Snapshot.AgentUsers).Count)</b><span>Agent users</span></div>"
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $n = @($Evaluation.Findings | Where-Object Severity -EQ $sev).Count
        & $add "<div class=""tile sev-$sev""><b>$n</b><span>$sev</span></div>"
    }
    & $add '</div>'

    if ($Evaluation.NotEvaluated.Count) {
        & $add "<div class=""callout""><p><strong>$($Evaluation.NotEvaluated.Count) check(s) could not run</strong> because the data they need wasn't available. Their absence below means <em>not checked</em>, not <em>clean</em>. See <a href=""#coverage"">collection coverage</a>.</p><ul>"
        foreach ($n in $Evaluation.NotEvaluated) {
            & $add "<li><span class=""mono"">$(& $h $n.RuleId)</span> $(& $h $n.Title) &mdash; $(& $h $n.Reason)</li>"
        }
        & $add '</ul></div>'
    }

    # ---- Findings
    & $add '<h2>Findings</h2>'
    if (-not $Evaluation.Findings.Count) {
        & $add '<div class="scroll"><p class="empty">No findings among the checks that ran.</p></div>'
    }
    foreach ($sev in 'Critical', 'High', 'Medium', 'Low', 'Info') {
        $group = @($Evaluation.Findings | Where-Object Severity -EQ $sev)
        if (-not $group) { continue }
        & $add "<h3><span class=""chip $sev"">$sev</span> $($group.Count) finding(s)</h3>"
        foreach ($f in $group) {
            & $add '<div class="finding"><div class="head">'
            & $add "<span class=""title"">$(& $h $f.Title)</span><span class=""rule"">$(& $h $f.RuleId)</span></div>"
            & $add "<div class=""object"">$(& $h $f.ObjectType): <strong>$(& $h $f.ObjectName)</strong> <span class=""mono"">$(& $h $f.ObjectId)</span></div>"
            & $add "<p>$(& $h $f.Detail)</p>"
            & $add "<p class=""fix"">$(& $h $f.Remediation) $(ConvertTo-AgentIdHtmlLink $f.Reference 'Reference')</p></div>"
        }
    }

    # ---- Blueprints
    & $add '<h2>Blueprints</h2>'
    $rows = foreach ($bp in @($Snapshot.Blueprints)) {
        if (-not $bp) { continue }
        $agentCount = if ($ctx.AgentsByBlueprintAppId.ContainsKey("$($bp.appId)")) { $ctx.AgentsByBlueprintAppId[$bp.appId].Count } else { 0 }
        $inherit = if ($null -eq $bp.inheritablePermissions) { $unknown } elseif (-not @($bp.inheritablePermissions).Count) { 'none' } else {
            (@($bp.inheritablePermissions) | ForEach-Object {
                $scopeText = if ($_.kind -eq 'allAllowed') { 'all scopes' } else { ($_.scopes -join ', ') }
                '{0}: {1}' -f (& $h (Get-AgentIdResourceName $ctx $_.resourceAppId)), (& $h $scopeText)
            }) -join '<br>'
        }
        , @(
            (& $td "<strong>$(& $h $bp.displayName)</strong><br><span class=""mono"">$(& $h $bp.appId)</span>")
            (& $td $agentCount 'num')
            (& $td (@(Get-AgentIdActiveCredential $ctx $bp.passwordCredentials).Count) 'num')
            (& $td (@(Get-AgentIdActiveCredential $ctx $bp.keyCredentials).Count) 'num')
            (& $td (& $count $bp.federatedIdentityCredentials) 'num')
            (& $td (& $count $bp.sponsors) 'num')
            (& $td $inherit)
            (& $td (& $h $bp.signInAudience))
        )
    }
    & $table @('Blueprint', 'Agents', 'Active secrets', 'Active certificates', 'Federated credentials', 'Sponsors', 'Inheritable scopes', 'Audience') $rows 'No blueprints found.'

    # ---- Agent identities
    & $add '<h2>Agent identities</h2>'
    $risk = @{}
    foreach ($r in @($Snapshot.RiskyAgents)) { if ($r) { $risk[$r.id] = $r } }
    $rows = foreach ($a in @($Snapshot.AgentIdentities)) {
        if (-not $a) { continue }
        $bpName = if ($ctx.BlueprintByAppId.ContainsKey("$($a.agentIdentityBlueprintId)")) { $ctx.BlueprintByAppId[$a.agentIdentityBlueprintId].displayName }
        elseif ($ctx.BlueprintPrincipalByAppId.ContainsKey("$($a.agentIdentityBlueprintId)")) { $ctx.BlueprintPrincipalByAppId[$a.agentIdentityBlueprintId].displayName }
        else { $a.agentIdentityBlueprintId }
        $mine = @($ctx.AccessRows | Where-Object PrincipalId -EQ $a.id)
        $direct = if ($null -eq $a.appRoleAssignments -and $null -eq $a.oauth2PermissionGrants) { $unknown } else { @($mine | Where-Object Source -EQ 'Direct').Count }
        $inherited = if ($null -eq $a.inheritedAppRoleAssignments -and $null -eq $a.inheritedOauth2PermissionGrants) { $unknown } else { @($mine | Where-Object Source -EQ 'Inherited').Count }
        $signIn = if (-not $ctx.SignInByAppId.ContainsKey("$($a.appId)")) { $unknown } elseif ($ctx.SignInByAppId[$a.appId].lastSignInDateTime) { Format-AgentIdDate $ctx.SignInByAppId[$a.appId].lastSignInDateTime } else { 'none recorded' }
        $riskText = if ($risk.ContainsKey("$($a.id)")) { & $h ("{0} / {1}" -f $risk[$a.id].riskLevel, $risk[$a.id].riskState) } elseif ((Test-AgentIdCoverageUsable $Snapshot 'RiskyAgents')) { 'none' } else { $unknown }
        , @(
            (& $td "<strong>$(& $h $a.displayName)</strong><br><span class=""mono"">$(& $h $a.id)</span>")
            (& $td (& $h $bpName))
            (& $td (& $h $a.accountEnabled))
            (& $td (& $h (Format-AgentIdDate $a.createdDateTime)) 'date')
            (& $td (& $count $a.sponsors) 'num')
            (& $td $direct 'num')
            (& $td $inherited 'num')
            (& $td $signIn 'date')
            (& $td $riskText)
        )
    }
    & $table @('Agent identity', 'Blueprint', 'Enabled', 'Created', 'Sponsors', 'Direct permissions', 'Inherited permissions', 'Last sign-in', 'Risk') $rows 'No agent identities found.'

    # ---- Agent users
    & $add '<h2>Agent users</h2>'
    $rows = foreach ($u in @($Snapshot.AgentUsers)) {
        if (-not $u) { continue }
        $parent = if ($ctx.AgentById.ContainsKey("$($u.identityParentId)")) { & $h $ctx.AgentById[$u.identityParentId].displayName } elseif ($u.identityParentId) { "<span class=""mono"">$(& $h $u.identityParentId)</span>" } else { $unknown }
        , @(
            (& $td "<strong>$(& $h $u.displayName)</strong><br><span class=""mono"">$(& $h $u.userPrincipalName)</span>")
            (& $td (& $h $u.accountEnabled))
            (& $td $parent)
            (& $td (& $count $u.sponsors) 'num')
        )
    }
    & $table @('Agent user', 'Enabled', 'Parent agent identity', 'Sponsors') $rows 'No agent users found.'

    # ---- Effective access
    & $add '<h2>Effective access</h2>'
    $rows = foreach ($row in ($ctx.AccessRows | Sort-Object PrincipalName, PermissionType, ResourceName, Permission)) {
        $flag = if (Test-AgentIdBlockedPermission $ctx $row) { '<span class="chip Critical">Blocked for agents</span>' }
        elseif (Test-AgentIdSensitivePermission $ctx $row.PermissionType $row.ResourceAppId $row.Permission) { '<span class="chip High">Sensitive</span>' }
        else { '' }
        $consent = if ($row.PermissionType -eq 'Application') { 'n/a' } elseif ($row.ConsentType -eq 'AllPrincipals') { 'All users' } else { 'One user' }
        , @(
            (& $td "<strong>$(& $h $row.PrincipalName)</strong><br><span class=""mono"">$(& $h (Get-AgentIdPrincipalLabel $row.PrincipalKind))</span>")
            (& $td (& $h $row.PermissionType))
            (& $td (& $h $row.ResourceName))
            (& $td "$(& $h $row.Permission) $flag")
            (& $td (& $h $consent))
            (& $td (& $h $row.Source))
        )
    }
    & $table @('Principal', 'Type', 'Resource', 'Permission', 'Consent', 'Source') $rows 'No permission grants found.'

    # ---- Coverage
    & $add '<h2 id="coverage">Collection coverage</h2>'
    $rows = foreach ($p in $Snapshot.Coverage.PSObject.Properties) {
        $c = $p.Value
        , @(
            (& $td (& $h $p.Name))
            (& $td "<span class=""chip $(& $h $c.Status)"">$(& $h $c.Status)</span>")
            (& $td $c.Succeeded 'num')
            (& $td $c.Failed 'num')
            (& $td (& $h $c.Detail))
        )
    }
    & $table @('Data', 'Status', 'Calls succeeded', 'Calls failed', 'Detail') $rows 'No coverage information.'

    # ---- Footer
    & $add '<footer>'
    & $add "<p>Generated by $(ConvertTo-AgentIdHtmlLink $Branding.ProjectUrl "$($Branding.ProductName) $($Snapshot.ToolVersion)"). Collection is read-only; no secret values, certificate contents or tokens are collected.</p>"
    if ($Branding.ContactLine) { & $add "<p>$(& $h $Branding.ContactLine)</p>" }
    & $add '</footer></div></body></html>'

    return $sb.ToString()
}
