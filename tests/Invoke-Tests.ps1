#Requires -Version 7.2
<#
Runs the AgentIdAudit test suite against a fake Microsoft Graph (see FakeTenant.ps1). No tenant, network access
or extra modules are needed. Exits with code 1 if any assertion fails.
#>
[CmdletBinding()]
param([switch]$KeepOutput)

$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src\AgentIdAudit\AgentIdAudit.psd1') -Force
. (Join-Path $PSScriptRoot 'FakeTenant.ps1')

$script:passed = 0
$script:failed = 0
function Assert {
    param([bool]$Condition, [string]$Message)
    if ($Condition) { $script:passed++ } else { $script:failed++; Write-Host "  FAIL: $Message" -ForegroundColor Red }
}
function Section { param([string]$Name) Write-Host "- $Name" -ForegroundColor Cyan }
function InModule { param([scriptblock]$Script, [object[]]$Arguments) & (Get-Module AgentIdAudit) $Script @Arguments }

$asOf = [datetimeoffset]'2026-09-18T12:00:00Z'
$out = Join-Path ([System.IO.Path]::GetTempPath()) ("agentidaudit-tests-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $out | Out-Null

try {
    # ------------------------------------------------------------------------------------------------ A
    Section 'Scenario A: collection'
    $fake = New-FakeGraphHandler (New-FakeTenant -Scenario A)
    Set-FakeGraph $fake.Handler
    $snap = Get-AgentIdInventory
    Assert ($snap.PSObject.TypeNames[0] -eq 'AgentIdAudit.Snapshot') 'snapshot has the AgentIdAudit.Snapshot type name'
    Assert ($snap.TenantName -eq 'Contoso (sample data)') 'tenant name collected'
    Assert (@($snap.Blueprints).Count -eq 3) "3 blueprints (got $(@($snap.Blueprints).Count))"
    Assert (@($snap.AgentIdentities).Count -eq 4) "4 agent identities across two pages (got $(@($snap.AgentIdentities).Count))"
    Assert (@($snap.AgentUsers).Count -eq 2) 'agent users collected via the fallback URI after the $select variant was rejected'
    Assert (@($snap.DirectoryRoleAssignments).Count -eq 2) 'role assignments filtered to agent principals (human Global Administrator excluded)'
    Assert (@($snap.Resources).Count -eq 2) 'two resource service principals resolved'
    $notOk = @($snap.Coverage.PSObject.Properties | Where-Object { $_.Value.Status -ne 'Ok' } | ForEach-Object { "$($_.Name)=$($_.Value.Status)" })
    Assert ($notOk.Count -eq 0) "all coverage Ok in scenario A (not Ok: $($notOk -join ', '))"
    $expectedUnrouted = @('servicePrincipals/microsoft.graph.agentIdentity?$expand=sponsors')
    Assert (@($fake.Unrouted).Count -eq 0) "no requests to unknown routes (got: $($fake.Unrouted -join '; '))"
    Assert ($fake.Calls -contains $expectedUnrouted[0]) 'tried $expand=sponsors first'
    Assert (@($fake.Calls | Where-Object { $_ -like '*agentIdentity/sponsors*' }).Count -eq 4) 'fell back to per-agent sponsor calls after $expand was rejected'

    Section 'Scenario A: no secret material in the snapshot'
    $json = $snap | ConvertTo-Json -Depth 32
    Assert ($json -notmatch 'SUPERSECRET') 'secretText is not stored'
    Assert ($json -notmatch 'Q7x|Zz9') 'secret hints are not stored'
    Assert ($json -notmatch '"hint"') 'no hint property at all'
    Assert ($json -notmatch 'MIIBASE64CERTDATA') 'certificate key material is not stored'

    Section 'Scenario A: unknown vs empty'
    $a1 = $snap.AgentIdentities | Where-Object id -EQ 'a1'
    Assert ($null -ne $a1.sponsors -and @($a1.sponsors).Count -eq 0) 'an agent with no sponsors has an empty list, not $null'
    Assert ($snap.SignInActivity.Count -eq 4) 'a sign-in entry for every agent looked up'
    $a3SignIn = $snap.SignInActivity | Where-Object appId -EQ 'a3-app'
    Assert ($null -ne $a3SignIn -and $null -eq $a3SignIn.lastSignInDateTime) 'an agent that never signed in has an entry with a null date'

    Section 'Scenario A: effective access'
    $access = @($snap | Get-AgentIdEffectiveAccess -Name 'Sales Agent')
    $describe = { param($rows) ($rows | ForEach-Object { "$($_.Source)|$($_.PermissionType)|$($_.Permission)|$($_.ConsentType)" } | Sort-Object) -join ';' }
    $expectedA1 = 'Direct|Application|Directory.ReadWrite.All|;Direct|Delegated|Mail.Read|AllPrincipals;Direct|Delegated|User.Read|AllPrincipals;Inherited|Application|Mail.Send|'
    Assert ((& $describe $access) -eq $expectedA1) "Sales Agent effective access resolved (got $(& $describe $access))"
    $a2Access = @($snap | Get-AgentIdEffectiveAccess -Name 'HR Agent' | Where-Object PermissionType -EQ 'Application')
    Assert ($a2Access.Count -eq 1 -and $a2Access[0].Permission -eq '(default access)') 'default-access app role shown as (default access)'
    $bpAccess = @($snap | Get-AgentIdEffectiveAccess -PrincipalKind BlueprintPrincipal)
    Assert ($bpAccess.Count -eq 1 -and $bpAccess[0].Permission -eq 'Mail.Send') 'blueprint principal access listed'

    Section 'Scenario A: findings are exactly the expected set'
    $findings = @($snap | Get-AgentIdFinding -AsOf $asOf -WarningVariable warnings -WarningAction SilentlyContinue)
    $actual = @($findings | ForEach-Object { "$($_.RuleId) $($_.ObjectId)" } | Sort-Object)
    $expected = @(
        'AID-CRED-001 bp1', 'AID-CRED-002 bp1', 'AID-CRED-003 bp1', 'AID-CRED-004 bp1', 'AID-CRED-005 a3', 'AID-CRED-006 bp3'
        'AID-PERM-001 a1', 'AID-PERM-002 bpp1', 'AID-PERM-002 a3', 'AID-PERM-003 a1', 'AID-PERM-004 bp1', 'AID-PERM-005 a1', 'AID-PERM-005 u2'
        'AID-GOV-001 a1', 'AID-GOV-002 a3', 'AID-GOV-003 bp1', 'AID-GOV-004 a4', 'AID-GOV-005 bp1', 'AID-GOV-006 bp1', 'AID-GOV-007 a4'
        'AID-USER-001 u1', 'AID-USER-002 u2'
        'AID-LIFE-001 a1', 'AID-LIFE-001 a3', 'AID-LIFE-002 a3', 'AID-LIFE-003 a1'
    ) | Sort-Object
    $missing = @($expected | Where-Object { $_ -notin $actual })
    $extra = @($actual | Where-Object { $_ -notin $expected })
    Assert ($missing.Count -eq 0) "missing findings: $($missing -join ', ')"
    Assert ($extra.Count -eq 0) "unexpected findings (false positives): $($extra -join ', ')"
    Assert (@($warnings).Count -eq 0) "no rules skipped in scenario A (warnings: $($warnings -join ' / '))"
    $cleanObjects = 'bp2', 'bpp2', 'bpp3', 'a2'
    Assert (-not ($findings | Where-Object ObjectId -In $cleanObjects)) 'clean objects (HR Blueprint, HR Agent) produce no findings'
    Assert (-not ($findings | Where-Object { $_.RuleId -eq 'AID-PERM-002' -and $_.ObjectId -eq 'a1' })) 'inherited Mail.Send reported once, on the blueprint principal, not repeated per agent'

    Section 'Scenario A: severities and wording'
    $sev = { param($rule, $obj) ($findings | Where-Object { $_.RuleId -eq $rule -and $_.ObjectId -eq $obj }).Severity }
    Assert ((& $sev 'AID-PERM-005' 'a1') -eq 'Critical') 'Global Administrator on an agent is Critical'
    Assert ((& $sev 'AID-PERM-005' 'u2') -eq 'Medium') 'non-privileged role on an agent user is Medium'
    Assert ((& $sev 'AID-PERM-004' 'bp1') -eq 'High') 'allAllowed inheritance is High'
    Assert ((& $sev 'AID-LIFE-003' 'a1') -eq 'High') 'atRisk/high agent is High'
    Assert ($findings[0].Severity -eq 'Critical' -and $findings[-1].Severity -eq 'Info') 'findings sorted most severe first'
    $cred1 = $findings | Where-Object { $_.RuleId -eq 'AID-CRED-001' }
    Assert ($cred1.Detail -match 'the 1 agent identity created from this blueprint') "secret finding states blast radius (got: $($cred1.Detail))"
    $cred2 = $findings | Where-Object { $_.RuleId -eq 'AID-CRED-002' }
    Assert ($cred2.Detail -match '2299-12-31' -and $cred2.Detail -match 'CN=sales') 'long-lived finding lists both the secret and the certificate'
    $perm2 = $findings | Where-Object { $_.RuleId -eq 'AID-PERM-002' -and $_.ObjectId -eq 'bpp1' }
    Assert ($perm2.Detail -match 'inherited by the 1 agent identity') 'blueprint-principal permission states that agents inherit it'

    Section 'Filtering'
    $high = @($snap | Get-AgentIdFinding -AsOf $asOf -MinimumSeverity High)
    Assert ($high.Count -gt 0 -and -not ($high | Where-Object Severity -NotIn 'Critical', 'High')) '-MinimumSeverity High'
    $credOnly = @($snap | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-CRED-*')
    Assert ($credOnly.Count -eq 6 -and -not ($credOnly | Where-Object RuleId -NotLike 'AID-CRED-*')) '-RuleId wildcard'
    $noCred = @($snap | Get-AgentIdFinding -AsOf $asOf -ExcludeRuleId 'AID-CRED-*')
    Assert ($noCred.Count -eq ($findings.Count - 6)) '-ExcludeRuleId wildcard'
    $lenient = @($snap | Get-AgentIdFinding -AsOf $asOf -MaxCredentialLifetimeDays 200 -RuleId 'AID-CRED-002')
    Assert ($lenient.Count -eq 1 -and $lenient[0].Detail -notmatch 'CN=sales') '-MaxCredentialLifetimeDays changes the threshold'

    Section 'Custom security attributes: opt-in collection'
    Assert (-not ($snap.Coverage.PSObject.Properties.Name -contains 'AgentSecurityAttributes')) 'security attributes are not collected unless requested'
    Assert (-not ($fake.Calls | Where-Object { $_ -like '*customSecurityAttributes*' })) 'no security attribute requests unless requested'
    $null = $snap | Get-AgentIdFinding -AsOf $asOf -RequiredSecurityAttribute 'Engineering.CostCenter' -WarningVariable notCollected -WarningAction SilentlyContinue
    Assert (@($notCollected | Where-Object { $_.Message -match '^AID-GOV-008 .*AgentSecurityAttributes NotCollected' }).Count -eq 1) "a configured rule on a snapshot without the data is reported as not evaluated (got: $($notCollected -join ' / '))"

    $fake = New-FakeGraphHandler (New-FakeTenant -Scenario A)
    Set-FakeGraph $fake.Handler
    $snapAttr = Get-AgentIdInventory -IncludeSecurityAttributes
    Assert ($snapAttr.Coverage.AgentSecurityAttributes.Status -eq 'Ok') "AgentSecurityAttributes coverage Ok (got $($snapAttr.Coverage.AgentSecurityAttributes.Status))"
    Assert (@($fake.Calls | Where-Object { $_ -like '*customSecurityAttributes*' }).Count -eq 4) 'one attribute request per agent identity'
    Assert (@($fake.Unrouted).Count -eq 0) "no requests to unknown routes (got: $($fake.Unrouted -join '; '))"
    $names = { param($id) (($snapAttr.AgentIdentities | Where-Object id -EQ $id).securityAttributes | Sort-Object) -join ',' }
    Assert ((& $names 'a1') -eq 'Engineering.CostCenter,Engineering.Project') "a1 attribute names (got $(& $names 'a1'))"
    Assert ((& $names 'a4') -eq 'Engineering.CostCenter,Finance.Region') "a4: empty value and annotations are not attributes (got $(& $names 'a4'))"
    $a3Attr = ($snapAttr.AgentIdentities | Where-Object id -EQ 'a3').securityAttributes
    Assert ($null -ne $a3Attr -and @($a3Attr).Count -eq 0) 'an agent with no attributes has an empty list, not $null'
    Assert (($snapAttr | ConvertTo-Json -Depth 32) -notmatch 'Baker|Cascade|EMEA|Internal') 'attribute values are not stored'
    $unit = InModule { param($j) ConvertTo-AgentIdSecurityAttributeName ($j | ConvertFrom-Json) } @('{"S":{"@odata.type":"x","A@odata.type":"#Collection(String)","A":[],"B":"  ","C":false,"D":0,"E":["x"],"F":null}}')
    Assert ((@($unit) -join ',') -eq 'S.C,S.D,S.E') "empty collection, blank string and null are not values; false and 0 are (got $(@($unit) -join ','))"

    Section 'Custom security attributes: rules'
    $required = 'Engineering.CostCenter', 'Engineering.Project'
    $optional = 'Engineering.DataClass'
    $attrFindings = @($snapAttr | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-00[89]' -RequiredSecurityAttribute $required -OptionalSecurityAttribute $optional -WarningVariable attrWarnings -WarningAction SilentlyContinue)
    $attrActual = @($attrFindings | ForEach-Object { "$($_.RuleId) $($_.ObjectId)" } | Sort-Object)
    $attrExpected = @('AID-GOV-008 a3', 'AID-GOV-008 a4', 'AID-GOV-009 a1', 'AID-GOV-009 a3', 'AID-GOV-009 a4')
    Assert (($attrActual -join ',') -eq ($attrExpected -join ',')) "required and optional findings (got $($attrActual -join ', '))"
    Assert (@($attrWarnings).Count -eq 0) 'no warnings when the data was collected'
    $req3 = $attrFindings | Where-Object { $_.RuleId -eq 'AID-GOV-008' -and $_.ObjectId -eq 'a3' }
    $req4 = $attrFindings | Where-Object { $_.RuleId -eq 'AID-GOV-008' -and $_.ObjectId -eq 'a4' }
    Assert ($req3.Severity -eq 'Medium' -and $req3.Detail -match 'Engineering\.CostCenter, Engineering\.Project') 'a3 lacks both required attributes'
    Assert ($req4.Detail -match 'Engineering\.Project' -and $req4.Detail -notmatch 'CostCenter') 'a4 lacks only Project (empty string is not a value)'
    Assert (($attrFindings | Where-Object RuleId -EQ 'AID-GOV-009' | Select-Object -First 1).Severity -eq 'Info') 'optional attribute findings are Info'
    Assert (-not ($attrFindings | Where-Object ObjectId -EQ 'a2')) 'an agent with every attribute produces no findings'
    $none = @($snapAttr | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-00[89]' -WarningVariable noneWarn -WarningAction SilentlyContinue)
    Assert ($none.Count -eq 0 -and @($noneWarn).Count -eq 0) 'without attribute names the rules do nothing and do not warn'
    $reqOnly = @($snapAttr | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-00[89]' -RequiredSecurityAttribute $required)
    Assert (-not ($reqOnly | Where-Object RuleId -EQ 'AID-GOV-009')) 'no optional findings when no optional attributes are named'
    $cased = @($snapAttr | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-008' -RequiredSecurityAttribute 'engineering.COSTCENTER')
    Assert (($cased.ObjectId -join ',') -eq 'a3') "attribute names are matched case-insensitively (got $($cased.ObjectId -join ','))"
    $both = @($snapAttr | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-00[89]' -RequiredSecurityAttribute 'Engineering.Project' -OptionalSecurityAttribute 'Engineering.Project', 'Engineering.DataClass')
    Assert (-not ($both | Where-Object { $_.RuleId -eq 'AID-GOV-009' -and $_.Detail -match 'Project' })) 'an attribute in both lists is treated as required'
    $threw = $false; try { $snapAttr | Get-AgentIdFinding -RequiredSecurityAttribute 'NoDot' | Out-Null } catch { $threw = $_.Exception.Message -match 'AttributeSet\.AttributeName' }
    Assert $threw 'attribute names must be AttributeSet.AttributeName'

    Section 'Custom security attributes: partial and denied'
    $routes = New-FakeTenant -Scenario A
    $routes['servicePrincipals/a1?$select=id,customSecurityAttributes'] = ConvertTo-FakeGraphObject @{ id = 'a1' }
    Set-FakeGraph (New-FakeGraphHandler $routes).Handler
    $snapP = Get-AgentIdInventory -IncludeSecurityAttributes
    Assert ($snapP.Coverage.AgentSecurityAttributes.Status -eq 'Partial') "a response without the property makes coverage Partial (got $($snapP.Coverage.AgentSecurityAttributes.Status))"
    Assert ($null -eq ($snapP.AgentIdentities | Where-Object id -EQ 'a1').securityAttributes) 'unreadable attributes stored as unknown ($null), never as empty'
    $partial = @($snapP | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-008' -RequiredSecurityAttribute $required)
    Assert ((($partial.ObjectId | Sort-Object) -join ',') -eq 'a3,a4') "agent with unknown attributes is skipped, not reported (got $($partial.ObjectId -join ','))"

    Set-FakeGraph (New-FakeGraphHandler (New-FakeTenant -Scenario B)).Handler
    $snapD = Get-AgentIdInventory -IncludeSecurityAttributes
    Assert ($snapD.Coverage.AgentSecurityAttributes.Status -eq 'Denied') "AgentSecurityAttributes Denied (got $($snapD.Coverage.AgentSecurityAttributes.Status))"
    $denied = @($snapD | Get-AgentIdFinding -AsOf $asOf -RequiredSecurityAttribute $required -WarningVariable deniedWarn -WarningAction SilentlyContinue | Where-Object RuleId -EQ 'AID-GOV-008')
    Assert ($denied.Count -eq 0) 'no missing-attribute findings from data that could not be read'
    Assert (@($deniedWarn | Where-Object { $_.Message -match '^AID-GOV-008 .*AgentSecurityAttributes Denied' }).Count -eq 1) 'rule reported as not evaluated with the reason'

    Section 'Snapshot export and import'
    $file = Export-AgentIdSnapshot -Snapshot $snap -Path (Join-Path $out 'snap.json')
    $reloaded = Import-AgentIdSnapshot $file.FullName
    $again = @($reloaded | Get-AgentIdFinding -AsOf $asOf | ForEach-Object { "$($_.RuleId) $($_.ObjectId)" } | Sort-Object)
    Assert (($again -join ',') -eq ($actual -join ',')) 'identical findings from a reloaded snapshot'
    $bad = Join-Path $out 'bad.json'
    '{"hello":"world"}' | Set-Content $bad
    $threw = $false; try { Import-AgentIdSnapshot $bad | Out-Null } catch { $threw = $_.Exception.Message -match 'not an AgentIdAudit snapshot' }
    Assert $threw 'Import rejects files that are not snapshots'
    $future = Join-Path $out 'future.json'
    (Get-Content $file.FullName -Raw) -replace '"SchemaVersion": 1', '"SchemaVersion": 99' | Set-Content $future
    $threw = $false; try { Import-AgentIdSnapshot $future | Out-Null } catch { $threw = $_.Exception.Message -match 'newer' }
    Assert $threw 'Import rejects snapshots from a newer schema'

    Section 'HTML report'
    $report = Export-AgentIdReport -Snapshot $snap -Path (Join-Path $out 'report.html') -AsOf $asOf
    $html = Get-Content $report.FullName -Raw
    Assert ($html -match '&lt;script&gt;alert\(1\)&lt;/script&gt; Orphan Agent') 'hostile display name is HTML-encoded'
    Assert ($html -notmatch '<script') 'report contains no script elements'
    Assert ($html -notmatch '<link|src="http|@import') 'report loads no external resources'
    foreach ($t in ($findings.Title | Sort-Object -Unique)) { Assert ($html.Contains([System.Net.WebUtility]::HtmlEncode($t))) "report includes finding '$t'" }
    Assert ($html -match 'Contoso \(sample data\)') 'report names the tenant'
    Assert ($html -notmatch 'could not run') 'no not-evaluated callout when everything was collected'

    # ------------------------------------------------------------------------------------------------ B
    Section 'Scenario B: denied sponsors and Identity Protection'
    $fake = New-FakeGraphHandler (New-FakeTenant -Scenario B)
    Set-FakeGraph $fake.Handler
    $snapB = Get-AgentIdInventory
    Assert (@($snapB.AgentIdentities).Count -eq 4) 'agent list still collected when $expand=sponsors is denied'
    Assert ($snapB.Coverage.AgentIdentities.Status -eq 'Ok') 'AgentIdentities coverage Ok'
    Assert ($snapB.Coverage.AgentSponsors.Status -eq 'Denied') "AgentSponsors Denied (got $($snapB.Coverage.AgentSponsors.Status))"
    Assert ($snapB.Coverage.RiskyAgents.Status -eq 'Denied') 'RiskyAgents Denied'
    Assert (-not ($snapB.AgentIdentities | Where-Object { $null -ne $_.sponsors })) 'unreadable sponsors stored as unknown ($null), never as empty'
    $findingsB = @($snapB | Get-AgentIdFinding -AsOf $asOf -WarningVariable warningsB -WarningAction SilentlyContinue)
    Assert (-not ($findingsB | Where-Object RuleId -In 'AID-GOV-001', 'AID-GOV-002', 'AID-LIFE-003')) 'no sponsor or risk findings from data that could not be read'
    $skipped = @($warningsB | ForEach-Object { ($_.Message -split ' ')[0] } | Sort-Object)
    Assert (($skipped -join ',') -eq 'AID-GOV-001,AID-GOV-002,AID-LIFE-003') "exactly the dependent rules reported as not evaluated (got $($skipped -join ','))"
    $reportB = Export-AgentIdReport -Snapshot $snapB -Path (Join-Path $out 'reportB.html') -AsOf $asOf
    $htmlB = Get-Content $reportB.FullName -Raw
    Assert ($htmlB -match '3 check\(s\) could not run') 'report calls out the checks that could not run'
    Assert ($htmlB -match 'AgentSponsors Denied') 'report explains why'

    # ------------------------------------------------------------------------------------------------ C
    Section 'Scenario C: sponsors via $expand'
    $fake = New-FakeGraphHandler (New-FakeTenant -Scenario C)
    Set-FakeGraph $fake.Handler
    $snapC = Get-AgentIdInventory
    Assert (-not ($fake.Calls | Where-Object { $_ -like '*agentIdentity/sponsors*' })) 'no per-agent sponsor calls when $expand works'
    Assert ($snapC.Coverage.AgentSponsors.Status -eq 'Ok') 'AgentSponsors Ok from $expand'
    $gov = @($snapC | Get-AgentIdFinding -AsOf $asOf -RuleId 'AID-GOV-00[12]' | ForEach-Object { "$($_.RuleId) $($_.ObjectId)" } | Sort-Object)
    Assert (($gov -join ',') -eq 'AID-GOV-001 a1,AID-GOV-002 a3') "sponsor findings identical via either path (got $($gov -join ','))"

    Section 'Skip switches'
    $snapS = Get-AgentIdInventory -SkipSignInActivity -SkipRisk
    Assert ($snapS.Coverage.SignInActivity.Status -eq 'Skipped' -and $snapS.Coverage.RiskyAgents.Status -eq 'Skipped') 'skipped data recorded as Skipped'
    Assert (-not ($fake.Calls | Select-Object -Last 40 | Where-Object { $_ -like 'reports/*' -or $_ -like 'identityProtection/*' })) 'skipped data not requested'

    Section 'Invoke-AgentIdAudit end to end'
    $summary = Invoke-AgentIdAudit -OutputPath (Join-Path $out 'audit') -WarningAction SilentlyContinue
    Assert ((Test-Path $summary.Report) -and (Test-Path $summary.Findings) -and (Test-Path $summary.Snapshot)) 'report, findings CSV and snapshot written'
    $csv = @(Import-Csv $summary.Findings)
    Assert ($csv.Count -eq ($summary.Critical + $summary.High + $summary.Medium + $summary.Low + $summary.Info)) 'CSV row count matches the summary'
    Assert ($summary.AgentIdentities -eq 4 -and $summary.Blueprints -eq 3) 'summary counts'
    $summaryAttr = Invoke-AgentIdAudit -OutputPath (Join-Path $out 'audit-attr') -RequiredSecurityAttribute 'Engineering.CostCenter', 'Engineering.Project' -WarningAction SilentlyContinue
    $csvAttr = @(Import-Csv $summaryAttr.Findings | Where-Object RuleId -EQ 'AID-GOV-008')
    Assert ($csvAttr.Count -eq 2) "naming required attributes collects them and reports findings (got $($csvAttr.Count))"

    # ------------------------------------------------------------------------------------------------ units
    Section 'Error classification'
    $classify = { param($message) InModule { param($m) try { throw $m } catch { (Get-AgentIdErrorStatus $_).AgentIdStatus } } @($message) }
    Assert ((& $classify 'Response status code does not indicate success: Forbidden (Forbidden).') -eq 'Denied') '403 -> Denied'
    Assert ((& $classify 'Authorization_RequestDenied: Insufficient privileges to complete the operation.') -eq 'Denied') 'Graph error code -> Denied'
    Assert ((& $classify 'Response status code does not indicate success: NotFound (Not Found).') -eq 'NotSupported') '404 -> NotSupported'
    Assert ((& $classify 'Response status code does not indicate success: BadRequest (Bad Request).') -eq 'NotSupported') '400 -> NotSupported'
    Assert ((& $classify 'The operation has timed out.') -eq 'Error') 'other -> Error'
    $viaResponse = InModule {
        $ex = [System.Exception]::new('opaque failure')
        $ex | Add-Member -NotePropertyName Response -NotePropertyValue ([pscustomobject]@{ StatusCode = [System.Net.HttpStatusCode]::Forbidden })
        try { throw [System.Management.Automation.ErrorRecord]::new($ex, 'x', 'NotSpecified', $null) } catch { (Get-AgentIdErrorStatus $_).AgentIdStatus }
    }
    Assert ($viaResponse -eq 'Denied') 'status code read from the exception''s Response when present'

    Section 'Rules and manifest'
    $rules = @(Get-AgentIdRule)
    Assert ($rules.Count -eq 25) "25 rules (got $($rules.Count))"
    Assert (-not ($rules | Where-Object { $_.Reference -notmatch '^https://learn\.microsoft\.com/' })) 'every rule references Microsoft documentation'
    $manifest = Test-ModuleManifest (Join-Path $root 'src\AgentIdAudit\AgentIdAudit.psd1')
    $exported = @($manifest.ExportedFunctions.Keys | Sort-Object)
    $available = @((Get-Command -Module AgentIdAudit).Name | Sort-Object)
    Assert (($exported -join ',') -eq ($available -join ',')) 'manifest exports match the module''s public commands'
    $blocked = InModule { $script:AgentIdBlockedPermissions }
    Assert ($blocked.Application.Count -eq 55 -and $blocked.Delegated.Count -eq 19) 'blocked-permission list matches Microsoft''s table (55 application, 19 delegated)'
} finally {
    Set-FakeGraph $null
    if ($KeepOutput) { Write-Host "Output kept in $out" } else { Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue }
}

Write-Host ''
$color = if ($script:failed) { 'Red' } else { 'Green' }
Write-Host ("{0} passed, {1} failed" -f $script:passed, $script:failed) -ForegroundColor $color
if ($script:failed) { exit 1 }
