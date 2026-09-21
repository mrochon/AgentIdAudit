#Requires -Version 7.2
<#
Regenerates samples/sample-report.html and samples/sample-snapshot.json from the fake tenant used by the tests.
The sample shows what the report looks like without anyone having to run the audit against a real tenant.
#>
$root = Split-Path $PSScriptRoot -Parent
Import-Module (Join-Path $root 'src\AgentIdAudit\AgentIdAudit.psd1') -Force
. (Join-Path $root 'tests\FakeTenant.ps1')

$samples = Join-Path $root 'samples'
New-Item -ItemType Directory -Force -Path $samples | Out-Null
$fake = New-FakeGraphHandler (New-FakeTenant -Scenario A)
Set-FakeGraph $fake.Handler
try {
    $snapshot = Get-AgentIdInventory
    Export-AgentIdSnapshot -Snapshot $snapshot -Path (Join-Path $samples 'sample-snapshot.json') | Out-Null
    Export-AgentIdReport -Snapshot $snapshot -Path (Join-Path $samples 'sample-report.html') -AsOf ([datetimeoffset]'2026-09-18T12:00:00Z')
} finally {
    Set-FakeGraph $null
}
