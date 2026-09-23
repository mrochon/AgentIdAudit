# AgentIdAudit

A read-only security audit for **Microsoft Entra Agent ID**. It inventories the agent identity blueprints, agent identities and agent users in a tenant, works out what each agent can actually access, and reports problems in a single self-contained HTML file.

```PowerShell
Install-Module AgentIdAudit -AllowPrerelease -Scope CurrentUser
Invoke-AgentIdAudit -OutputPath .\agent-audit
```

Or from a clone of this repository: 

```PowerShell
Import-Module ./src/AgentIdAudit
```

To see what a report looks like without running anything, open [samples/sample-report.html](samples/sample-report.html), generated from sample data.

## Why agents need their own audit

Agent identities don't fit the checks written for users or ordinary applications:

- **A blueprint credential is a master key.** Agent identities get their tokens through their blueprint, so whoever holds a blueprint's secret or certificate can act as every agent created from it — including agents created next month.
- **Access is inherited.** An agent's effective permissions are its own grants *plus* what it inherits from its blueprint. The portal shows these in different places; AgentIdAudit puts them in one list.
- **Microsoft blocks the most dangerous Graph permissions for agents — but not everything dangerous.** `Mail.Send` as an application permission isn't blocked, and neither are SharePoint's own `Sites.FullControl.All` and Exchange's `full_access_as_app`. A grant of a blocked permission that exists anyway is its own red flag.
- **Accountability is a sponsor.** Every agent should have a person answerable for it. Sponsors leave; agents stay.

## What it checks

| Rule | Max severity | Check |
|---|---|---|
| AID-CRED-001 | High | Blueprint authenticates with a client secret |
| AID-CRED-002 | Medium | Long-lived blueprint credential |
| AID-CRED-003 | Low | Expired credentials still attached to blueprint |
| AID-CRED-004 | Low | Blueprint has multiple active credentials |
| AID-CRED-005 | Medium | Agent identity has its own credentials |
| AID-CRED-006 | Info | Blueprint credentials expire soon |
| AID-PERM-001 | Critical | Agent holds a permission Microsoft blocks for agents |
| AID-PERM-002 | High | Agent holds a sensitive application permission |
| AID-PERM-003 | Medium | Sensitive delegated permission consented for all users |
| AID-PERM-004 | High | Blueprint lets agents inherit broad delegated permissions |
| AID-PERM-005 | Critical | Agent holds a directory role |
| AID-GOV-001 | Medium | Agent identity has no sponsor |
| AID-GOV-002 | Medium | Sponsor account is disabled |
| AID-GOV-003 | Medium | Blueprint has no sponsor |
| AID-GOV-004 | Medium | Agent identity's blueprint is not in this tenant |
| AID-GOV-005 | Low | Other applications can create agents from this blueprint |
| AID-GOV-006 | Info | Blueprint is available to other tenants |
| AID-GOV-007 | High | Microsoft has disabled this object |
| AID-GOV-008 | Medium | Agent identity is missing required custom security attributes *(opt-in)* |
| AID-GOV-009 | Info | Agent identity is missing optional custom security attributes *(opt-in)* |
| AID-USER-001 | Medium | Agent user has no sponsor |
| AID-USER-002 | Medium | Agent user's parent agent identity not found |
| AID-LIFE-001 | Medium | Agent identity has not signed in recently |
| AID-LIFE-002 | Low | Disabled agent identity still holds permissions |
| AID-LIFE-003 | Critical | Identity Protection flags this agent as risky |

`Get-AgentIdRule` lists each rule with its remediation guidance and a link to Microsoft's documentation.

## How it behaves

- **Read-only.** Every Microsoft Graph call is a GET, and every permission requested is a `.Read` permission.
- **No secrets collected.** Credentials are recorded as metadata only — name, type, validity dates. Secret hints, certificate contents and tokens are never stored: each object is rebuilt from an explicit list of allowed properties.
- **"Not checked" is never reported as "clean".** If data can't be read — a permission wasn't consented, a feature isn't enabled in the tenant — the checks that depend on it are listed as *not evaluated*, with the reason, at the top of the report. They don't silently pass, and they don't produce false findings such as "agent has no sponsor".
- **Point-in-time.** Time-based checks (expiry, staleness) are evaluated as of the moment the snapshot was collected, so a snapshot analyzed later gives the same answers.
- **Safe to open.** The report is one HTML file with no scripts and no external resources. Every value is HTML-encoded — agent names are chosen by whoever creates the agent.

## Permissions

`Connect-AgentIdAudit` requests these delegated, read-only Microsoft Graph permissions (an administrator consents once):

| Permission | Used for |
|---|---|
| AgentIdentity.Read.All | Agent identities |
| AgentIdentityBlueprint.Read.All | Blueprints and inheritable permissions |
| AgentIdentityBlueprintPrincipal.Read.All | Blueprint principals |
| Application.Read.All | Owners, sponsors of blueprints, inherited app role assignments, permission names |
| Directory.Read.All | Delegated permission grants, agent users, tenant name |
| RoleManagement.Read.Directory | Directory role assignments |
| AuditLog.Read.All *(optional)* | Sign-in activity (also needs Microsoft Entra ID P1 or P2) |
| IdentityRiskyAgent.Read.All *(optional)* | Identity Protection risk |
| CustomSecAttributeAssignment.Read.All *(opt-in, `-IncludeSecurityAttributes`)* | Custom security attributes on agent identities (the signed-in account also needs the Attribute Assignment Reader role) |

Use `-SkipOptionalScopes` to request only the first six. To run app-only (for example, from automation), connect with `Connect-MgGraph` and a certificate yourself — the other commands use whichever Graph connection is current.

> **Note on agent sponsors.** Microsoft currently documents the agent identity *sponsors* API as requiring `AgentIdentity.ReadWrite.All`. AgentIdAudit doesn't request write permissions. It first tries to read sponsors with the list call; if the tenant refuses, the sponsor checks are reported as not evaluated rather than guessed.

## Commands

| Command | Purpose |
|---|---|
| `Invoke-AgentIdAudit` | Everything in one step: connect if needed, collect, evaluate, write snapshot + CSV + HTML |
| `Connect-AgentIdAudit` | Connect to Graph with the read-only scopes above |
| `Get-AgentIdInventory` | Collect a snapshot |
| `Export-AgentIdSnapshot` / `Import-AgentIdSnapshot` | Save and load snapshots |
| `Get-AgentIdFinding` | Evaluate a snapshot; filter with `-MinimumSeverity`, `-RuleId`, `-ExcludeRuleId` |
| `Get-AgentIdEffectiveAccess` | What each agent can access, direct and inherited |
| `Export-AgentIdReport` | Write the HTML report |
| `Get-AgentIdRule` | List the rules |

Thresholds are adjustable: `-MaxCredentialLifetimeDays` (default 180), `-StaleAfterDays` (90), `-ExpiringWithinDays` (30).

### Requiring custom security attributes

AID-GOV-008 and AID-GOV-009 check that every agent identity has a value for the custom security attributes you name, written as `AttributeSet.AttributeName`. They are off until you name attributes, and the attributes must be collected, which needs the extra permission above:

```PowerShell
Invoke-AgentIdAudit `
    -RequiredSecurityAttribute Engineering.CostCenter, Engineering.Owner `
    -OptionalSecurityAttribute Engineering.DataClass
```

- **Required** attributes that an agent has no value for are reported at Medium (AID-GOV-008). **Optional** ones are reported at Info (AID-GOV-009); an attribute named in both lists counts as required.
- A blank value, or an empty multi-value list, counts as no value. Names are matched case-insensitively.
- Only the *names* of attributes that have a value are stored in the snapshot, never the values.
- The lists are analysis options, so you can collect once with `Get-AgentIdInventory -IncludeSecurityAttributes` and try different lists later with `Get-AgentIdFinding` or `Export-AgentIdReport`.
- If an agent's attributes can't be read (permission or role missing), that agent is not reported as missing them. When none can be read the checks are listed as not evaluated.

### Collect here, analyze elsewhere

A snapshot is plain JSON. Collect it inside the organization and analyze it anywhere — no Graph connection is needed to evaluate it:

```PowerShell
# In the tenant
Connect-AgentIdAudit
Get-AgentIdInventory | Export-AgentIdSnapshot -Path .\agents.json

# Anywhere
Import-AgentIdSnapshot .\agents.json | Get-AgentIdFinding -MinimumSeverity High
Import-AgentIdSnapshot .\agents.json | Export-AgentIdReport -Path .\agents.html
```

Snapshots contain no secrets, but they do contain names — including the names and user principal names of sponsors and owners. Handle them as internal data.

## Customizing

- **Sensitive permissions** — `src/AgentIdAudit/Data/SensitivePermissions.psd1` lists the non-blocked permissions treated as sensitive. Edit it to match your organization's risk appetite.
- **Blocked permissions** — `Data/BlockedPermissions.psd1` is generated from Microsoft's published table; don't edit it by hand.
- **Report footer** — `Data/Branding.psd1`.

## Status

**Preview.** The Agent ID APIs are in Microsoft Graph beta and still changing. The module is tested against a simulated Graph (see `tests/`) covering collection, paging, permission denials, fallbacks and every rule; please report anything that behaves differently in a real tenant.

Requires PowerShell 7.2 or later and the `Microsoft.Graph.Authentication` module.

## Development

```PowerShell
./tests/Invoke-Tests.ps1          # full test suite against the fake Graph; no tenant needed
./tools/New-SampleReport.ps1      # regenerate samples/
```

## License

MIT
