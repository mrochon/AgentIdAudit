# Changelog

## Unreleased

- New rules AID-GOV-008 (required) and AID-GOV-009 (optional): agent identities that have no value for the custom security attributes named with `-RequiredSecurityAttribute` / `-OptionalSecurityAttribute`. Off until attribute names are given.
- `-IncludeSecurityAttributes` on `Get-AgentIdInventory`, `Connect-AgentIdAudit` and `Invoke-AgentIdAudit` collects agents' custom security attributes (needs `CustomSecAttributeAssignment.Read.All`). Snapshots store attribute names only, in a new `securityAttributes` property on agent identities.
- Rules can define an `Applies` scriptblock; a rule that doesn't apply is skipped silently rather than reported as not evaluated.

## 0.1.0-preview — 2026-09-18

First preview.

- Read-only inventory of agent identity blueprints, blueprint principals, agent identities and agent users: credential metadata, federated credentials, inheritable permissions, sponsors, owners, direct and inherited grants, directory roles, sign-in activity and Identity Protection risk.
- 23 rules across credentials, permissions, governance, agent users and lifecycle.
- Effective access: direct and inherited permissions resolved to names.
- Self-contained HTML report, findings CSV and JSON snapshots that can be analyzed offline.
- Coverage tracking: checks whose data couldn't be collected are reported as not evaluated, with the reason.
