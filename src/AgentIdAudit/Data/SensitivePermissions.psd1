# Permissions that are NOT on Microsoft's agent block list (see BlockedPermissions.psd1) but that give an
# agent broad access to organizational data or the ability to act as people. Curated - edit to suit your
# organization's risk appetite. Keys are resource application IDs; values are permission names as published
# by that resource (appRole values for Application, oauth2PermissionScope values for Delegated).
@{
    Application = @{
        # Microsoft Graph
        '00000003-0000-0000-c000-000000000000' = @(
            'AuditLog.Read.All'
            'Calendars.ReadWrite'
            'CallRecords.Read.All'
            'Contacts.Read'
            'Contacts.ReadWrite'
            'Directory.Read.All'
            'Group.Read.All'
            'GroupMember.Read.All'
            'IdentityRiskyUser.Read.All'
            'Mail.Read'
            'Mail.ReadBasic.All'
            'Mail.ReadWrite'
            'Mail.Send'
            'MailboxSettings.ReadWrite'
            'Notes.Read.All'
            'Notes.ReadWrite.All'
            'OnlineMeetingRecording.Read.All'
            'OnlineMeetingTranscript.Read.All'
            'People.Read.All'
            'Policy.Read.All'
            'Reports.Read.All'
            'SecurityEvents.Read.All'
            'TeamMember.ReadWrite.All'
            'User.Read.All'
        )
        # Office 365 Exchange Online
        '00000002-0000-0ff1-ce00-000000000000' = @(
            'Exchange.ManageAsApp'
            'full_access_as_app'
        )
        # Office 365 SharePoint Online - same names as the Graph permissions Microsoft blocks, but published
        # by SharePoint's own API, so the Graph block list does not cover them.
        '00000003-0000-0ff1-ce00-000000000000' = @(
            'Sites.FullControl.All'
            'Sites.Manage.All'
            'Sites.Read.All'
            'Sites.ReadWrite.All'
        )
    }

    # Delegated scopes that are sensitive when consented tenant-wide (consentType AllPrincipals) or made
    # inheritable from a blueprint: the agent can use them on behalf of any user without per-user consent.
    Delegated = @{
        # Microsoft Graph
        '00000003-0000-0000-c000-000000000000' = @(
            'AuditLog.Read.All'
            'Calendars.ReadWrite'
            'Chat.Read'
            'Chat.ReadWrite'
            'Contacts.ReadWrite'
            'Directory.Read.All'
            'EWS.AccessAsUser.All'
            'Files.Read.All'
            'Files.ReadWrite.All'
            'Group.Read.All'
            'Mail.Read'
            'Mail.Read.Shared'
            'Mail.ReadWrite'
            'Mail.Send'
            'Mail.Send.Shared'
            'Notes.ReadWrite.All'
            'Sites.Read.All'
            'Sites.ReadWrite.All'
            'User.Read.All'
        )
        # Office 365 Exchange Online
        '00000002-0000-0ff1-ce00-000000000000' = @(
            'EWS.AccessAsUser.All'
        )
    }

    # Fallback list of privileged Microsoft Entra built-in role template IDs, used only when the tenant's role
    # definitions don't report isPrivileged. Role template IDs are stable across tenants.
    PrivilegedRoleTemplateIds = @{
        '62e90394-69f5-4237-9190-012177145e10' = 'Global Administrator'
        'e8611ab8-c189-46e8-94e1-60213ab1f814' = 'Privileged Role Administrator'
        '7be44c8a-adaf-4e2a-84d6-ab2649e08a13' = 'Privileged Authentication Administrator'
        '9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3' = 'Application Administrator'
        '158c047a-c907-4556-b7ef-446551a6b5f7' = 'Cloud Application Administrator'
        'c4e39bd9-1100-46d3-8c65-fb160da0071f' = 'Authentication Administrator'
        'b1be1c3e-b65d-4f19-8427-f6fa0d97feb9' = 'Conditional Access Administrator'
        '194ae4cb-b126-40b2-bd5b-6091b380977d' = 'Security Administrator'
        'fe930be7-5e62-47db-91af-98c3a49a38b1' = 'User Administrator'
        'fdd7a751-b60b-444a-984c-02652fe8fa1c' = 'Groups Administrator'
        '29232cdf-9323-42fd-ade2-1d097af3e4de' = 'Exchange Administrator'
        'f28a1f50-f6e7-4571-818b-6a12f2af6b6c' = 'SharePoint Administrator'
        '3a2c62db-5318-420d-8d74-23affee5d9d5' = 'Intune Administrator'
        '8ac3fc64-6eca-42ea-9e69-59f4c7b60eb2' = 'Hybrid Identity Administrator'
        '729827e3-9c14-49f7-bb1b-9608f156bbb8' = 'Helpdesk Administrator'
        '9360feb5-f418-4baa-8175-e2a00bac4301' = 'Directory Writers'
    }
}
