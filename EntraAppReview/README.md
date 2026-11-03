# Microsoft Entra Application Review Collector

`Invoke-EntraAppReview.ps1` collects Microsoft Entra app registrations, enterprise applications, API permissions, and client-secret expiration metadata for offline review. It uses read-only Microsoft Graph requests and does not modify applications, permission grants, or credentials.

The primary output, `dashboard.html`, is a self-contained application triage dashboard sorted from highest to lowest granted API permission priority. The companion `inventory.json` contains the complete structured inventory.

Requested permissions are shown separately from granted access. Client-secret values and hints are not exported.

## What the script collects

Every run collects:

- App registrations, including registrations without a tenant service principal
- Enterprise applications and other service principals, including Microsoft applications, third-party applications, managed identities, and disabled applications
- Granted application permissions from each client's `appRoleAssignments`
- Granted delegated permissions from `oauth2PermissionGrants`, distinguishing tenant-wide and per-user consent
- Requested API permissions from each local registration's `requiredResourceAccess`
- API names and permission definitions, resolved where available from tenant service principals or local app registrations
- Client-secret metadata from application and service-principal `passwordCredentials`: display name, key ID, source object, UTC start and expiration dates, days remaining, expiration state, and not-yet-valid status
- Application and object identifiers, collection timestamps, triage scores, classification reasons, and warnings

Registrations and service principals are linked by application/client ID. The dashboard has one review row per service principal plus any registration without a service principal. Registration counts, service-principal counts, and review-row counts are therefore reported separately.

Grants remain visible even when they are no longer declared in a registration's requested permission list. Delegated consent user IDs are retained; user profiles are not queried.

The script follows Graph pagination and retries transient failures and throttling with bounded attempts and `Retry-After` support. A failed collection stops the run rather than displaying missing permissions as zero access. Unresolved permissions, unknown secret expiration dates, and delegated grants referencing absent client principals are surfaced for review.

## Requirements

- Windows PowerShell 5.1 or PowerShell 7 on Windows
- The `Microsoft.Graph.Authentication` PowerShell module
- A Microsoft Entra tenant ID
- An account with appropriate active tenant roles, such as Directory Readers, and the required admin-consented Graph permission
- A modern browser, such as Microsoft Edge or Google Chrome, for the dashboard

Install the required module for the current user:

```powershell
Install-Module Microsoft.Graph.Authentication -Scope CurrentUser
```

Follow your organization's consent, PIM activation, and script-signing policies. The script does not install dependencies automatically or bypass PowerShell execution policy. Global Administrator is not required just to run the inventory after consent has been approved.

## Graph permissions

| Connection mode | Microsoft Graph permission |
| --- | --- |
| New interactive connection | Delegated `Directory.Read.All` |
| Existing delegated connection | Delegated `Directory.Read.All` |
| Existing app-only connection | Application `Directory.Read.All` |

`Directory.Read.All` is broad, read-only directory access. It covers application inventory, app-role assignments, and delegated consent grants. An authorized administrator must approve the permission; the signed-in operator must also have the appropriate tenant role for delegated collection.

The script does not request write permissions. For app-only collection, configure the reader application's permission and administrator consent before running the script.

A new interactive connection uses a process-scoped Graph context and is disconnected when the run ends. Existing connections are reused without being disconnected. The connected tenant and cloud environment are checked before collection.

## Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-TenantId` | Required | GUID of the tenant to inventory. |
| `-OutputDirectory` | A timestamped `EntraReview-yyyyMMdd-HHmmss` folder in the current directory | Sets the output directory. The parent must exist and the output directory must be new. |
| `-ExpiringInDays` | `30` | Number of days used to flag upcoming client-secret expiration. Valid range is 1 through 3650. |
| `-Environment` | `Global` | Selects `Global`, `USGov`, `USGovDoD`, or `China`. Must match an existing connection when one is reused. |
| `-UseExistingConnection` | Off | Reuses an existing Microsoft Graph connection instead of starting interactive authentication. |
| `-NoOpen` | Off | Generates the report without automatically opening the dashboard. |

Previous report directories are not overwritten. Output files are staged after collection completes and then published to the new output directory.

## Run examples

Open PowerShell in this folder, then run one of the following commands.

Collect the tenant inventory and open the dashboard:

```powershell
.\Invoke-EntraAppReview.ps1 -TenantId 'YOUR-TENANT-GUID'
```

Use a 60-day secret-expiration window and a specific new output directory:

```powershell
.\Invoke-EntraAppReview.ps1 -TenantId 'YOUR-TENANT-GUID' `
    -OutputDirectory 'C:\Reports\EntraReview-CustomerA' `
    -ExpiringInDays 60
```

The `C:\Reports` parent directory must already exist.

Generate the files without opening a browser:

```powershell
.\Invoke-EntraAppReview.ps1 -TenantId 'YOUR-TENANT-GUID' -NoOpen
```

Reuse a delegated Graph connection:

```powershell
Connect-MgGraph -TenantId 'YOUR-TENANT-GUID' -Scopes 'Directory.Read.All'

.\Invoke-EntraAppReview.ps1 -TenantId 'YOUR-TENANT-GUID' `
    -UseExistingConnection
```

Reuse a certificate-based app-only connection:

```powershell
Connect-MgGraph -TenantId 'YOUR-TENANT-GUID' `
    -ClientId 'READER-APP-GUID' `
    -CertificateThumbprint 'CERTIFICATE-THUMBPRINT'

.\Invoke-EntraAppReview.ps1 -TenantId 'YOUR-TENANT-GUID' `
    -UseExistingConnection -NoOpen
```

Collect from a US Government tenant:

```powershell
.\Invoke-EntraAppReview.ps1 -TenantId 'YOUR-TENANT-GUID' -Environment USGov
```

For an existing non-Global connection, also pass the matching `-Environment`.

## Output files

Each successful run creates these files in the output directory:

| File | Purpose |
| --- | --- |
| `dashboard.html` | Self-contained application, permission, and client-secret triage dashboard. Opens automatically unless `-NoOpen` is used. |
| `inventory.json` | Complete inventory, including every collected permission/grant entry, credential metadata, scores, classification reasons, warnings, identifiers, and collection timestamps. |

The HTML embeds the inventory. Open `dashboard.html` directly in a browser; no JSON import, web server, CDN, or external dashboard dependency is required.

## Review dashboard

The dashboard supports:

- Search by application name, application/object ID, API, permission, or consent user ID
- Filters for priority, application type, granted access, manual classification, and client-secret expiration
- Sorting by highest or lowest privilege priority, application name, or earliest known secret expiration
- Per-application drilldowns showing granted permissions, requested permissions, observed consent status, scoring reasons, and client-secret metadata
- Inventory-wide summary cards and paginated results with 50 applications per page

Summary cards always describe the full inventory, not just the current filtered results.

Secret expiration is evaluated at collection start in UTC. Days remaining are rounded down: a secret expiring in a few hours has zero days remaining but is not yet expired. Missing expiration dates are labeled explicitly, and future start dates are flagged as not yet valid. Collect a fresh report for current expiration status.

Application and service-principal credential entries remain distinct, even if they share a key ID. Summary cards deduplicate the same source-object/key ID if it appears across linked rows.

## Privilege priority

The score is a transparent triage heuristic, not a formal risk rating or a calculation of effective access.

Only **granted API permissions** contribute to the application score. The score is the highest permission weight plus one point per additional distinct resource/type/permission, capped at a five-point breadth adjustment and a total score of 100. Repeated per-user consent for the same scope does not inflate the score.

| Permission category | Application weight | Delegated weight |
| --- | --- | --- |
| Recognized Microsoft Graph identity, credential, application, or consent control | 95 | 80 |
| Broad write/full control, mail sending, owned-application management, or mail/calendar/contact/settings write | 80 | 65 |
| Broad `.Read.All` or mail/calendar/contact/settings read | 65 | 50 |
| Selected-resource permissions | 40 | 25 |
| Basic sign-in, profile, or session scopes | 20 | 5 |
| Other Microsoft Graph permissions requiring classification | 60 | 45 |
| Non-Microsoft-Graph APIs requiring manual interpretation | 70 | 70 |
| Unresolved resource or permission | 75 | 75 |
| Default/zero app-role assignment with no named API role | 10 | Not applicable |

Priority bands are **Critical: 90-100**, **High: 65-89**, **Medium: 35-64**, **Low: 1-34**, and **No API grants: 0**.

The rules and recognized identity-control permissions are defined in `Get-PermissionWeight`. Review and adapt them to your organization's API classifications. Custom and unresolved API scores conservatively prioritize investigation; they do not establish that those permissions are necessarily more powerful than known permissions.

Requested permissions may include classification weights for reference, but they do not affect the application score. Disabled applications retain their grant-based score. Client-secret expiration is a separate operational signal and does not change privilege ranking.

## Coverage limitations

- External publishers' home-tenant registration credentials and requested permission lists are not visible unless the registration is local to the collected tenant. "No visible secrets" does not mean "no credentials." Managed identities normally have no client secrets.
- The inventory does not include soft-deleted objects, Entra directory roles/PIM, Azure RBAC, certificates, federated identity credentials, Exchange application RBAC/access policies, SharePoint/Teams resource-specific grants, API-internal authorization, or secrets stored outside Entra.
- Granted API permissions are not the full authorization picture. Resource-specific grants and API policies may expand or restrict actual access. Selected-resource permissions require separate resource-level review.
- Delegated access is constrained by the signed-in user and API policy. Tenant-wide delegated consent is not app-only access or proof that every user can access the same data.
- Collection is a nontransactional snapshot. Graph replication and changes during collection can affect results. Delegated grants referencing absent clients are retained in `OrphanedDelegatedGrants` with a warning.
- A score of zero means no API grants were found in the collected data, not that the application has no access.

The script makes a sequential role-assignment request for every service principal, plus any continuation pages. Large tenants may take significant time; progress is displayed during collection.

## Data handling

Both output files contain sensitive directory and security information, including application names, tenant and user object IDs, permission assignments, and credential metadata. Store and transfer them only through an approved secure process and protect them with appropriate filesystem permissions.

The dashboard runs locally and makes no external network requests. Secret values and hints are not exported. Do not publish production `dashboard.html` or `inventory.json` files to GitHub, public websites, or other unapproved locations.

The files in the [Example](Example) folder contain synthetic demonstration data only. To try the dashboard without a tenant connection, download the project and open `Example\dashboard.html` locally.

## Offline checks

Run the included checks without a Graph module or tenant sign-in:

```powershell
.\Test-EntraAppReview.ps1
```

The checks use synthetic Graph responses to exercise pagination, permission resolution, registration/service-principal linking, ranking, credential-expiration boundaries, retry and failure handling, authentication behavior, safe HTML embedding, and dashboard filtering and drilldowns.

Browser checks use an isolated headless Microsoft Edge profile at the standard Windows installation path. To use a different Edge or Chrome executable:

```powershell
.\Test-EntraAppReview.ps1 `
    -BrowserPath 'C:\Program Files\Google\Chrome\Application\chrome.exe'
```

To run collection and report checks without browser checks:

```powershell
.\Test-EntraAppReview.ps1 -SkipBrowser
```

## Microsoft references

- [List applications](https://learn.microsoft.com/en-us/graph/api/application-list?view=graph-rest-1.0)
- [List service principals](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list?view=graph-rest-1.0)
- [List app roles granted to a service principal](https://learn.microsoft.com/en-us/graph/api/serviceprincipal-list-approleassignments?view=graph-rest-1.0)
- [List delegated permission grants](https://learn.microsoft.com/en-us/graph/api/oauth2permissiongrant-list?view=graph-rest-1.0)
