#Requires -Version 5.1
<#
.SYNOPSIS
Creates an offline, read-only Entra application permission and secret-expiry dashboard.
.EXAMPLE
.\Invoke-EntraAppReview.ps1 -TenantId '00000000-0000-0000-0000-000000000000'
.EXAMPLE
.\Invoke-EntraAppReview.ps1 -TenantId $tenantId -UseExistingConnection -NoOpen
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [guid]$TenantId,
    [string]$OutputDirectory = (Join-Path (Get-Location) ('EntraReview-' + (Get-Date -Format 'yyyyMMdd-HHmmss'))),
    [ValidateRange(1, 3650)]
    [int]$ExpiringInDays = 30,
    [ValidateSet('Global', 'USGov', 'USGovDoD', 'China')]
    [string]$Environment = 'Global',
    [switch]$UseExistingConnection,
    [switch]$NoOpen
)

function Get-GraphCollection {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Uri, [Parameter(Mandatory)][string]$GraphRoot)

    $allowed = [uri]$GraphRoot
    $visited = @{}
    while ($Uri) {
        $target = [uri]$Uri
        if ($target.Scheme -ne 'https' -or $target.Authority -ne $allowed.Authority -or
            -not $target.AbsolutePath.StartsWith('/v1.0/', [StringComparison]::OrdinalIgnoreCase)) {
            throw "Unexpected Graph URL: $Uri"
        }
        if ($visited.ContainsKey($Uri)) { throw "Graph returned a repeated continuation URL: $Uri" }
        $visited[$Uri] = $true
        $page = $null
        for ($attempt = 0; $attempt -lt 6; $attempt++) {
            try {
                $page = Invoke-MgGraphRequest -Method GET -Uri $Uri -OutputType Hashtable -ErrorAction Stop
                break
            }
            catch {
                $failure = $_
                $status = 0
                $response = $failure.Exception.Response
                if ($response -and $response.StatusCode) { $status = [int]$response.StatusCode }
                elseif ($failure.Exception.ResponseStatusCode) { $status = [int]$failure.Exception.ResponseStatusCode }
                if ($status -notin @(429, 500, 502, 503, 504) -or $attempt -eq 5) {
                    throw "Graph inventory failed at $Uri (HTTP $status). No new report was published. $($failure.Exception.Message)"
                }
                $delay = [int][math]::Pow(2, $attempt + 1)
                if ($response -and $response.Headers) {
                    $retry = $response.Headers.RetryAfter
                    if ($retry -and $retry.Delta) {
                        $delay = [int][math]::Ceiling($retry.Delta.TotalSeconds)
                    }
                    elseif ($retry -and $retry.Date) {
                        $delay = [int][math]::Ceiling(($retry.Date - [DateTimeOffset]::UtcNow).TotalSeconds)
                    }
                    elseif ($response.Headers -is [System.Collections.IDictionary]) {
                        $seconds = 0
                        if ([int]::TryParse([string]$response.Headers['Retry-After'], [ref]$seconds)) { $delay = $seconds }
                    }
                }
                $delay = [math]::Max(1, $delay)
                Write-Warning "Graph HTTP $status; retrying in $delay seconds (attempt $($attempt + 2)/6)."
                Start-Sleep -Seconds $delay
            }
        }
        if ($page -isnot [System.Collections.IDictionary] -or -not $page.Contains('value')) {
            throw "Graph did not return a collection at $Uri. No new report was published."
        }
        foreach ($item in $page['value']) { $item }
        $Uri = [string]$page['@odata.nextLink']
    }
}

function New-ResourceDefinition {
    param($Object, [switch]$Application)
    $roles = @{}
    $scopes = @{}
    $scopeValues = @{}
    foreach ($role in $Object.appRoles) { $roles[[string]$role.id] = $role }
    $definitions = $Object.oauth2PermissionScopes
    if ($Application) { $definitions = $Object.api.oauth2PermissionScopes }
    foreach ($scope in $definitions) {
        $scopes[[string]$scope.id] = $scope
        $scopeValues[[string]$scope.value] = $scope
    }
    @{
        Name = [string]$Object.displayName
        AppId = [string]$Object.appId
        ObjectId = $(if ($Application) { '' } else { [string]$Object.id })
        Roles = $roles
        Scopes = $scopes
        ScopeValues = $scopeValues
    }
}

function Get-PermissionWeight {
    param([string]$ResourceAppId, [string]$Name, [string]$Type, [bool]$Resolved, [bool]$DefaultRole)
    if ($DefaultRole) {
        return @{ Weight = 10; Reason = 'Default role assignment; no named API role.'; Review = $false }
    }
    if (-not $Resolved) {
        return @{ Weight = 75; Reason = 'Unresolved resource or permission; manual review required.'; Review = $true }
    }
    if ($ResourceAppId -ne '00000003-0000-0000-c000-000000000000') {
        return @{ Weight = 70; Reason = 'Non-Microsoft-Graph API: privilege semantics require manual review.'; Review = $true }
    }
    $critical = @(
        'RoleManagement.ReadWrite.Directory', 'RoleManagementPolicy.ReadWrite.Directory',
        'AppRoleAssignment.ReadWrite.All', 'Application.ReadWrite.All',
        'Directory.ReadWrite.All', 'DelegatedPermissionGrant.ReadWrite.All',
        'RoleAssignmentSchedule.ReadWrite.Directory', 'RoleEligibilitySchedule.ReadWrite.Directory',
        'PrivilegedAccess.ReadWrite.AzureAD', 'PrivilegedAssignmentSchedule.ReadWrite.AzureADGroup',
        'UserAuthenticationMethod.ReadWrite.All', 'User-PasswordProfile.ReadWrite.All',
        'Directory.AccessAsUser.All', 'User.ManageIdentities.All',
        'Policy.ReadWrite.ConditionalAccess', 'Policy.ReadWrite.Authorization',
        'Policy.ReadWrite.AuthenticationMethod', 'Policy.ReadWrite.PermissionGrant',
        'Policy.ReadWrite.CrossTenantAccess', 'Policy.ReadWrite.AuthenticationFlows',
        'Policy.ReadWrite.AuthenticationStrength'
    )
    $review = $false
    if ($Name -in $critical) {
        $weight = 95; $reason = 'Identity, credential, application, or consent control.'
    }
    elseif ($Name -match '(\.ReadWrite\.All$|\.FullControl\.All$|^Mail\.Send$|^Application\.ReadWrite\.OwnedBy$|^User\.EnableDisableAccount\.All$|^(Mail|MailboxSettings|Calendars|Contacts)\.ReadWrite$)') {
        $weight = 80; $reason = 'Broad write, full control, mail sending, or application management.'
    }
    elseif ($Name -match '(\.Read\.All$|^(Mail|MailboxSettings|Calendars|Contacts)\.Read$|^Mail\.ReadBasic$)') {
        $weight = 65; $reason = 'Broad read access; data sensitivity requires review.'
    }
    elseif ($Name -match '(^openid$|^profile$|^email$|^offline_access$|^User\.Read$)') {
        $weight = 20; $reason = 'Basic sign-in/profile or session scope.'
    }
    elseif ($Name -match '\.Selected($|\.)') {
        $weight = 40; $reason = 'Selected-resource access; inspect resource-specific grants separately.'
    }
    else {
        $weight = 60; $reason = 'Unclassified Microsoft Graph permission; manual review required.'; $review = $true
    }
    if ($Type -eq 'Delegated') {
        $weight = [math]::Max(5, $weight - 15)
        $reason += ' Delegated access is constrained by the signed-in user and API policy.'
    }
    @{ Weight = $weight; Reason = $reason; Review = $review }
}

function New-PermissionRecord {
    param(
        $Resource, [string]$ResourceId, [string]$ResourceAppId,
        [string]$PermissionId, [string]$ScopeValue, [string]$Type,
        [string]$State, [string]$ConsentType, [string]$PrincipalId, [string]$GrantId
    )
    $name = $PermissionId
    $resolved = $false
    $defaultRole = $Type -eq 'Application' -and $PermissionId -eq '00000000-0000-0000-0000-000000000000'
    if ($Resource) {
        $ResourceAppId = $Resource.AppId
        if (-not $ResourceId) { $ResourceId = $Resource.ObjectId }
        if ($Type -eq 'Application' -and $Resource.Roles.ContainsKey($PermissionId)) {
            $name = [string]$Resource.Roles[$PermissionId].value
            $resolved = -not [string]::IsNullOrWhiteSpace($name)
        }
        elseif ($Type -eq 'Delegated') {
            if ($ScopeValue -and $Resource.ScopeValues.ContainsKey($ScopeValue)) {
                $name = $ScopeValue
                $PermissionId = [string]$Resource.ScopeValues[$ScopeValue].id
                $resolved = $true
            }
            elseif ($PermissionId -and $Resource.Scopes.ContainsKey($PermissionId)) {
                $name = [string]$Resource.Scopes[$PermissionId].value
                $resolved = -not [string]::IsNullOrWhiteSpace($name)
            }
        }
    }
    if ($ScopeValue -and -not $resolved) { $name = $ScopeValue }
    if ($defaultRole) { $name = 'Default access (no named API role)' }
    if (-not $name) { $name = '(unnamed permission)' }
    $assessment = Get-PermissionWeight -ResourceAppId $ResourceAppId -Name $name -Type $Type -Resolved $resolved -DefaultRole $defaultRole
    [pscustomobject][ordered]@{
        State = $State
        Type = $Type
        ResourceName = $(if ($Resource) { $Resource.Name } else { 'Unresolved API' })
        ResourceAppId = $ResourceAppId
        ResourceServicePrincipalId = $ResourceId
        Permission = $name
        PermissionId = $PermissionId
        Resolved = $resolved
        ConsentType = $ConsentType
        PrincipalId = $PrincipalId
        GrantId = $GrantId
        ConsentStatus = ''
        Weight = $assessment.Weight
        Reason = $assessment.Reason
        NeedsReview = $assessment.Review
    }
}

function Get-SecretMetadata {
    param($Object, [string]$Source, [DateTimeOffset]$Now, [int]$ExpiryDays)
    foreach ($credential in $Object.passwordCredentials) {
        $end = $null
        $start = $null
        if ($credential.endDateTime) {
            $end = [DateTimeOffset]::Parse([string]$credential.endDateTime, [Globalization.CultureInfo]::InvariantCulture)
        }
        if ($credential.startDateTime) {
            $start = [DateTimeOffset]::Parse([string]$credential.startDateTime, [Globalization.CultureInfo]::InvariantCulture)
        }
        $days = $null
        $status = 'Unknown expiry'
        if ($null -ne $end) {
            $days = [int][math]::Floor(($end - $Now).TotalDays)
            if ($end -le $Now) { $status = 'Expired' }
            elseif ($end -le $Now.AddDays($ExpiryDays)) { $status = 'Expiring' }
            else { $status = 'Valid' }
        }
        [pscustomobject][ordered]@{
            Source = $Source
            SourceObjectId = [string]$Object.id
            KeyId = [string]$credential.keyId
            DisplayName = [string]$credential.displayName
            StartDateTime = $(if ($null -ne $start) { $start.ToUniversalTime().ToString('o') } else { $null })
            EndDateTime = $(if ($null -ne $end) { $end.ToUniversalTime().ToString('o') } else { $null })
            DaysRemaining = $days
            Status = $status
            NotYetValid = ($null -ne $start -and $start -gt $Now)
        }
    }
}

function New-ReviewRecord {
    param($Application, $ServicePrincipal, [object[]]$Grants, $ResourceByAppId, [DateTimeOffset]$Now, [int]$ExpiryDays)
    $requested = @(
        foreach ($access in $Application.requiredResourceAccess) {
            $resource = $ResourceByAppId[[string]$access.resourceAppId]
            foreach ($permission in $access.resourceAccess) {
                $type = switch ([string]$permission.type) {
                    'Role' { 'Application' }
                    'Scope' { 'Delegated' }
                    default { throw "Unknown requiredResourceAccess type '$($permission.type)' in application $($Application.id)." }
                }
                $entry = New-PermissionRecord -Resource $resource -ResourceAppId $access.resourceAppId `
                    -PermissionId $permission.id -Type $type -State 'Requested'
                $matches = @($Grants | Where-Object {
                    $_.ResourceAppId -eq $entry.ResourceAppId -and $_.Type -eq $entry.Type -and
                    (($_.PermissionId -and $_.PermissionId -eq $entry.PermissionId) -or
                        ($entry.Resolved -and $_.Permission -eq $entry.Permission))
                })
                if (-not $ServicePrincipal) { $entry.ConsentStatus = 'No tenant service principal' }
                elseif ($matches.Count -eq 0) { $entry.ConsentStatus = 'Not found in collected grants' }
                elseif ($type -eq 'Application') { $entry.ConsentStatus = 'Application permission granted' }
                elseif (@($matches | Where-Object ConsentType -eq 'AllPrincipals').Count) {
                    $entry.ConsentStatus = 'Granted tenant-wide'
                }
                else { $entry.ConsentStatus = 'Granted for specific user(s)' }
                $entry
            }
        }
    )
    $secrets = @(
        if ($Application) { Get-SecretMetadata -Object $Application -Source 'Application' -Now $Now -ExpiryDays $ExpiryDays }
        if ($ServicePrincipal) { Get-SecretMetadata -Object $ServicePrincipal -Source 'ServicePrincipal' -Now $Now -ExpiryDays $ExpiryDays }
    )
    $unique = @($Grants | Sort-Object ResourceServicePrincipalId, Type, Permission -Unique)
    $score = 0
    $reasons = @('No granted API permissions were found in the collected tenant data.')
    if ($unique.Count) {
        $highest = $unique | Sort-Object Weight -Descending | Select-Object -First 1
        $breadth = [math]::Min(5, $unique.Count - 1)
        $score = [int][math]::Min(100, $highest.Weight + $breadth)
        $reasons = @("$($highest.Permission): $($highest.Reason)", "Breadth adjustment: +$breadth for $($unique.Count) distinct granted permissions.")
    }
    $band = if ($score -ge 90) { 'Critical' } elseif ($score -ge 65) { 'High' } elseif ($score -ge 35) { 'Medium' } elseif ($score -gt 0) { 'Low' } else { 'No API grants' }
    $kind = if ($ServicePrincipal.servicePrincipalType -eq 'ManagedIdentity') { 'Managed identity' }
        elseif ($Application -and $ServicePrincipal) { 'Registration + enterprise app' }
        elseif ($Application) { 'Registration only' } else { 'Enterprise application' }
    $name = [string]$ServicePrincipal.displayName
    if (-not $name) { $name = [string]$Application.displayName }
    $appId = [string]$ServicePrincipal.appId
    if (-not $appId) { $appId = [string]$Application.appId }
    [pscustomobject][ordered]@{
        DisplayName = $name
        ApplicationDisplayName = [string]$Application.displayName
        AppId = $appId
        ApplicationObjectId = [string]$Application.id
        ServicePrincipalObjectId = [string]$ServicePrincipal.id
        ServicePrincipalType = [string]$ServicePrincipal.servicePrincipalType
        Kind = $kind
        AccountEnabled = $(if ($ServicePrincipal) { $ServicePrincipal.accountEnabled } else { $null })
        PublisherTenantId = [string]$ServicePrincipal.appOwnerOrganizationId
        SignInAudience = [string]$Application.signInAudience
        Score = $score
        Band = $band
        ScoreReasons = $reasons
        NeedsManualReview = (@($Grants | Where-Object NeedsReview).Count -gt 0)
        GrantedApplicationCount = @($unique | Where-Object Type -eq 'Application').Count
        GrantedDelegatedCount = @($unique | Where-Object Type -eq 'Delegated').Count
        RequestedCount = $requested.Count
        GrantedPermissions = @($Grants)
        RequestedPermissions = $requested
        Secrets = $secrets
    }
}

function Get-EntraInventory {
    [CmdletBinding()]
    param([string]$GraphRoot, [string]$Tenant, [int]$ExpiryDays = 30)
    $started = [DateTimeOffset]::UtcNow
    Write-Host 'Reading app registrations...'
    $applications = @(Get-GraphCollection -GraphRoot $GraphRoot -Uri (
        $GraphRoot + '/applications?$select=id,appId,displayName,signInAudience,requiredResourceAccess,passwordCredentials,appRoles,api&$top=999'))
    Write-Host 'Reading enterprise applications and API definitions...'
    $principals = @(Get-GraphCollection -GraphRoot $GraphRoot -Uri (
        $GraphRoot + '/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,passwordCredentials,appRoles,oauth2PermissionScopes&$top=100'))
    Write-Host 'Reading delegated permission grants...'
    $delegated = @(Get-GraphCollection -GraphRoot $GraphRoot -Uri ($GraphRoot + '/oauth2PermissionGrants'))
    $appByAppId = @{}
    $resourceById = @{}
    $resourceByAppId = @{}
    $delegatedByClient = @{}
    $matchedApps = @{}
    foreach ($app in $applications) {
        $appByAppId[[string]$app.appId] = $app
        $resourceByAppId[[string]$app.appId] = New-ResourceDefinition -Object $app -Application
    }
    foreach ($sp in $principals) {
        $resource = New-ResourceDefinition -Object $sp
        $resourceById[[string]$sp.id] = $resource
        if ($sp.appId) { $resourceByAppId[[string]$sp.appId] = $resource }
    }
    foreach ($grant in $delegated) {
        $client = [string]$grant.clientId
        if (-not $delegatedByClient.ContainsKey($client)) {
            $delegatedByClient[$client] = [Collections.Generic.List[object]]::new()
        }
        $delegatedByClient[$client].Add($grant)
    }
    $records = [Collections.Generic.List[object]]::new()
    $count = 0
    foreach ($sp in $principals) {
        $count++
        Write-Progress -Activity 'Reading granted application permissions' -Status "$count / $($principals.Count): $($sp.displayName)" `
            -PercentComplete (($count * 100) / [math]::Max(1, $principals.Count))
        $assignments = @(Get-GraphCollection -GraphRoot $GraphRoot -Uri (
            $GraphRoot + '/servicePrincipals/' + $sp.id + '/appRoleAssignments?$select=id,resourceId,appRoleId,principalId'))
        $grants = @(
            foreach ($assignment in $assignments) {
                New-PermissionRecord -Resource $resourceById[[string]$assignment.resourceId] `
                    -ResourceId $assignment.resourceId -PermissionId $assignment.appRoleId `
                    -Type 'Application' -State 'Granted' -ConsentType 'Application assignment' -GrantId $assignment.id
            }
            foreach ($grant in $delegatedByClient[[string]$sp.id]) {
                foreach ($scope in ([string]$grant.scope -split '\s+' | Where-Object { $_ })) {
                    New-PermissionRecord -Resource $resourceById[[string]$grant.resourceId] `
                        -ResourceId $grant.resourceId -ScopeValue $scope -Type 'Delegated' `
                        -State 'Granted' -ConsentType $grant.consentType -PrincipalId $grant.principalId -GrantId $grant.id
                }
            }
        )
        $app = $appByAppId[[string]$sp.appId]
        if ($app) { $matchedApps[[string]$app.id] = $true }
        $records.Add((New-ReviewRecord -Application $app -ServicePrincipal $sp -Grants $grants `
            -ResourceByAppId $resourceByAppId -Now $started -ExpiryDays $ExpiryDays))
    }
    Write-Progress -Activity 'Reading granted application permissions' -Completed
    foreach ($app in $applications) {
        if (-not $matchedApps.ContainsKey([string]$app.id)) {
            $records.Add((New-ReviewRecord -Application $app -Grants @() `
                -ResourceByAppId $resourceByAppId -Now $started -ExpiryDays $ExpiryDays))
        }
    }
    $knownClients = @{}
    foreach ($sp in $principals) { $knownClients[[string]$sp.id] = $true }
    $orphanedGrants = @($delegated | Where-Object { -not $knownClients.ContainsKey([string]$_.clientId) })
    $warnings = [Collections.Generic.List[string]]::new()
    if ($orphanedGrants.Count) {
        $warnings.Add("$($orphanedGrants.Count) delegated grant(s) reference client service principals absent from the collected inventory. See OrphanedDelegatedGrants in JSON.")
    }
    if (@($records | Where-Object NeedsManualReview).Count) {
        $warnings.Add('Some granted permissions are unresolved or unclassified. Their conservative triage scores require manual interpretation.')
    }
    if (@($records | ForEach-Object { $_.Secrets } | Where-Object Status -eq 'Unknown expiry').Count) {
        $warnings.Add('Some client-secret metadata has no expiration date. Review entries marked Unknown expiry.')
    }
    foreach ($warning in $warnings) { Write-Warning $warning }
    [pscustomobject][ordered]@{
        SchemaVersion = 1
        TenantId = $Tenant
        GraphEndpoint = $GraphRoot
        CollectionStartedUtc = $started.ToString('o')
        CollectionCompletedUtc = [DateTimeOffset]::UtcNow.ToString('o')
        ExpiringInDays = $ExpiryDays
        IsDemo = $false
        ApplicationCount = $applications.Count
        ServicePrincipalCount = $principals.Count
        Warnings = @($warnings.ToArray())
        OrphanedDelegatedGrants = @(
            foreach ($grant in $orphanedGrants) {
                [pscustomobject]@{
                    Id = [string]$grant.id; ClientId = [string]$grant.clientId; ResourceId = [string]$grant.resourceId
                    Scope = [string]$grant.scope; ConsentType = [string]$grant.consentType; PrincipalId = [string]$grant.principalId
                }
            }
        )
        Applications = @($records.ToArray() | Sort-Object @{ Expression = 'Score'; Descending = $true }, DisplayName, ServicePrincipalObjectId)
    }
}

function Write-EntraReport {
    [CmdletBinding()]
    param([Parameter(Mandatory)]$Inventory, [Parameter(Mandatory)][string]$Directory)
    if (Test-Path -LiteralPath $Directory) { throw "Output directory already exists. Choose a new directory to preserve prior reports: $Directory" }
    $json = ConvertTo-Json -InputObject $Inventory -Depth 30
    $safeJson = $json.Replace('&', '\u0026').Replace('<', '\u003c').Replace('>', '\u003e').
        Replace([string][char]0x2028, '\u2028').Replace([string][char]0x2029, '\u2029')
    $template = @'
<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'none'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>Entra application triage</title>
<style>
:root{color-scheme:dark;--bg:#0c1321;--panel:#151f32;--line:#30405a;--text:#edf3ff;--muted:#acbbd3;--accent:#8ebcff}
*{box-sizing:border-box}body{font:14px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--text);margin:0}
main{max-width:1560px;margin:auto;padding:30px}h1{margin:0 0 5px;font-size:28px}h2{font-size:17px;margin:20px 0 8px}
p{margin:8px 0}.muted,small{color:var(--muted)}.notice{padding:12px 16px;border:1px solid #9b783b;background:#302619;border-radius:8px;margin:16px 0;white-space:pre-line}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(155px,1fr));gap:12px;margin:20px 0}.card{background:var(--panel);border:1px solid var(--line);padding:16px;border-radius:10px}.card strong{display:block;font-size:27px}
.controls{display:flex;gap:12px;flex-wrap:wrap;align-items:end;margin:18px 0}label{display:flex;flex-direction:column;gap:4px;color:var(--muted)}
input,select,button{font:inherit;color:var(--text);background:var(--panel);border:1px solid var(--line);border-radius:6px;padding:9px}input{min-width:300px}button{cursor:pointer}button:hover{border-color:var(--accent)}
.scroll{overflow:auto}table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:11px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600;white-space:nowrap}thead{background:var(--panel)}td.name{min-width:270px}td code{overflow-wrap:anywhere}code{font-size:12px}
.badge{display:inline-block;border:1px solid var(--line);border-radius:20px;padding:2px 9px;font-size:12px;white-space:nowrap}.Critical,.Expired{color:#ffacb3;border-color:#c65e70}.High,.Expiring{color:#ffd094;border-color:#b78443}.Medium{color:#ffe69c;border-color:#9b8c4a}.Low,.Valid{color:#9de2c1;border-color:#448d77}
.Unknown,.manual{color:#d2b6ff}.details{background:#111b2d;padding:18px}.details td{font-size:13px}.detail-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:8px}.detail-grid code{display:block}
.pager{display:flex;gap:12px;align-items:center;justify-content:flex-end;margin:14px 0}.empty{text-align:center;padding:30px}.toggle{background:transparent;text-align:left;border:0;padding:0;color:var(--accent);font-weight:600}.disabled{color:#ffd094}
summary{cursor:pointer;color:var(--accent)}a{color:var(--accent)}.wrap{overflow-wrap:anywhere}noscript{display:block;padding:30px;color:#ffd094}
@media(max-width:700px){main{padding:15px}input{min-width:220px}.controls label{width:100%}}
@media print{.controls,.pager,button{display:none}body{background:white;color:black}.scroll{overflow:visible}.muted,small,th{color:#444}}
</style></head><body><main>
<h1>Entra application triage</h1><p class="muted" id="metadata"></p>
<div id="demo" class="notice" hidden>DEMONSTRATION DATA ONLY - this report does not contain a real tenant inventory.</div>
<div id="warnings" class="notice" hidden></div>
<div class="cards" id="cards"></div>
<details><summary>Scope, ranking model, and important limitations</summary>
<p>This inventory combines local app registrations and tenant service principals, including managed identities and Microsoft/third-party enterprise apps. A registration is linked by client ID; registrations without a service principal are retained. Disabled apps remain visible and retain their grant-based score.</p>
<p><strong>Priority is a heuristic, not an effective-access calculation.</strong> Only granted API permissions contribute: maximum permission weight plus one point per additional distinct resource/type/permission, capped at +5 and a total of 100. Application permissions are not user-bound; delegated access is limited by the signed-in user and API policy. Repeated per-user consent does not inflate the score.</p>
<p>Microsoft Graph weights: identity/credential/consent control 95; broad write/full control/mail sending 80; broad read 65; selected-resource scopes 40; basic sign-in scopes 20; unclassified scopes 60. Delegated weights are reduced by 15, minimum 5. Non-Graph APIs are conservatively 70 and unresolved grants 75, both requiring manual review; the default/zero app role is 10. Critical &ge;90, High &ge;65, Medium &ge;35, Low &gt;0. Zero means no collected API grants, <strong>not no access</strong>.</p>
<p>Requested permissions are displayed separately and never treated as consent. Existing grants can exceed a registration's current request list. Tenant-wide and per-user delegated consents are distinguished; principal IDs are preserved without looking up user profiles.</p>
<p>Secret expiration is a separate operational signal, not privilege. UTC dates and days remaining are calculated at collection start. Metadata only: secret values and hints are never exported. For external/multitenant apps, home-tenant registration secrets are not visible here. A managed identity normally has no client secret.</p>
<p>This is not a point-in-time transactional snapshot. Entra replication and changes during collection can affect results. Not covered: Entra directory roles/PIM, Azure RBAC, Exchange application RBAC/access policies, SharePoint or Teams resource-specific grants, API-internal authorization, federated credentials, certificates, or secrets outside Entra. No tenant changes or external network requests are made by this dashboard.</p>
</details>
<div class="controls">
<label>Search apps, IDs, APIs, permissions<input id="search" type="search" placeholder="e.g. Mail.Read, app name, client ID"></label>
<label>Priority<select id="band"><option value="">All priorities</option><option>Critical</option><option>High</option><option>Medium</option><option>Low</option><option>No API grants</option></select></label>
<label>Application type<select id="kind"><option value="">All types</option><option>Registration + enterprise app</option><option>Enterprise application</option><option>Registration only</option><option>Managed identity</option></select></label>
<label>Granted access<select id="access"><option value="">Any / none</option><option value="application">Application permissions</option><option value="delegated">Delegated permissions</option><option value="tenant">Tenant-wide delegated consent</option><option value="user">Per-user delegated consent</option><option value="review">Needs manual classification</option><option value="none">No API grants</option></select></label>
<label>Client secrets<select id="secrets"><option value="">All</option><option value="Expired">Has expired secrets</option><option value="Expiring">Has expiring secrets</option><option value="Unknown expiry">Unknown expiration</option><option value="none">No visible secrets</option></select></label>
<label>Sort<select id="sort"><option value="priority">Most privileged first</option><option value="least">Least privileged first</option><option value="expiry">Earliest secret expiration</option><option value="name">Application name</option></select></label>
</div>
<p class="muted" id="resultCount" aria-live="polite"></p>
<div class="scroll"><table aria-label="Application triage"><thead><tr><th>Priority</th><th>Application / client ID</th><th>Type / status</th><th>Granted APIs</th><th>Requested</th><th>Client secrets</th><th>Earliest secret expiry (UTC)</th></tr></thead><tbody id="rows"></tbody></table></div>
<div class="pager"><button id="previous" type="button">Previous</button><span id="pageInfo"></span><button id="next" type="button">Next</button></div>
<noscript>Enable JavaScript to view this local dashboard, or inspect inventory.json directly.</noscript>
</main>
<script id="inventory" type="application/json">
'@
    $footer = @'
</script>
<script>
'use strict';
const data = JSON.parse(document.getElementById('inventory').textContent);
const apps = data.Applications;
const byId = id => document.getElementById(id);
const el = (tag, text, cls) => { const n = document.createElement(tag); if (text !== undefined) n.textContent = String(text); if (cls) n.className = cls; return n; };
const badge = (text, cls) => el('span', text, 'badge ' + (cls || text));
const utc = value => value ? new Date(value).toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC') : 'Unknown';
const expiry = app => {
  const dates = app.Secrets.filter(s => s.EndDateTime).map(s => Date.parse(s.EndDateTime));
  return dates.length ? Math.min(...dates) : Infinity;
};
const uniqueSecrets = new Map();
for (const app of apps) for (const s of app.Secrets) uniqueSecrets.set([s.Source,s.SourceObjectId,s.KeyId].join('|'), s);
const secrets = [...uniqueSecrets.values()];
byId('metadata').textContent = 'Tenant: ' + data.TenantId + ' | Collection: ' + utc(data.CollectionStartedUtc) + ' to ' + utc(data.CollectionCompletedUtc);
byId('demo').hidden = !data.IsDemo;
if (data.Warnings.length) { byId('warnings').hidden = false; byId('warnings').textContent = data.Warnings.join('\n'); }
for (const [label, value] of [
  ['Review rows', apps.length], ['App registrations', data.ApplicationCount], ['Service principals', data.ServicePrincipalCount],
  ['Critical / high priority', apps.filter(a => ['Critical','High'].includes(a.Band)).length],
  ['Visible client secrets', secrets.length], ['Expired secrets', secrets.filter(s => s.Status === 'Expired').length],
  ['Expiring in ' + data.ExpiringInDays + ' days', secrets.filter(s => s.Status === 'Expiring').length]
]) { const card = el('div', undefined, 'card'); card.append(el('strong', value), el('span', label)); byId('cards').append(card); }
const searchable = new Map(apps.map(a => [a, [a.DisplayName,a.ApplicationDisplayName,a.AppId,a.ApplicationObjectId,a.ServicePrincipalObjectId,
  ...a.GrantedPermissions.concat(a.RequestedPermissions).flatMap(p => [p.Permission,p.PermissionId,p.ResourceName,p.ResourceAppId,p.ResourceServicePrincipalId,p.PrincipalId])].join(' ').toLowerCase()]));
let page = 0;
const pageSize = 50;
function table(parent, headers, rows) {
  const wrap = el('div', undefined, 'scroll'), t = el('table'), head = el('thead'), tr = el('tr'), body = el('tbody');
  for (const h of headers) tr.append(el('th', h));
  head.append(tr);
  for (const values of rows) {
    const r = el('tr');
    for (const v of values) { const c = el('td', undefined, 'wrap'); c.append(v instanceof Node ? v : document.createTextNode(String(v === null || v === undefined ? '' : v))); r.append(c); }
    body.append(r);
  }
  t.append(head,body); wrap.append(t); parent.append(wrap);
}
function permissionRows(permissions, requested) {
  return permissions.map(p => {
    const permission = el('div'); permission.append(el('strong', p.Permission), el('div', p.PermissionId || 'No definition ID available', 'muted'));
    if (!p.Resolved) permission.append(el('div', 'Unresolved definition / default role', 'manual'));
    const api = el('div', p.ResourceName); api.append(el('div', p.ResourceAppId || p.ResourceServicePrincipalId, 'muted'));
    return [api,permission,p.Type,requested ? p.ConsentStatus : p.ConsentType,
      requested ? 'Requested only; does not establish access' : (p.PrincipalId || (p.Type === 'Application' ? 'App identity' : 'All users')),
      requested ? p.Reason : p.Weight + ' - ' + p.Reason];
  });
}
function detail(app) {
  const panel = el('div', undefined, 'details'), ids = el('div', undefined, 'detail-grid');
  for (const [label,value] of [['Registration object ID',app.ApplicationObjectId],['Service principal object ID',app.ServicePrincipalObjectId],
    ['Registration display name',app.ApplicationDisplayName],['Publisher tenant ID',app.PublisherTenantId],['Sign-in audience',app.SignInAudience],['Service principal type',app.ServicePrincipalType]]) {
    const item = el('div',label); item.append(el('code',value || 'Not present / not visible')); ids.append(item);
  }
  panel.append(ids,el('h2','Why this priority?'));
  for (const reason of app.ScoreReasons) panel.append(el('p',reason));
  panel.append(el('h2','Granted API permissions (' + app.GrantedPermissions.length + ' grant/scope entries)'));
  if (!app.GrantedPermissions.length) panel.append(el('p','No granted API permissions found. This does not exclude other authorization paths.','muted'));
  else table(panel,['API / resource ID','Permission / definition ID','Type','Consent','User object ID / subject','Weight / rationale'],permissionRows(app.GrantedPermissions,false));
  panel.append(el('h2','Requested permissions (' + app.RequestedPermissions.length + ')'));
  if (!app.ApplicationObjectId) panel.append(el('p','No local app registration. The publisher tenant request list is not visible here.','muted'));
  else if (!app.RequestedPermissions.length) panel.append(el('p','No API permissions declared in requiredResourceAccess. Existing grants above may still apply.','muted'));
  else table(panel,['API / resource ID','Permission / definition ID','Type','Observed consent','Interpretation','Classification rationale'],permissionRows(app.RequestedPermissions,true));
  panel.append(el('h2','Client-secret metadata (' + app.Secrets.length + ')'));
  if (!app.Secrets.length) panel.append(el('p','No client-secret metadata visible on the collected objects. This does not prove the application has no credentials.','muted'));
  else table(panel,['Name / key ID','Source / object ID','Start (UTC)','Expiration (UTC)','Days left','State'],app.Secrets.map(s => {
    const name = el('div',s.DisplayName || '(unnamed secret)'); name.append(el('div',s.KeyId,'muted'));
    const source = el('div',s.Source); source.append(el('div',s.SourceObjectId,'muted'));
    const state = el('div'); state.append(badge(s.Status,s.Status.split(' ')[0])); if (s.NotYetValid) state.append(el('div','Not yet valid','muted'));
    return [name,source,s.StartDateTime ? utc(s.StartDateTime) : 'Unknown',utc(s.EndDateTime),s.DaysRemaining === null ? 'Unknown' : s.DaysRemaining,state];
  }));
  return panel;
}
function render() {
  const query = byId('search').value.trim().toLowerCase(), band = byId('band').value, kind = byId('kind').value, access = byId('access').value, secret = byId('secrets').value;
  const filtered = apps.filter(a => {
    if (query && !searchable.get(a).includes(query)) return false;
    if (band && a.Band !== band || kind && a.Kind !== kind) return false;
    if (secret && (secret === 'none' ? a.Secrets.length !== 0 : !a.Secrets.some(s => s.Status === secret))) return false;
    if (access === 'application' && !a.GrantedApplicationCount || access === 'delegated' && !a.GrantedDelegatedCount) return false;
    if (access === 'review' && !a.NeedsManualReview || access === 'none' && a.GrantedPermissions.length) return false;
    if (access === 'tenant' && !a.GrantedPermissions.some(p => p.Type === 'Delegated' && p.ConsentType === 'AllPrincipals')) return false;
    if (access === 'user' && !a.GrantedPermissions.some(p => p.Type === 'Delegated' && p.ConsentType === 'Principal')) return false;
    return true;
  });
  const sort = byId('sort').value;
  filtered.sort((a,b) => {
    let delta = 0;
    if (sort === 'priority') delta = b.Score - a.Score;
    else if (sort === 'least') delta = a.Score - b.Score;
    else if (sort === 'expiry') { const x = expiry(a), y = expiry(b); delta = x === y ? 0 : x < y ? -1 : 1; }
    return delta || a.DisplayName.localeCompare(b.DisplayName) || a.ServicePrincipalObjectId.localeCompare(b.ServicePrincipalObjectId);
  });
  const pages = Math.max(1,Math.ceil(filtered.length/pageSize)); page = Math.min(page,pages-1);
  byId('rows').replaceChildren();
  byId('resultCount').textContent = filtered.length + ' of ' + apps.length + ' rows match. Summary cards show the full inventory. Click an application to inspect permissions and secrets.';
  for (const app of filtered.slice(page*pageSize,(page+1)*pageSize)) {
    const row = el('tr'), priority = el('td'); priority.append(badge(app.Band),el('div',app.Score + ' / 100','muted')); if (app.NeedsManualReview) priority.append(el('small','Manual review','manual'));
    const name = el('td',undefined,'name'), button = el('button',app.DisplayName || '(unnamed application)','toggle'); button.type = 'button'; button.setAttribute('aria-expanded','false');
    name.append(button,el('div',app.AppId || 'No client ID','muted'));
    const kindCell = el('td',app.Kind); if (app.AccountEnabled === false) kindCell.append(el('div','Disabled','disabled')); else if (app.AccountEnabled === true) kindCell.append(el('div','Enabled','muted'));
    const granted = el('td',app.GrantedApplicationCount + ' application'); granted.append(el('div',app.GrantedDelegatedCount + ' delegated','muted'));
    const secretCell = el('td',app.Secrets.length + ' visible');
    for (const state of ['Expired','Expiring','Unknown expiry']) { const n = app.Secrets.filter(s => s.Status === state).length; if (n) { const line = el('div'); line.append(badge(n + ' ' + state,state.split(' ')[0])); secretCell.append(line); } }
    const next = expiry(app); row.append(priority,name,kindCell,granted,el('td',app.RequestedCount),secretCell,el('td',next === Infinity ? 'No known expiry' : utc(next)));
    const expanded = el('tr'); expanded.hidden = true; const cell = el('td'); cell.colSpan = 7; expanded.append(cell);
    let loaded = false;
    button.addEventListener('click',() => { if (!loaded) { cell.append(detail(app)); loaded = true; } expanded.hidden = !expanded.hidden; button.setAttribute('aria-expanded',String(!expanded.hidden)); });
    byId('rows').append(row,expanded);
  }
  if (!filtered.length) { const row = el('tr'), c = el('td','No applications match these filters.','empty'); c.colSpan = 7; row.append(c); byId('rows').append(row); }
  byId('pageInfo').textContent = 'Page ' + (page+1) + ' of ' + pages;
  byId('previous').disabled = page === 0; byId('next').disabled = page >= pages-1;
}
let searchTimer;
byId('search').addEventListener('input',() => { clearTimeout(searchTimer); searchTimer = setTimeout(() => { page = 0; render(); },150); });
for (const id of ['band','kind','access','secrets','sort']) byId(id).addEventListener('change',() => { page = 0; render(); });
byId('previous').addEventListener('click',() => { page--; render(); });
byId('next').addEventListener('click',() => { page++; render(); });
render();
</script></body></html>
'@
    $html = $template + "`n" + $safeJson + "`n" + $footer
    $fullDirectory = [IO.Path]::GetFullPath($Directory).TrimEnd([IO.Path]::DirectorySeparatorChar, [IO.Path]::AltDirectorySeparatorChar)
    $parent = [IO.Path]::GetDirectoryName($fullDirectory)
    if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw "Output parent directory does not exist: $parent" }
    $staging = Join-Path $parent ('.entra-review-' + [guid]::NewGuid().ToString('N'))
    $null = New-Item -ItemType Directory -Path $staging -ErrorAction Stop
    try {
        $utf8 = [Text.UTF8Encoding]::new($false)
        [IO.File]::WriteAllText((Join-Path $staging 'inventory.json'), $json, $utf8)
        [IO.File]::WriteAllText((Join-Path $staging 'dashboard.html'), $html, $utf8)
        [IO.Directory]::Move($staging, $fullDirectory)
    }
    catch {
        foreach ($file in @('inventory.json', 'dashboard.html')) {
            $path = Join-Path $staging $file
            if (Test-Path -LiteralPath $path -PathType Leaf) { Remove-Item -LiteralPath $path -ErrorAction Stop }
        }
        if (Test-Path -LiteralPath $staging -PathType Container) { Remove-Item -LiteralPath $staging -ErrorAction Stop }
        throw
    }
    Join-Path $fullDirectory 'dashboard.html'
}

function Invoke-EntraAppReview {
    [CmdletBinding()]
    param([guid]$Tenant, [string]$Directory, [int]$ExpiryDays, [string]$Cloud, [switch]$Existing, [switch]$SkipOpen)
    $ErrorActionPreference = 'Stop'
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Authentication)) {
        throw 'Install the authentication module first: Install-Module Microsoft.Graph.Authentication -Scope CurrentUser'
    }
    Import-Module Microsoft.Graph.Authentication -ErrorAction Stop
    $connectedHere = $false
    try {
        if (-not $Existing) {
            Connect-MgGraph -TenantId $Tenant.ToString() -Environment $Cloud -Scopes 'Directory.Read.All' `
                -ContextScope Process -NoWelcome -ErrorAction Stop | Out-Null
            $connectedHere = $true
        }
        $context = Get-MgContext
        if (-not $context) { throw 'No Graph connection. Omit -UseExistingConnection or call Connect-MgGraph first.' }
        if ([string]$context.TenantId -ne $Tenant.ToString()) { throw "Connected to tenant $($context.TenantId), not requested tenant $Tenant." }
        if ($context.Environment -ne $Cloud) { throw "Connected to $($context.Environment), not requested environment $Cloud." }
        if ($context.AuthType -eq 'Delegated' -and 'Directory.Read.All' -notin $context.Scopes) {
            throw 'Delegated connection requires admin-consented Directory.Read.All for complete read-only coverage.'
        }
        $graphEnvironment = Get-MgEnvironment -Name $context.Environment
        $root = $graphEnvironment.GraphEndpoint.TrimEnd('/') + '/v1.0'
        if (Test-Path -LiteralPath $Directory) { throw "Choose a new output directory; this path already exists: $Directory" }
        $inventory = Get-EntraInventory -GraphRoot $root -Tenant $Tenant.ToString() -ExpiryDays $ExpiryDays
        $dashboard = Write-EntraReport -Inventory $inventory -Directory $Directory
        Write-Host "Collected $($inventory.ApplicationCount) registrations and $($inventory.ServicePrincipalCount) service principals."
        Write-Host "Dashboard: $dashboard"
        Write-Host "Inventory: $(Join-Path ([IO.Path]::GetDirectoryName($dashboard)) 'inventory.json')"
        if (-not $SkipOpen) { Invoke-Item -LiteralPath $dashboard -ErrorAction Stop }
        $dashboard
    }
    finally {
        if ($connectedHere) { Disconnect-MgGraph -ErrorAction Stop | Out-Null }
    }
}

if ($MyInvocation.InvocationName -ne '.') {
    Invoke-EntraAppReview -Tenant $TenantId -Directory $OutputDirectory -ExpiryDays $ExpiringInDays `
        -Cloud $Environment -Existing:$UseExistingConnection -SkipOpen:$NoOpen
}
