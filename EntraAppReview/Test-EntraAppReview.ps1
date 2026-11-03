#Requires -Version 5.1
[CmdletBinding()]
param(
    [switch]$GenerateExample,
    [switch]$SkipBrowser,
    [string]$BrowserPath = 'C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe'
)
$ErrorActionPreference = 'Stop'
. (Join-Path $PSScriptRoot 'Invoke-EntraAppReview.ps1') -TenantId '11111111-1111-1111-1111-111111111111'
$script:assertions = 0
function Assert-True {
    param([bool]$Condition, [string]$Message)
    $script:assertions++
    if (-not $Condition) { throw "Assertion failed: $Message" }
}
function Assert-Throws {
    param([scriptblock]$Action, [string]$Pattern)
    $caught = $null
    try { & $Action | Out-Null } catch { $caught = $_ }
    Assert-True ($null -ne $caught -and $caught.Exception.Message -match $Pattern) "Expected failure matching '$Pattern'; received '$caught'."
}
$script:routes = @{}
$script:requests = [Collections.Generic.List[string]]::new()
$script:failureStatus = 0
$script:failureCount = 0
$script:delays = [Collections.Generic.List[int]]::new()
function Invoke-MgGraphRequest {
    param($Method, $Uri, $OutputType, $ErrorAction)
    if ($Method -ne 'GET') { throw 'A write method was attempted.' }
    $script:requests.Add($Uri)
    if ($script:failureCount -gt 0) {
        $script:failureCount--
        $exception = [Exception]::new('Synthetic Graph failure')
        $exception | Add-Member -NotePropertyName Response -NotePropertyValue @{
            StatusCode = $script:failureStatus
            Headers = @{ 'Retry-After' = '3' }
        }
        throw $exception
    }
    if (-not $script:routes.ContainsKey($Uri)) { throw "Unexpected fixture route: $Uri" }
    $script:routes[$Uri]
}
function Start-Sleep { param([int]$Seconds) $script:delays.Add($Seconds) }
function New-FixtureApp {
    param([string]$Id, [string]$Name)
    @{ id = 'app-' + $Id; appId = $Id; displayName = $Name; signInAudience = 'AzureADMyOrg'
        requiredResourceAccess = @(); passwordCredentials = @(); appRoles = @(); api = @{ oauth2PermissionScopes = @() } }
}
function New-FixtureSp {
    param([string]$Id, [string]$Name)
    @{ id = 'sp-' + $Id; appId = $Id; displayName = $Name; servicePrincipalType = 'Application'
        accountEnabled = $true; appOwnerOrganizationId = '11111111-1111-1111-1111-111111111111'
        passwordCredentials = @(); appRoles = @(); oauth2PermissionScopes = @() }
}
$root = 'https://graph.microsoft.com/v1.0'
$appRoute = $root + '/applications?$select=id,appId,displayName,signInAudience,requiredResourceAccess,passwordCredentials,appRoles,api&$top=999'
$spRoute = $root + '/servicePrincipals?$select=id,appId,displayName,servicePrincipalType,accountEnabled,appOwnerOrganizationId,passwordCredentials,appRoles,oauth2PermissionScopes&$top=100'
$oauthRoute = $root + '/oauth2PermissionGrants'
$graphId = '00000003-0000-0000-c000-000000000000'
$graph = New-FixtureSp $graphId 'Microsoft Graph (demo)'
$graph.appRoles = @(
    @{ id = 'role-control'; value = 'RoleManagement.ReadWrite.Directory' },
    @{ id = 'role-mail'; value = 'Mail.Read' },
    @{ id = 'role-directory-read'; value = 'Directory.Read.All' }
)
$graph.oauth2PermissionScopes = @(
    @{ id = 'scope-user'; value = 'User.Read' },
    @{ id = 'scope-offline'; value = 'offline_access' }
)
$adminApp = New-FixtureApp 'demo-admin' 'Directory automation (demo)'
$adminApp.requiredResourceAccess = @(@{ resourceAppId = $graphId; resourceAccess = @(
    @{ id = 'role-control'; type = 'Role' }, @{ id = 'scope-user'; type = 'Scope' }
) })
$now = [DateTimeOffset]::UtcNow
$adminApp.passwordCredentials = @(
    @{ keyId = 'key-expired'; displayName = 'Retired automation secret'; startDateTime = $now.AddDays(-300).ToString('o'); endDateTime = $now.AddDays(-1).ToString('o'); secretText = 'NEVER-EXPORT-THIS'; hint = 'LEAK-HINT' },
    @{ keyId = 'key-soon'; displayName = 'Rotation due'; startDateTime = $now.AddDays(-20).ToString('o'); endDateTime = $now.AddDays(10).ToString('o') }
)
$adminSp = New-FixtureSp 'demo-admin' 'Directory automation (demo)'
$adminSp.passwordCredentials = @(
    @{ keyId = 'key-sp'; displayName = 'Service principal secret'; startDateTime = $now.AddDays(1).ToString('o'); endDateTime = $now.AddDays(90).ToString('o') }
)
$lowApp = New-FixtureApp 'demo-basic' 'Employee sign-in (demo)'
$lowApp.requiredResourceAccess = @(@{ resourceAppId = $graphId; resourceAccess = @(@{ id = 'scope-user'; type = 'Scope' }) })
$lowSp = New-FixtureSp 'demo-basic' 'Employee sign-in (demo)'
$requestApp = New-FixtureApp 'demo-requested' 'Disabled app with requested access (demo)'
$requestApp.requiredResourceAccess = @(@{ resourceAppId = $graphId; resourceAccess = @(@{ id = 'role-control'; type = 'Role' }) })
$requestSp = New-FixtureSp 'demo-requested' $requestApp.displayName
$requestSp.accountEnabled = $false
$orphanApp = New-FixtureApp 'demo-orphan' 'Unprovisioned registration (demo)'
$orphanApp.requiredResourceAccess = @(@{ resourceAppId = 'missing-api'; resourceAccess = @(@{ id = 'missing-scope'; type = 'Scope' }) })
$orphanApp.passwordCredentials = @(@{ keyId = 'unknown-expiry'; displayName = 'Missing expiry metadata'; startDateTime = $null; endDateTime = $null })
$custom = New-FixtureSp 'demo-custom-api' 'Internal finance API (demo)'
$custom.appRoles = @(@{ id = 'custom-reader'; value = 'Finance.Reader' })
$external = New-FixtureSp 'demo-external' 'Vendor integration (demo)'
$managed = New-FixtureSp 'demo-managed' 'Reporting managed identity (demo)'
$managed.servicePrincipalType = 'ManagedIdentity'
$injectionName = 'Example </script><img src=x onerror="window.pwned=true"> (demo)'
$injection = New-FixtureSp 'demo-injection' $injectionName
$unknown = New-FixtureSp 'demo-unknown' 'Unresolved API grant (demo)'
$principals = @($graph,$adminSp,$lowSp,$requestSp,$custom,$external,$managed,$injection,$unknown)
$apps = @($adminApp,$lowApp,$requestApp,$orphanApp)
$appNext = $root + '/applications?$skiptoken=page2'
$spNext = $root + '/servicePrincipals?$skiptoken=page2'
$oauthNext = $root + '/oauth2PermissionGrants?$skiptoken=page2'
$script:routes[$appRoute] = @{ value = @($apps[0]); '@odata.nextLink' = $appNext }
$script:routes[$appNext] = @{ value = @($apps[1..3]) }
$script:routes[$spRoute] = @{ value = @($principals[0]); '@odata.nextLink' = $spNext }
$script:routes[$spNext] = @{ value = @($principals[1..8]) }
$userGrants = @(
    @{ id = 'grant-user-1'; clientId = $lowSp.id; resourceId = $graph.id; scope = 'User.Read'; consentType = 'Principal'; principalId = 'demo-user-1' },
    @{ id = 'grant-user-2'; clientId = $lowSp.id; resourceId = $graph.id; scope = 'User.Read'; consentType = 'Principal'; principalId = 'demo-user-2' },
    @{ id = 'grant-tenant'; clientId = $lowSp.id; resourceId = $graph.id; scope = 'offline_access'; consentType = 'AllPrincipals'; principalId = $null },
    @{ id = 'orphaned-grant'; clientId = 'sp-missing'; resourceId = $graph.id; scope = 'User.Read'; consentType = 'Principal'; principalId = 'demo-user-3' }
)
$script:routes[$oauthRoute] = @{ value = @($userGrants[0]); '@odata.nextLink' = $oauthNext }
$script:routes[$oauthNext] = @{ value = @($userGrants[1..3]) }
foreach ($sp in $principals) {
    $uri = $root + '/servicePrincipals/' + $sp.id + '/appRoleAssignments?$select=id,resourceId,appRoleId,principalId'
    $script:routes[$uri] = @{ value = @() }
}
$adminUri = $root + '/servicePrincipals/' + $adminSp.id + '/appRoleAssignments?$select=id,resourceId,appRoleId,principalId'
$assignmentNext = $root + '/servicePrincipals/' + $adminSp.id + '/appRoleAssignments?$skiptoken=page2'
$script:routes[$adminUri] = @{ value = @(@{ id = 'assignment-control'; resourceId = $graph.id; appRoleId = 'role-control' }); '@odata.nextLink' = $assignmentNext }
$script:routes[$assignmentNext] = @{ value = @(@{ id = 'assignment-mail'; resourceId = $graph.id; appRoleId = 'role-mail' }) }
$externalUri = $root + '/servicePrincipals/' + $external.id + '/appRoleAssignments?$select=id,resourceId,appRoleId,principalId'
$script:routes[$externalUri] = @{ value = @(@{ id = 'assignment-custom'; resourceId = $custom.id; appRoleId = 'custom-reader' }) }
$managedUri = $root + '/servicePrincipals/' + $managed.id + '/appRoleAssignments?$select=id,resourceId,appRoleId,principalId'
$script:routes[$managedUri] = @{ value = @(@{ id = 'assignment-managed'; resourceId = $graph.id; appRoleId = 'role-directory-read' }) }
$unknownUri = $root + '/servicePrincipals/' + $unknown.id + '/appRoleAssignments?$select=id,resourceId,appRoleId,principalId'
$script:routes[$unknownUri] = @{ value = @(@{ id = 'assignment-unknown'; resourceId = 'missing-resource'; appRoleId = 'unknown-role' }) }

$inventory = Get-EntraInventory -GraphRoot $root -Tenant '11111111-1111-1111-1111-111111111111' -ExpiryDays 30
$inventory.IsDemo = $true
Assert-True ($inventory.ApplicationCount -eq 4 -and $inventory.ServicePrincipalCount -eq 9) 'All pages and object counts.'
Assert-True ($inventory.Applications.Count -eq 10) 'Linked apps are not duplicated; registration-only app is retained.'
Assert-True ($inventory.Applications[0].AppId -eq 'demo-admin') 'Most privileged application appears first.'
$admin = $inventory.Applications | Where-Object AppId -eq 'demo-admin'
$basic = $inventory.Applications | Where-Object AppId -eq 'demo-basic'
$requestedOnly = $inventory.Applications | Where-Object AppId -eq 'demo-requested'
$unprovisioned = $inventory.Applications | Where-Object AppId -eq 'demo-orphan'
$externalRecord = $inventory.Applications | Where-Object AppId -eq 'demo-external'
Assert-True ($admin.Score -eq 96 -and $admin.Band -eq 'Critical') 'Critical grant plus breadth adjustment.'
Assert-True ($admin.Secrets.Count -eq 3) 'Application and service principal credential metadata.'
Assert-True ($admin.GrantedApplicationCount -eq 2) 'Role-assignment pagination and granted API count.'
Assert-True ($admin.RequestedPermissions[0].ConsentStatus -eq 'Application permission granted') 'Requested role matched to actual grant.'
Assert-True ($admin.RequestedPermissions[1].ConsentStatus -eq 'Not found in collected grants') 'Ungrant scope is not misrepresented.'
Assert-True (@($admin.GrantedPermissions | Where-Object Permission -eq 'Mail.Read').Count -eq 1) 'Undeclared existing grant preserved.'
Assert-True ($basic.GrantedPermissions.Count -eq 3 -and $basic.GrantedDelegatedCount -eq 2 -and $basic.Score -eq 6) 'Per-user grants preserved without score inflation.'
Assert-True ($basic.RequestedPermissions[0].ConsentStatus -eq 'Granted for specific user(s)') 'Per-user and tenant consent distinguished.'
Assert-True ($requestedOnly.Score -eq 0 -and $requestedOnly.RequestedCount -eq 1 -and $requestedOnly.AccountEnabled -eq $false) 'Requested-only and disabled app behavior.'
Assert-True ($unprovisioned.Kind -eq 'Registration only' -and $unprovisioned.RequestedPermissions[0].ConsentStatus -eq 'No tenant service principal') 'Registration without SP.'
Assert-True ($externalRecord.Score -eq 70 -and $externalRecord.NeedsManualReview -and $externalRecord.GrantedPermissions[0].Permission -eq 'Finance.Reader') 'Custom API resolved and marked for interpretation.'
Assert-True (($inventory.Applications | Where-Object AppId -eq 'demo-unknown').Score -eq 75) 'Unresolved grants receive explicit conservative priority.'
Assert-True (($inventory.Applications | Where-Object AppId -eq 'demo-managed').Kind -eq 'Managed identity') 'Managed identities included.'
Assert-True ($inventory.OrphanedDelegatedGrants.Count -eq 1 -and $inventory.Warnings.Count -eq 3) 'Orphaned grants and unknown expiry surfaced.'
Assert-True ($script:requests.Contains($appNext) -and $script:requests.Contains($spNext) -and $script:requests.Contains($oauthNext) -and $script:requests.Contains($assignmentNext)) 'Every supported collection follows pagination.'

$fixedNow = [DateTimeOffset]::Parse('2026-10-20T12:00:00Z')
$boundaryCredentials = @{ id = 'boundaries'; passwordCredentials = @(
    @{ keyId = 'expired'; endDateTime = $fixedNow.ToString('o') },
    @{ keyId = 'hours'; endDateTime = $fixedNow.AddHours(2).ToString('o') },
    @{ keyId = 'boundary'; endDateTime = $fixedNow.AddDays(30).ToString('o') },
    @{ keyId = 'outside'; endDateTime = $fixedNow.AddDays(30).AddSeconds(1).ToString('o') },
    @{ keyId = 'future'; startDateTime = $fixedNow.AddDays(1).ToString('o'); endDateTime = $fixedNow.AddDays(90).ToString('o') },
    @{ keyId = 'unknown' }
) }
$states = @(Get-SecretMetadata -Object $boundaryCredentials -Source Application -Now $fixedNow -ExpiryDays 30)
Assert-True ($states[0].Status -eq 'Expired') 'Exact expiration instant is expired.'
Assert-True ($states[1].Status -eq 'Expiring' -and $states[1].DaysRemaining -eq 0) 'A few hours remaining is not expired.'
Assert-True ($states[2].Status -eq 'Expiring' -and $states[2].DaysRemaining -eq 30) 'Exact expiry window boundary is included.'
Assert-True ($states[3].Status -eq 'Valid') 'After expiry window is valid.'
Assert-True ($states[4].NotYetValid -and $states[5].Status -eq 'Unknown expiry') 'Future start and missing expiry are explicit.'
Assert-Throws { Get-SecretMetadata -Object @{ passwordCredentials = @(@{ endDateTime = 'not-a-date' }) } -Source Application -Now $fixedNow -ExpiryDays 30 } 'recognized|valid|format'
$resource = New-ResourceDefinition -Object $graph
$default = New-PermissionRecord -Resource $resource -PermissionId '00000000-0000-0000-0000-000000000000' -Type Application -State Granted
Assert-True ($default.Weight -eq 10 -and -not $default.NeedsReview) 'Default/zero app role is not full API access.'
$localResourceApp = New-FixtureApp 'local-api' 'Local API with no SP'
$localResourceApp.api.oauth2PermissionScopes = @(@{ id = 'local-scope'; value = 'Custom.Scope' })
$localResource = New-ResourceDefinition -Object $localResourceApp -Application
$localPermission = New-PermissionRecord -Resource $localResource -PermissionId 'local-scope' -Type Delegated -State Requested
Assert-True ($localPermission.Resolved -and $localPermission.Permission -eq 'Custom.Scope') 'Local registration definition fallback.'
Assert-True ((Get-PermissionWeight -ResourceAppId $graphId -Name 'Sites.Selected' -Type Application -Resolved $true -DefaultRole $false).Weight -eq 40) 'Selected resource weight.'
Assert-True ((Get-PermissionWeight -ResourceAppId $graphId -Name 'AppRoleAssignment.ReadWrite.All' -Type Delegated -Resolved $true -DefaultRole $false).Weight -eq 80) 'Delegated critical control weight.'
Assert-True ((Get-PermissionWeight -ResourceAppId $graphId -Name 'Mail.ReadWrite' -Type Application -Resolved $true -DefaultRole $false).Weight -eq 80) 'Tenant mailbox write recognized without an All suffix.'
Assert-True ((Get-PermissionWeight -ResourceAppId $graphId -Name 'Mail.Read' -Type Application -Resolved $true -DefaultRole $false).Weight -eq 65) 'Tenant mailbox read recognized without an All suffix.'
Assert-True ((Get-PermissionWeight -ResourceAppId $graphId -Name 'Policy.ReadWrite.ConditionalAccess' -Type Application -Resolved $true -DefaultRole $false).Weight -eq 95) 'Conditional access policy control prioritized.'

$script:failureStatus = 429; $script:failureCount = 1
$null = @(Get-GraphCollection -Uri $appRoute -GraphRoot $root)
Assert-True ($script:delays.Count -eq 1 -and $script:delays[0] -eq 3) 'Throttle Retry-After honored.'
$script:failureStatus = 503; $script:failureCount = 6
Assert-Throws { Get-GraphCollection -Uri $appRoute -GraphRoot $root } 'HTTP 503'
Assert-True ($script:failureCount -eq 0) 'Retry attempts bounded.'
$script:failureStatus = 403; $script:failureCount = 1
Assert-Throws { Get-EntraInventory -GraphRoot $root -Tenant 'demo' } 'HTTP 403'
Assert-Throws { Get-GraphCollection -Uri 'https://example.com/v1.0/applications' -GraphRoot $root } 'Unexpected Graph URL'
$repeatUri = $root + '/applications?$skiptoken=repeat'
$script:routes[$repeatUri] = @{ value = @(); '@odata.nextLink' = $repeatUri }
Assert-Throws { Get-GraphCollection -Uri $repeatUri -GraphRoot $root } 'repeated continuation'
$badUri = $root + '/applications?$skiptoken=bad'
$script:routes[$badUri] = @{ error = 'malformed' }
Assert-Throws { Get-GraphCollection -Uri $badUri -GraphRoot $root } 'did not return a collection'

$work = Join-Path $PSScriptRoot ('.test-' + [guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $work
try {
    $reportFolder = Join-Path $work 'report'
    $htmlPath = Write-EntraReport -Inventory $inventory -Directory $reportFolder
    $html = [IO.File]::ReadAllText($htmlPath)
    $json = [IO.File]::ReadAllText((Join-Path $reportFolder 'inventory.json'))
    $roundtrip = $json | ConvertFrom-Json
    Assert-True ($roundtrip.Applications.Count -eq 10 -and $roundtrip.Applications[0].Score -eq 96) 'JSON has full inventory and sorted score.'
    Assert-True (-not $json.Contains('NEVER-EXPORT-THIS') -and -not $json.Contains('LEAK-HINT') -and -not $json.Contains('"secretText"')) 'No secret values or hints exported.'
    Assert-True (-not $html.Contains($injectionName) -and $html.Contains('\u003c/script\u003e')) 'Embedded JSON cannot terminate its script element.'
    Assert-True ($html -notmatch '<script[^>]+src=|https://cdn\.|fetch\(') 'Dashboard has no remote scripts or fetch.'
    Assert-Throws { Write-EntraReport -Inventory $inventory -Directory $reportFolder } 'already exists'
    $embedded = [regex]::Match($html,'(?s)<script id="inventory" type="application/json">\s*(.*?)\s*</script>').Groups[1].Value | ConvertFrom-Json
    Assert-True (($embedded.Applications | Where-Object AppId -eq 'demo-injection').DisplayName -eq $injectionName) 'Safe JSON preserves original display names.'
    $script:routes[$appRoute] = @{ value = @() }; $script:routes[$spRoute] = @{ value = @() }; $script:routes[$oauthRoute] = @{ value = @() }
    $empty = Get-EntraInventory -GraphRoot $root -Tenant 'empty'
    Assert-True ($empty.Applications.Count -eq 0 -and $empty.Warnings.Count -eq 0) 'Empty tenant remains an empty array without spurious records.'
    $null = Write-EntraReport -Inventory $empty -Directory (Join-Path $work 'empty')
    $script:moduleAvailable = $true
    $script:connectCount = 0
    $script:disconnectCount = 0
    $script:openCount = 0
    $script:contextScope = ''
    $script:context = [pscustomobject]@{
        TenantId = '11111111-1111-1111-1111-111111111111'
        Environment = 'Global'; AuthType = 'Delegated'; Scopes = @('Directory.Read.All')
    }
    function Get-Module {
        param([switch]$ListAvailable, $Name)
        if ($script:moduleAvailable) { [pscustomobject]@{ Name = 'Microsoft.Graph.Authentication' } }
    }
    function Import-Module { param($Name, $ErrorAction) }
    function Get-MgContext { $script:context }
    function Get-MgEnvironment { param($Name) [pscustomobject]@{ GraphEndpoint = 'https://graph.microsoft.com' } }
    function Connect-MgGraph {
        param($TenantId, $Environment, $Scopes, $ContextScope, [switch]$NoWelcome, $ErrorAction)
        $script:connectCount++; $script:contextScope = $ContextScope
    }
    function Disconnect-MgGraph { param($ErrorAction) $script:disconnectCount++ }
    function Invoke-Item { param($LiteralPath, $ErrorAction) $script:openCount++ }
    $tenant = [guid]'11111111-1111-1111-1111-111111111111'
    $null = Invoke-EntraAppReview -Tenant $tenant -Directory (Join-Path $work 'fresh-auth') -ExpiryDays 30 -Cloud Global
    Assert-True ($script:connectCount -eq 1 -and $script:disconnectCount -eq 1 -and $script:contextScope -eq 'Process' -and $script:openCount -eq 1) 'Interactive context is process-scoped, disconnected, and opens dashboard.'
    $null = Invoke-EntraAppReview -Tenant $tenant -Directory (Join-Path $work 'existing-auth') -ExpiryDays 30 -Cloud Global -Existing -SkipOpen
    Assert-True ($script:connectCount -eq 1 -and $script:disconnectCount -eq 1 -and $script:openCount -eq 1) 'Existing context retained and NoOpen honored.'
    Assert-Throws { Invoke-EntraAppReview -Tenant ([guid]'22222222-2222-2222-2222-222222222222') -Directory (Join-Path $work 'wrong-tenant') -ExpiryDays 30 -Cloud Global -Existing -SkipOpen } 'not requested tenant'
    Assert-Throws { Invoke-EntraAppReview -Tenant $tenant -Directory (Join-Path $work 'wrong-cloud') -ExpiryDays 30 -Cloud USGov -Existing -SkipOpen } 'not requested environment'
    $script:context.Scopes = @('User.Read')
    Assert-Throws { Invoke-EntraAppReview -Tenant $tenant -Directory (Join-Path $work 'missing-scope') -ExpiryDays 30 -Cloud Global -Existing -SkipOpen } 'requires admin-consented'
    $script:context.Scopes = @('Directory.Read.All')
    $script:failureStatus = 403; $script:failureCount = 1
    $failedFolder = Join-Path $work 'failed-collection'
    Assert-Throws { Invoke-EntraAppReview -Tenant $tenant -Directory $failedFolder -ExpiryDays 30 -Cloud Global -SkipOpen } 'HTTP 403'
    Assert-True (-not (Test-Path -LiteralPath $failedFolder) -and $script:disconnectCount -eq 2) 'Failed collection publishes no report and disconnects its own session.'
    $script:context.AuthType = 'AppOnly'; $script:context.Scopes = @()
    $null = Invoke-EntraAppReview -Tenant $tenant -Directory (Join-Path $work 'app-only') -ExpiryDays 30 -Cloud Global -Existing -SkipOpen
    Assert-True ($script:disconnectCount -eq 2) 'App-only context uses existing connection without delegated-scope preflight.'
    $script:moduleAvailable = $false
    Assert-Throws { Invoke-EntraAppReview -Tenant $tenant -Directory (Join-Path $work 'no-module') -ExpiryDays 30 -Cloud Global -SkipOpen } 'Install-Module'
    if (-not $SkipBrowser) {
        if (-not (Test-Path -LiteralPath $BrowserPath -PathType Leaf)) { throw 'Browser not found. Set -BrowserPath to Edge/Chrome or use -SkipBrowser explicitly.' }
        $harness = @'
<script>
const checks=[];
function check(value,message) { if (!value) throw new Error(message); checks.push(message); }
try {
  check(typeof render === 'function','dashboard JavaScript initialized');
  check(byId('rows').children.length === 20,'all ten review rows rendered');
  check(byId('rows').children[0].textContent.includes('Directory automation'),'default privilege sort');
  check(!window.pwned && !document.querySelector('img'),'application metadata cannot execute HTML');
  byId('rows').querySelector('button').click();
  check(byId('rows').children[1].hidden === false,'drilldown expanded');
  check(byId('rows').children[1].textContent.includes('RoleManagement.ReadWrite.Directory'),'permission details');
  check(byId('rows').children[1].textContent.includes('Retired automation secret'),'secret metadata details');
  byId('band').value='Critical'; byId('band').dispatchEvent(new Event('change'));
  check(byId('rows').children.length===2,'priority filter');
  byId('band').value=''; byId('search').value='Finance.Reader'; render();
  check(byId('rows').children.length===2 && byId('rows').textContent.includes('Vendor integration'),'permission search');
  byId('search').value=''; byId('secrets').value='Expired'; render();
  check(byId('rows').children.length===2,'expired secret filter');
  byId('secrets').value=''; byId('access').value='user'; render();
  check(byId('rows').children.length===2 && byId('rows').textContent.includes('Employee sign-in'),'per-user consent filter');
  byId('access').value='tenant'; render();
  check(byId('rows').children.length===2,'tenant consent filter');
  byId('access').value=''; byId('kind').value='Managed identity'; render();
  check(byId('rows').children.length===2 && byId('rows').textContent.includes('Reporting managed identity'),'identity type filter');
  byId('kind').value=''; byId('sort').value='least'; render();
  check(byId('rows').children[0].textContent.includes('No API grants'),'least privileged sort');
  byId('search').value='this will match nothing'; render();
  check(byId('rows').textContent.includes('No applications match'),'empty search results');
  byId('search').value=''; byId('sort').value='priority';
  for(let i=0;i<51;i++) apps.push({...apps[0],DisplayName:'Pagination demo '+i});
  render();
  check(byId('rows').children.length===100 && !byId('next').disabled,'pagination page size');
  byId('next').click();
  check(byId('pageInfo').textContent==='Page 2 of 2' && byId('rows').children.length===22,'pagination next page');
  const result=el('pre',JSON.stringify(checks)); result.id='test-results'; result.dataset.success='true'; document.body.append(result);
} catch (error) {
  const result=document.createElement('pre'); result.id='test-results'; result.dataset.success='false'; result.textContent=error.stack; document.body.append(result);
}
</script>
'@
        $harnessPath = Join-Path $work 'browser-check.html'
        [IO.File]::WriteAllText($harnessPath, $html.Replace('</body></html>', ($harness + '</body></html>')), [Text.UTF8Encoding]::new($false))
        $profile = Join-Path $work 'browser-profile'
        $uri = ([uri]$harnessPath).AbsoluteUri
        $browserArguments = @('--headless','--disable-gpu','--no-first-run','--no-default-browser-check',
            '--disable-extensions','--disable-background-networking','--dump-dom','--virtual-time-budget=3000',
            ('--user-data-dir="' + $profile + '"'), ('"' + $uri + '"'))
        $startInfo = [Diagnostics.ProcessStartInfo]::new()
        $startInfo.FileName = $BrowserPath
        $startInfo.Arguments = $browserArguments -join ' '
        $startInfo.UseShellExecute = $false
        $startInfo.RedirectStandardOutput = $true
        $startInfo.RedirectStandardError = $true
        $browser = [Diagnostics.Process]::new()
        $browser.StartInfo = $startInfo
        $null = $browser.Start()
        $outputTask = $browser.StandardOutput.ReadToEndAsync()
        $errorTask = $browser.StandardError.ReadToEndAsync()
        try {
            if (-not $browser.WaitForExit(60000) -or -not $outputTask.Wait(30000) -or -not $errorTask.Wait(30000)) {
                throw 'Offline browser check timed out.'
            }
            $dom = $outputTask.Result
            $browserErrors = $errorTask.Result
        }
        finally {
            if (-not $browser.HasExited) { Stop-Process -Id $browser.Id -ErrorAction Stop }
            $browser.Dispose()
        }
        $result = [regex]::Match($dom,'(?s)<pre id="test-results" data-success="(true|false)">(.*?)</pre>')
        Assert-True ($result.Success -and $result.Groups[1].Value -eq 'true') (
            'Offline dashboard interaction checks: ' + [Net.WebUtility]::HtmlDecode($result.Groups[2].Value) +
            $(if (-not $result.Success) { $browserErrors }))
        Write-Host ('Browser checks: ' + [Net.WebUtility]::HtmlDecode($result.Groups[2].Value))
    }
    if ($GenerateExample) {
        $example = Join-Path $PSScriptRoot 'Example'
        $null = Write-EntraReport -Inventory $inventory -Directory $example
        Write-Host "Synthetic example dashboard: $(Join-Path $example 'dashboard.html')"
    }
    Write-Host "PASS: $script:assertions offline assertions."
}
finally {
    if (Test-Path -LiteralPath $work -PathType Container) {
        Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop
    }
}
