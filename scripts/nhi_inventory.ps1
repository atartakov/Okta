<#
.SYNOPSIS
    Non-human identity (NHI) inventory: every machine identity in Okta, risk-ranked. Read-only.

.DESCRIPTION
    PowerShell port of nhi_inventory.py; prints exactly the same text and CSV,
    and the same JSON content.

    AI agents, pipelines and integrations reach Okta through three kinds of
    non-human identity. This script finds all of them, scores each one, and
    says in plain English why it is risky:

      oauth-service-app  OIDC apps that can mint tokens without a user
                         (client_credentials / service type), plus
                         token-exchange "agent" apps: granted okta.* scopes,
                         admin roles on the client, client secret vs
                         private_key_jwt, secret/key age, last access token
                         issued (System Log).
      api-service        API service integrations (OIN machine-to-machine).
      api-token          SSWS API tokens: owner, owner status and roles,
                         network restriction, last use.
      service-user       users that look like service accounts (svc-/bot/api
                         style names or a service-ish user type): MFA,
                         interactive sign-ins, admin roles, password age.

    READ-ONLY: every API call is a GET. Listing API tokens needs a super-admin
    token; anything unreadable is listed under errors and the rest still runs.
    Authentication comes from OKTA_DOMAIN / OKTA_API_TOKEN only.

.PARAMETER LogDays
    System Log window for 'last used' of OAuth apps. Default 30.

.PARAMETER NoLogs
    Skip the System Log lookups.

.PARAMETER RotationDays
    Flag client secrets older than this. Default 90.

.PARAMETER StaleDays
    Flag API tokens unused for longer than this. Default 30.

.PARAMETER NamePattern
    Regex (2nd group = keyword) marking service-account users.

.PARAMETER MinRisk
    low | medium | high | critical. Only show identities at or above this level.

.PARAMETER FailOn
    none | low | medium | high | critical. Exit 2 if any identity is at or above it.

.PARAMETER InputFile
    Score a saved -SaveRaw snapshot offline.

.PARAMETER SaveRaw
    Also save the raw pull for -InputFile.

.PARAMETER Now
    Fixed clock (ISO8601), for tests.

.PARAMETER Json
    Emit JSON.

.PARAMETER Csv
    Emit CSV.

.PARAMETER Output
    Write the report to this file path.

.EXAMPLE
    ./nhi_inventory.ps1

.EXAMPLE
    ./nhi_inventory.ps1 -Csv -Output ./nhi.csv -MinRisk medium

.EXAMPLE
    ./nhi_inventory.ps1 -SaveRaw ./snapshot.json; ./nhi_inventory.ps1 -InputFile ./snapshot.json -Json
#>

param(
    [int]$LogDays = 30,
    [switch]$NoLogs,
    [int]$RotationDays = 90,
    [int]$StaleDays = 30,
    [string]$NamePattern = '(^|[^a-z])(svc|service|bot|api|automation|integration|robot|sa|system|noreply|no-reply|daemon|sync|terraform|agent)([^a-z]|$)',
    [ValidateSet('low', 'medium', 'high', 'critical')][string]$MinRisk = 'low',
    [ValidateSet('none', 'low', 'medium', 'high', 'critical')][string]$FailOn = 'none',
    [string]$InputFile,
    [string]$SaveRaw,
    [string]$Now,
    [switch]$Json,
    [switch]$Csv,
    [string]$Output
)

$ErrorActionPreference = 'Stop'
$Inv = [Globalization.CultureInfo]::InvariantCulture
$Levels = @('low', 'medium', 'high', 'critical')

$RolePoints = @{
    SUPER_ADMIN = 50; ORG_ADMIN = 40; API_ACCESS_MANAGEMENT_ADMIN = 25
    APP_ADMIN = 25; USER_ADMIN = 25; CUSTOM = 25
    GROUP_MEMBERSHIP_ADMIN = 20; HELP_DESK_ADMIN = 20
    ACCESS_CERTIFICATIONS_ADMIN = 15; ACCESS_REQUESTS_ADMIN = 15
    MOBILE_ADMIN = 15; REPORT_ADMIN = 10; READ_ONLY_ADMIN = 5
}
$DefaultRolePoints = 15
$TakeoverScopes = @(
    'okta.roles.manage', 'okta.users.manage', 'okta.policies.manage',
    'okta.authenticators.manage', 'okta.apiTokens.manage', 'okta.apps.manage',
    'okta.clients.manage', 'okta.idps.manage', 'okta.networkZones.manage',
    'okta.sessions.manage', 'okta.orgs.manage', 'okta.factors.manage',
    'okta.authorizationServers.manage', 'okta.groups.manage'
)
$SecretAuth = @('client_secret_basic', 'client_secret_post', 'client_secret_jwt')
$GrantEvents = @('app.oauth2.token.grant.access_token', 'app.oauth2.as.token.grant.access_token')
$TokenExchange = 'urn:ietf:params:oauth:grant-type:token-exchange'

# ------------------------------------------------------------------ helpers

function Get-OrdinalSorted {
    # Sorted, de-duplicated strings in ordinal order (matches Python sorted(set(...))).
    param([object[]]$Items)
    $set = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::Ordinal)
    foreach ($i in @($Items)) { if ($null -ne $i) { [void]$set.Add([string]$i) } }
    return , ([string[]]@($set))
}

function ConvertTo-NormTime {
    param($Value)
    if ($null -eq $Value -or "$Value" -eq '') { return $null }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv) }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv) }
    $dto = [datetimeoffset]::MinValue
    if ([datetimeoffset]::TryParse([string]$Value, $Inv, [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$dto)) {
        return $dto.UtcDateTime.ToString('yyyy-MM-ddTHH:mm:ssZ', $Inv)
    }
    return $null
}

function Get-DaysSince {
    param($Value, [datetime]$NowUtc)
    $t = ConvertTo-NormTime $Value
    if (-not $t) { return $null }
    $dt = [datetime]::ParseExact($t, 'yyyy-MM-ddTHH:mm:ssZ', $Inv, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
    return [int][Math]::Floor(($NowUtc - $dt).TotalSeconds / 86400)
}

function Get-Level {
    param([int]$Score)
    if ($Score -ge 60) { return 'critical' }
    if ($Score -ge 40) { return 'high' }
    if ($Score -ge 20) { return 'medium' }
    return 'low'
}

function Get-RoleScore {
    param([object[]]$Roles)
    $types = Get-OrdinalSorted @(@($Roles) | Where-Object { $_ } | ForEach-Object { if ($_['type']) { $_['type'] } else { '?' } })
    if ($types.Count -eq 0) { return @(0, $null) }
    $best = ($types | ForEach-Object { if ($RolePoints.ContainsKey($_)) { $RolePoints[$_] } else { $DefaultRolePoints } } | Measure-Object -Maximum).Maximum
    $pts = [int]$best + 5 * ($types.Count - 1)
    $labels = Get-OrdinalSorted @(@($Roles) | Where-Object { $_ } | ForEach-Object { if ($_['label']) { $_['label'] } elseif ($_['type']) { $_['type'] } else { '?' } })
    if ($types -contains 'SUPER_ADMIN') { $why = 'holds SUPER_ADMIN: full control of the tenant' }
    elseif ($types -contains 'ORG_ADMIN') { $why = 'holds ORG_ADMIN: can manage users, groups, apps and most settings' }
    elseif ($types.Count -eq 1 -and $types[0] -eq 'READ_ONLY_ADMIN') { $why = 'holds READ_ONLY_ADMIN: can read all admin data' }
    else { $why = "holds admin role(s): $($labels -join ', ')" }
    return @($pts, $why)
}

function Get-ScopeScore {
    param([string[]]$Scopes)
    $manage = Get-OrdinalSorted @($Scopes | Where-Object { $_.EndsWith('.manage') })
    $takeover = @($manage | Where-Object { $TakeoverScopes -ccontains $_ })
    $other = @($manage | Where-Object { $TakeoverScopes -cnotcontains $_ })
    $pts = [Math]::Min(30, 6 * $takeover.Count) + [Math]::Min(10, 3 * $other.Count)
    $reasons = @()
    if ($takeover.Count) { $reasons += "$($takeover.Count) takeover-capable write scope(s): $($takeover -join ', ')" }
    if ($other.Count) { $reasons += "$($other.Count) other write scope(s): $($other -join ', ')" }
    if ($Scopes -ccontains 'okta.roles.manage') {
        $pts += 15
        $reasons += 'okta.roles.manage lets it grant admin roles, including to itself'
    }
    if ($Scopes.Count -gt 10) {
        $pts += 5
        $reasons += "broad grant: $($Scopes.Count) okta.* scopes"
    }
    return @($pts, $reasons)
}

function Get-PrivilegeText {
    param([object[]]$Roles, $Scopes, [switch]$NoScopes)
    $parts = @()
    $rtypes = Get-OrdinalSorted @(@($Roles) | Where-Object { $_ } | ForEach-Object { if ($_['type']) { $_['type'] } else { '?' } })
    if ($rtypes.Count) { $parts += ($rtypes -join ',') }
    if (-not $NoScopes) {
        $nManage = @($Scopes | Where-Object { $_.EndsWith('.manage') }).Count
        $parts += "$(@($Scopes).Count) scopes, $nManage write"
    }
    $t = $parts -join '; '
    if (-not $t) { $t = 'none' }
    return $t
}

function Complete-Row {
    param($Row, [int]$Score, [string[]]$Reasons)
    $Row['score'] = [Math]::Max(0, $Score)
    $Row['risk'] = Get-Level $Row['score']
    $Row['reasons'] = @($Reasons)
    if ($Reasons.Count) { $Row['why'] = $Reasons -join '; ' } else { $Row['why'] = 'no risk signals found' }
    return $Row
}

function Get-MaxAge {
    param([object[]]$Items, [datetime]$NowUtc)
    $m = 0
    foreach ($i in $Items) { $d = Get-DaysSince $i['created'] $NowUtc; if ($null -eq $d) { $d = 0 }; if ($d -gt $m) { $m = $d } }
    return $m
}

# ------------------------------------------------------------------ scoring

function Get-AppRow {
    param($App, $Raw, [datetime]$NowUtc)
    $scopes = Get-OrdinalSorted @($App['scopes'])
    $roles = @($App['roles'] | Where-Object { $_ })
    $auth = if ($App['auth_method']) { $App['auth_method'] } else { 'unknown' }
    $score = 0; $reasons = @()
    if ($App['status'] -ne 'ACTIVE') { $reasons += "app is $($App['status']) (cannot get tokens until reactivated)" }
    $rs = Get-RoleScore $roles
    if ($rs[1]) { $score += $rs[0]; $reasons += ($rs[1] + ' (assigned to the client itself)') }
    $ss = Get-ScopeScore $scopes
    $score += $ss[0]; $reasons += @($ss[1])
    if ($SecretAuth -contains $auth) {
        $score += 15
        $reasons += "authenticates with a shared client secret ($auth): it can be copied and replayed from anywhere; prefer private_key_jwt"
    }
    $activeSecrets = @($App['secrets'] | Where-Object { $_ -and $_['status'] -eq 'ACTIVE' })
    if ($activeSecrets.Count) {
        $oldest = Get-MaxAge $activeSecrets $NowUtc
        if ($oldest -gt $RotationDays) { $score += 10; $reasons += "client secret not rotated in $oldest days (> $RotationDays)" }
        if ($activeSecrets.Count -gt 1) { $score += 5; $reasons += "$($activeSecrets.Count) active client secrets (old one never retired?)" }
    }
    $activeKeys = @($App['keys'] | Where-Object { $_ -and $_['status'] -eq 'ACTIVE' })
    if ($auth -eq 'private_key_jwt' -and $activeKeys.Count) {
        $oldest = Get-MaxAge $activeKeys $NowUtc
        if ($oldest -gt 365) { $score += 5; $reasons += "signing key is $oldest days old" }
    }
    $grantTypes = @($App['grant_types'] | Where-Object { $_ })
    if ($grantTypes -contains $TokenExchange) {
        $reasons += 'token-exchange client: can act on behalf of signed-in users (AI agent / Cross App Access pattern)'
    }
    $last = $null
    if ($Raw['logs_available']) {
        $cid = if ($App['client_id']) { $App['client_id'] } else { $App['id'] }
        if ($Raw['token_grants']) { $last = $Raw['token_grants'][$cid] }
        if (-not $last -and ($scopes.Count -or $roles.Count) -and $App['status'] -eq 'ACTIVE') {
            $score += 10
            $reasons += "no access token issued in the last $($Raw['log_window_days']) days: standing access nobody uses, deactivation candidate"
        }
    }
    if ($App['status'] -ne 'ACTIVE') { $score = [int][Math]::Floor($score / 2) }
    $row = [ordered]@{
        type = 'oauth-service-app'; id = $App['id']
        name = $(if ($App['label']) { $App['label'] } else { $App['id'] })
        status = $App['status']; privilege = (Get-PrivilegeText $roles $scopes)
        credential = $auth
        last_used = $(if ($Raw['logs_available']) { ConvertTo-NormTime $last } else { 'unknown' })
        created = (ConvertTo-NormTime $App['created'])
        details = [ordered]@{
            scopes = $scopes
            admin_roles = (Get-OrdinalSorted @($roles | ForEach-Object { $_['type'] }))
            grant_types = (Get-OrdinalSorted $grantTypes)
        }
    }
    return Complete-Row $row $score $reasons
}

function Get-ApiServiceRow {
    param($Svc, $Raw, [datetime]$NowUtc)
    $scopes = Get-OrdinalSorted @($Svc['grantedScopes'])
    $score = 0; $reasons = @()
    $ss = Get-ScopeScore $scopes
    $score += $ss[0]; $reasons += @($ss[1])
    $score += 10
    $reasons += 'authenticates with a client secret (API service integrations have no private-key option)'
    $active = @($Svc['secrets'] | Where-Object { $_ -and $_['status'] -eq 'ACTIVE' })
    if ($active.Count) {
        $oldest = Get-MaxAge $active $NowUtc
        if ($oldest -gt $RotationDays) { $score += 10; $reasons += "client secret not rotated in $oldest days (> $RotationDays)" }
        if ($active.Count -gt 1) { $score += 5; $reasons += "$($active.Count) active client secrets" }
    }
    $last = $null
    if ($Raw['logs_available']) {
        if ($Raw['token_grants']) { $last = $Raw['token_grants'][$Svc['id']] }
        if (-not $last -and $scopes.Count) {
            $score += 10
            $reasons += "no access token issued in the last $($Raw['log_window_days']) days: unused integration, removal candidate"
        }
    }
    $row = [ordered]@{
        type = 'api-service'; id = $Svc['id']
        name = $(if ($Svc['name']) { $Svc['name'] } else { $Svc['id'] })
        status = 'ACTIVE'; privilege = (Get-PrivilegeText @() $scopes)
        credential = 'client_secret'
        last_used = $(if ($Raw['logs_available']) { ConvertTo-NormTime $last } else { 'unknown' })
        created = (ConvertTo-NormTime $Svc['createdAt'])
        details = [ordered]@{ scopes = $scopes; admin_roles = [string[]]@(); created_by = $Svc['createdBy'] }
    }
    return Complete-Row $row $score $reasons
}

function Get-TokenRow {
    param($Tok, $Raw, [datetime]$NowUtc)
    $owner = $null
    if ($Tok['userId'] -and $Raw['users']) { $owner = $Raw['users'][$Tok['userId']] }
    if (-not $owner) { $owner = @{ missing = $true } }
    $roles = @($owner['roles'] | Where-Object { $_ })
    $score = 25
    $reasons = @('SSWS API token: a long-lived bearer secret with no scopes; it carries every admin right its owner has')
    if ($owner['unknown']) {
        $reasons += 'owner could not be read'
        $ownerTxt = $Tok['userId']
    } elseif ($owner['missing']) {
        $score += 40
        $reasons += "owner's user record is gone: nobody is accountable for this token"
        $ownerTxt = '(gone)'
    } else {
        $ownerTxt = if ($owner['login']) { $owner['login'] } else { $Tok['userId'] }
        if ($owner['status'] -ne 'ACTIVE') {
            $score += 30
            $reasons += "owner is $($owner['status']): the token outlived its owner"
        }
    }
    $rs = Get-RoleScore $roles
    if ($rs[1]) { $score += $rs[0]; $reasons += ('owner ' + $rs[1]) }
    $net = 'ANYWHERE'
    if ($Tok['network'] -and $Tok['network']['connection']) { $net = $Tok['network']['connection'] }
    if ($net -eq 'ANYWHERE') { $score += 15; $reasons += 'usable from any IP address (no network zone restriction)' }
    $age = Get-DaysSince $Tok['lastUpdated'] $NowUtc
    if ($null -ne $age -and $age -gt $StaleDays) { $score += 10; $reasons += "not used in $age days: revoke if nothing depends on it" }
    $row = [ordered]@{
        type = 'api-token'; id = $Tok['id']
        name = $(if ($Tok['name']) { $Tok['name'] } else { $Tok['id'] })
        status = 'ACTIVE'; privilege = (Get-PrivilegeText $roles $null -NoScopes)
        credential = "SSWS (network $net)"
        last_used = (ConvertTo-NormTime $Tok['lastUpdated'])
        created = (ConvertTo-NormTime $Tok['created'])
        details = [ordered]@{
            owner = $ownerTxt; owner_status = $owner['status']
            admin_roles = (Get-OrdinalSorted @($roles | ForEach-Object { $_['type'] }))
            expires_at = (ConvertTo-NormTime $Tok['expiresAt'])
            idle_window = $Tok['tokenWindow']; client_name = $Tok['clientName']
        }
    }
    return Complete-Row $row $score $reasons
}

function Get-UserRow {
    param($U, $Raw, [datetime]$NowUtc)
    $roles = @($U['roles'] | Where-Object { $_ })
    $factors = @($U['factors'] | Where-Object { $_ })
    $score = 0; $reasons = @("looks like a service account ($($U['matched']))")
    $rs = Get-RoleScore $roles
    if ($rs[1]) { $score += $rs[0]; $reasons += $rs[1] }
    if ($U['has_password'] -and $factors.Count -eq 0) { $score += 15; $reasons += 'no MFA enrolled: the password alone unlocks it' }
    if ($U['lastLogin']) { $score += 10; $reasons += 'has signed in interactively: someone is using it like a person (shared credential)' }
    $age = Get-DaysSince $U['passwordChanged'] $NowUtc
    if ($U['has_password'] -and $null -ne $age -and $age -gt 365) { $score += 5; $reasons += "password not changed in $age days" }
    $owned = @($Raw['api_tokens'] | Where-Object { $_ -and $_['userId'] -eq $U['id'] })
    if ($owned.Count) { $score += 5; $reasons += "owns $($owned.Count) API token(s)" }
    if ($U['status'] -ne 'ACTIVE') { $score = [int][Math]::Floor($score / 2) }
    $cred = $(if ($U['has_password']) { 'password' } else { 'no password' })
    if ($factors.Count) { $cred += " + $($factors.Count) factor(s)" } else { $cred += ', no MFA' }
    $row = [ordered]@{
        type = 'service-user'; id = $U['id']
        name = $(if ($U['login']) { $U['login'] } else { $U['id'] })
        status = $U['status']; privilege = (Get-PrivilegeText $roles $null -NoScopes)
        credential = $cred
        last_used = (ConvertTo-NormTime $U['lastLogin'])
        created = (ConvertTo-NormTime $U['created'])
        details = [ordered]@{
            admin_roles = (Get-OrdinalSorted @($roles | ForEach-Object { $_['type'] }))
            factors = (Get-OrdinalSorted $factors); user_type = $U['type_name']
        }
    }
    return Complete-Row $row $score $reasons
}

function Get-NhiRows {
    param($Raw, [datetime]$NowUtc)
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($a in @($Raw['apps'] | Where-Object { $_ })) { $rows.Add((Get-AppRow $a $Raw $NowUtc)) }
    foreach ($s in @($Raw['api_services'] | Where-Object { $_ })) { $rows.Add((Get-ApiServiceRow $s $Raw $NowUtc)) }
    foreach ($t in @($Raw['api_tokens'] | Where-Object { $_ })) { $rows.Add((Get-TokenRow $t $Raw $NowUtc)) }
    if ($Raw['users']) {
        foreach ($k in @($Raw['users'].Keys)) {
            $u = $Raw['users'][$k]
            if ($u['candidate']) { $rows.Add((Get-UserRow $u $Raw $NowUtc)) }
        }
    }
    # Same order as Python: score desc, type, lower-cased name (ordinal).
    # The key ends in the row's index, so it is unique and maps back to the row.
    $byKey = @{}
    $keys = [System.Collections.Generic.List[string]]::new()
    for ($i = 0; $i -lt $rows.Count; $i++) {
        $r = $rows[$i]
        $k = '{0:D6}|{1}|{2}|{3:D6}' -f (999999 - $r['score']), $r['type'], ([string]$r['name']).ToLowerInvariant(), $i
        $keys.Add($k); $byKey[$k] = $r
    }
    $keys.Sort([StringComparer]::Ordinal)
    $sorted = [System.Collections.Generic.List[object]]::new()
    foreach ($k in $keys) { $sorted.Add($byKey[$k]) }
    return , $sorted.ToArray()
}

function Get-NhiSummary {
    param([object[]]$Rows)
    $byType = [ordered]@{ 'oauth-service-app' = 0; 'api-service' = 0; 'api-token' = 0; 'service-user' = 0 }
    $byRisk = [ordered]@{ critical = 0; high = 0; medium = 0; low = 0 }
    foreach ($r in $Rows) { $byType[$r['type']]++; $byRisk[$r['risk']]++ }
    return [ordered]@{ total = @($Rows).Count; by_type = $byType; by_risk = $byRisk }
}

# ------------------------------------------------------------------ collection

function ConvertTo-Plain {
    # PSCustomObject tree -> hashtables/arrays so live data and -InputFile look the same.
    param($Obj)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [string] -or $Obj -is [ValueType]) { return $Obj }
    if ($Obj -is [System.Collections.IDictionary]) {
        $h = [ordered]@{}
        foreach ($k in $Obj.Keys) { $h[$k] = ConvertTo-Plain $Obj[$k] }
        return $h
    }
    if ($Obj -is [System.Collections.IEnumerable]) { return , @($Obj | ForEach-Object { ConvertTo-Plain $_ }) }
    $h = [ordered]@{}
    foreach ($p in $Obj.PSObject.Properties) { $h[$p.Name] = ConvertTo-Plain $p.Value }
    return $h
}

function Get-HttpCode {
    param([string]$Message)
    if ($Message -match 'HTTP (\d{3})') { return $Matches[1] }
    if ($Message -match 'error (\d{3})') { return $Matches[1] }
    return '?'
}

function Test-ServiceMatch {
    param($User, [hashtable]$TypeNames)
    $p = $User['profile']
    $local = ([string]$p['login']).Split('@')[0].ToLowerInvariant()
    foreach ($pair in @(@('login', $local), @('first name', ([string]$p['firstName']).ToLowerInvariant()), @('last name', ([string]$p['lastName']).ToLowerInvariant()))) {
        $m = [regex]::Match($pair[1], $NamePattern, 'IgnoreCase')
        if ($m.Success) { return "$($pair[0]) matches '$($m.Groups[2].Value)'" }
    }
    $tid = if ($User['type']) { $User['type']['id'] } else { $null }
    if ($tid -and $TypeNames.ContainsKey($tid)) {
        $tname = $TypeNames[$tid]
        if ($tname -and [regex]::Match($tname.ToLowerInvariant(), $NamePattern, 'IgnoreCase').Success) { return "user type '$tname'" }
    }
    return $null
}

function Invoke-NhiCollect {
    param([datetime]$NowUtc)
    Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'OktaClient.psm1') -Force
    $client = New-OktaClient
    $errors = [System.Collections.Generic.List[string]]::new()

    $getList = {
        param([string]$Path, [hashtable]$Query, [string]$What)
        try {
            # Callers wrap the result in @(); a null means "could not read".
            return @(Invoke-OktaPagedGet -Client $client -Path $Path -Query $Query | ForEach-Object { ConvertTo-Plain $_ })
        } catch {
            $errors.Add("$($What): HTTP $(Get-HttpCode "$($_.Exception.Message)")")
            return $null
        }
    }
    # Object, $null when it does not exist (404), $false when unreadable.
    $getOne = {
        param([string]$Path, [string]$What)
        try {
            return (ConvertTo-Plain (Invoke-OktaRequest -Client $client -Method GET -Path $Path))
        } catch {
            $code = Get-HttpCode "$($_.Exception.Message)"
            if ($code -eq '404') { return $null }
            $errors.Add("$($What): HTTP $code")
            return $false
        }
    }

    $raw = [ordered]@{
        tenant = $client.BaseUrl; collected_at = (ConvertTo-NormTime $NowUtc)
        log_window_days = $LogDays; logs_available = $false
        apps = @(); api_services = @(); api_tokens = @(); users = [ordered]@{}
        token_grants = [ordered]@{}; errors = $null
    }

    [Console]::Error.WriteLine('listing OAuth apps...')
    $apps = [System.Collections.Generic.List[object]]::new()
    foreach ($app in @(& $getList '/api/v1/apps' @{ filter = 'name eq "oidc_client"' } 'apps')) {
        if (-not $app) { continue }
        $oc = @{}; if ($app['settings'] -and $app['settings']['oauthClient']) { $oc = $app['settings']['oauthClient'] }
        $cred = @{}; if ($app['credentials'] -and $app['credentials']['oauthClient']) { $cred = $app['credentials']['oauthClient'] }
        $grants = @($oc['grant_types'] | Where-Object { $_ })
        if (-not ($oc['application_type'] -eq 'service' -or $grants -contains 'client_credentials' -or $grants -contains $TokenExchange)) { continue }
        $cid = if ($cred['client_id']) { $cred['client_id'] } else { $app['id'] }
        $label = $app['label']
        $g = & $getList "/api/v1/apps/$($app['id'])/grants" $null "grants for $label"
        $r = & $getList "/oauth2/v1/clients/$cid/roles" $null "roles for $label"
        $s = & $getList "/api/v1/apps/$($app['id'])/credentials/secrets" $null "secrets for $label"
        $j = & $getOne "/api/v1/apps/$($app['id'])/credentials/jwks" "keys for $label"
        $keys = @()
        if ($j -is [System.Collections.IDictionary]) { $keys = @($j['keys'] | Where-Object { $_ }) }
        elseif ($j) { $keys = @($j | Where-Object { $_ }) }
        $apps.Add([ordered]@{
            id = $app['id']; label = $label; status = $app['status']; created = $app['created']
            client_id = $cid; application_type = $oc['application_type']; grant_types = $grants
            auth_method = $cred['token_endpoint_auth_method']
            scopes = (Get-OrdinalSorted @(@($g) | Where-Object { $_ -and $_['status'] -eq 'ACTIVE' -and $_['scopeId'] } | ForEach-Object { $_['scopeId'] }))
            roles = @(@($r) | Where-Object { $_ -and (-not $_['status'] -or $_['status'] -eq 'ACTIVE') } | ForEach-Object { [ordered]@{ type = $_['type']; label = $_['label'] } })
            secrets = @(@($s) | Where-Object { $_ } | ForEach-Object { [ordered]@{ status = $_['status']; created = $_['created'] } })
            keys = @($keys | ForEach-Object { [ordered]@{ status = $_['status']; created = $_['created'] } })
        })
    }
    $raw['apps'] = $apps.ToArray()

    [Console]::Error.WriteLine('listing API service integrations...')
    $svcs = [System.Collections.Generic.List[object]]::new()
    foreach ($svc in @(& $getList '/integrations/api/v1/api-services' $null 'api service integrations')) {
        if (-not $svc) { continue }
        $s = & $getList "/integrations/api/v1/api-services/$($svc['id'])/credentials/secrets" $null "secrets for $($svc['name'])"
        $svcs.Add([ordered]@{
            id = $svc['id']; name = $svc['name']; type = $svc['type']
            createdAt = $svc['createdAt']; createdBy = $svc['createdBy']
            grantedScopes = @($svc['grantedScopes'] | Where-Object { $_ })
            secrets = @(@($s) | Where-Object { $_ } | ForEach-Object { [ordered]@{ status = $_['status']; created = $_['created'] } })
        })
    }
    $raw['api_services'] = $svcs.ToArray()

    [Console]::Error.WriteLine('listing API tokens...')
    $raw['api_tokens'] = @(@(& $getList '/api/v1/api-tokens' $null 'api tokens (needs a SUPER_ADMIN token)') | Where-Object { $_ } | ForEach-Object {
        $t = $_
        $o = [ordered]@{}
        foreach ($k in 'id', 'name', 'userId', 'clientName', 'created', 'expiresAt', 'lastUpdated', 'tokenWindow', 'network') { $o[$k] = $t[$k] }
        $o
    })

    [Console]::Error.WriteLine('scanning users for service accounts...')
    $typeNames = @{}
    foreach ($t in @(& $getList '/api/v1/meta/types/user' $null 'user types')) {
        if ($t) { $typeNames[$t['id']] = $(if ($t['name']) { $t['name'] } elseif ($t['displayName']) { $t['displayName'] } else { '' }) }
    }
    $found = [ordered]@{}
    foreach ($u in @(& $getList '/api/v1/users' $null 'users')) {
        if (-not $u) { continue }
        $m = Test-ServiceMatch $u $typeNames
        if ($m) { $found[$u['id']] = @($u, $m) }
    }
    foreach ($t in $raw['api_tokens']) {
        $uid = $t['userId']
        if ($uid -and -not $found.Contains($uid)) {
            $u = & $getOne "/api/v1/users/$uid" "token owner $uid"
            if ($null -eq $u) { $found[$uid] = @($null, $null); $raw['users'][$uid] = [ordered]@{ id = $uid; missing = $true } }
            elseif ($u -is [bool]) { $found[$uid] = @($null, $null); $raw['users'][$uid] = [ordered]@{ id = $uid; unknown = $true } }
            else { $found[$uid] = @($u, $null) }
        }
    }
    foreach ($uid in @($found.Keys)) {
        $u = $found[$uid][0]; $matched = $found[$uid][1]
        if (-not $u) { continue }
        $p = $u['profile']
        $tid = if ($u['type']) { $u['type']['id'] } else { $null }
        $rec = [ordered]@{
            id = $uid; login = $p['login']; status = $u['status']; created = $u['created']
            lastLogin = $u['lastLogin']; passwordChanged = $u['passwordChanged']
            has_password = [bool]($u['credentials'] -and $u['credentials'].Contains('password'))
            type_name = $(if ($tid -and $typeNames.ContainsKey($tid)) { $typeNames[$tid] } else { $null })
            candidate = [bool]$matched; matched = $matched
            roles = @(@(& $getList "/api/v1/users/$uid/roles" $null "roles for $($p['login'])") | Where-Object { $_ } | ForEach-Object { [ordered]@{ type = $_['type']; label = $_['label'] } })
        }
        if ($matched) {
            $rec['factors'] = @(@(& $getList "/api/v1/users/$uid/factors" $null "factors for $($p['login'])") | Where-Object { $_ -and $_['status'] -eq 'ACTIVE' } | ForEach-Object { $_['factorType'] })
        }
        $raw['users'][$uid] = $rec
    }

    if (-not $NoLogs) {
        [Console]::Error.WriteLine('reading System Log for last token grants...')
        $since = $NowUtc.AddDays(-$LogDays).ToString('yyyy-MM-ddTHH:mm:ss.000Z', $Inv)
        $until = $NowUtc.ToString('yyyy-MM-ddTHH:mm:ss.000Z', $Inv)
        $evFilter = ($GrantEvents | ForEach-Object { "eventType eq `"$_`"" }) -join ' or '
        $ok = $true
        $ids = @($raw['apps'] | ForEach-Object { $_['client_id'] }) + @($raw['api_services'] | ForEach-Object { $_['id'] })
        foreach ($cid in $ids) {
            if (-not $cid) { continue }
            $q = @{ filter = "($evFilter) and actor.id eq `"$cid`" and outcome.result eq `"SUCCESS`""; since = $since; until = $until; sortOrder = 'DESCENDING'; limit = 1 }
            try {
                $latest = Invoke-OktaPagedGet -Client $client -Path '/api/v1/logs' -Query $q | Select-Object -First 1
            } catch {
                $errors.Add("system log: HTTP $(Get-HttpCode "$($_.Exception.Message)")")
                $ok = $false
                break
            }
            $raw['token_grants'][$cid] = $(if ($latest) { ConvertTo-NormTime $latest.published } else { $null })
        }
        $raw['logs_available'] = $ok
    }
    $raw['errors'] = [string[]]$errors.ToArray()
    return $raw
}

# ------------------------------------------------------------------ output

function Format-Cut {
    param($Value, [int]$Max)
    $s = [string]$Value
    if ($s.Length -gt $Max) { return $s.Substring(0, $Max) }
    return $s
}

function Format-NhiText {
    param($Raw, [object[]]$Rows)
    $s = Get-NhiSummary $Rows
    $bt = $s['by_type']; $br = $s['by_risk']
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("Non-human identity inventory: $($Raw['tenant']) (collected $(ConvertTo-NormTime $Raw['collected_at']))")
    $lines.Add("  $($s['total']) identities: $($bt['oauth-service-app']) OAuth service apps, $($bt['api-service']) API service integrations, $($bt['api-token']) API tokens, $($bt['service-user']) service-account users")
    $lines.Add('  ' + (($br.Keys | ForEach-Object { "$($_.ToUpperInvariant()) $($br[$_])" }) -join ' | '))
    $lines.Add('')
    if (@($Rows).Count -eq 0) {
        $lines.Add('No non-human identities found.')
    } else {
        $lines.Add(('{0,-9}{1,5}  {2,-18}{3,-28}{4,-38}{5,-24}LAST USED' -f 'RISK', 'SCORE', 'TYPE', 'NAME', 'PRIVILEGE', 'CREDENTIAL'))
        $lines.Add('-' * 132)
        foreach ($r in $Rows) {
            $last = Format-Cut $(if ($r['last_used']) { $r['last_used'] } else { 'never' }) 10
            $lines.Add(('{0,-9}{1,5}  {2,-18}{3,-28}{4,-38}{5,-24}{6}' -f $r['risk'].ToUpperInvariant(), $r['score'], $r['type'], (Format-Cut $r['name'] 27), (Format-Cut $r['privilege'] 37), (Format-Cut $r['credential'] 23), $last))
            $lines.Add((' ' * 16) + "why: $($r['why'])")
        }
    }
    $errs = @($Raw['errors'] | Where-Object { $_ })
    if ($errs.Count) {
        $lines.Add(''); $lines.Add('Could not read (inventory may be incomplete):')
        foreach ($e in $errs) { $lines.Add("  - $e") }
    }
    if (-not $Raw['logs_available']) {
        $lines.Add(''); $lines.Add("System Log not read: 'last used' for OAuth apps is unknown.")
    }
    return ($lines -join "`n") + "`n"
}

$CsvFields = @('risk', 'score', 'type', 'name', 'id', 'status', 'privilege', 'credential', 'last_used', 'created', 'why')

function Format-NhiCsv {
    param([object[]]$Rows)
    $q = { param($v) '"' + ([string]$v).Replace('"', '""') + '"' }
    $out = [System.Collections.Generic.List[string]]::new()
    $out.Add((($CsvFields | ForEach-Object { & $q $_ }) -join ','))
    foreach ($r in $Rows) { $out.Add((($CsvFields | ForEach-Object { & $q $r[$_] }) -join ',')) }
    return ($out -join "`n") + "`n"
}

function Format-NhiJson {
    param($Raw, [object[]]$Rows)
    $obj = [ordered]@{
        tenant = $Raw['tenant']; collected_at = (ConvertTo-NormTime $Raw['collected_at'])
        log_window_days = $Raw['log_window_days']; logs_available = [bool]$Raw['logs_available']
        summary = (Get-NhiSummary $Rows); identities = @($Rows)
        errors = [string[]]@($Raw['errors'] | Where-Object { $_ })
    }
    return ($obj | ConvertTo-Json -Depth 12) + "`n"
}

# ------------------------------------------------------------------ main

$nowUtc = [datetime]::UtcNow
if ($Now) {
    $nowUtc = [datetime]::ParseExact((ConvertTo-NormTime $Now), 'yyyy-MM-ddTHH:mm:ssZ', $Inv, [Globalization.DateTimeStyles]::AdjustToUniversal -bor [Globalization.DateTimeStyles]::AssumeUniversal)
}
if ($Json -and $Csv) { [Console]::Error.WriteLine('error: choose -Json or -Csv, not both'); exit 1 }

try {
    if ($InputFile) {
        $raw = Get-Content -Raw -Path $InputFile | ConvertFrom-Json -AsHashtable
    } else {
        $raw = Invoke-NhiCollect -NowUtc $nowUtc
    }
} catch {
    [Console]::Error.WriteLine("error: $($_.Exception.Message)")
    if ($env:NHI_DEBUG) { [Console]::Error.WriteLine($_.ScriptStackTrace) }
    exit 1
}
if ($SaveRaw) {
    [IO.File]::WriteAllText($SaveRaw, ($raw | ConvertTo-Json -Depth 12))
    [Console]::Error.WriteLine("wrote $SaveRaw")
}

$allRows = Get-NhiRows $raw $nowUtc
$minIdx = $Levels.IndexOf($MinRisk)
$rows = @($allRows | Where-Object { $Levels.IndexOf($_['risk']) -ge $minIdx })

if ($Json) { $report = Format-NhiJson $raw $rows }
elseif ($Csv) { $report = Format-NhiCsv $rows }
else { $report = Format-NhiText $raw $rows }

if ($Output) {
    [IO.File]::WriteAllText($Output, $report)
    [Console]::Error.WriteLine("wrote $Output")
} else {
    [Console]::Out.Write($report)
}

if ($FailOn -ne 'none') {
    $failIdx = $Levels.IndexOf($FailOn)
    if (@($allRows | Where-Object { $Levels.IndexOf($_['risk']) -ge $failIdx }).Count) { exit 2 }
}
exit 0
