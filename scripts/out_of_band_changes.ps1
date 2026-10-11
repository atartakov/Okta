<#
.SYNOPSIS
    Reports Okta configuration and access changes made outside code (Admin Console clicks, ad-hoc API calls). Read-only.

.DESCRIPTION
    If your tenant is managed as code (Terraform, scripts, a CI pipeline), every
    legitimate change is made by a known automation identity. This script reads
    the System Log for configuration changes in a time window and sorts each one:

      via code   made by an -AutomationActor (Terraform service app, pipeline token user)
      automatic  made by Okta itself (group rules, the system principal)
      manual     anything else: the out-of-band list

    Manual changes are ranked HIGH / MEDIUM / LOW (admin grants, policy, network
    zone and API token changes are HIGH, as is membership in an admin-ish group),
    grouped by who made them, and can be joined to a tenant_drift_detector diff
    to show who caused each piece of drift.

    Authentication comes from the OKTA_DOMAIN / OKTA_API_TOKEN environment
    variables only.

.PARAMETER Since
    Window start: 90m, 24h, 7d, or an ISO8601 timestamp. Default 24h.

.PARAMETER Until
    Window end, ISO8601. Default now.

.PARAMETER AutomationActor
    Comma-separated actor ids, logins, or names that make changes via code.

.PARAMETER SensitiveGroups
    Regex for group/app names whose membership changes count as HIGH.

.PARAMETER Drift
    Path to tenant_drift_detector JSON diff output to attribute.

.PARAMETER InputFile
    Read System Log events from a JSON file instead of the API.

.PARAMETER IncludeFailures
    Also report changes whose outcome was not SUCCESS.

.PARAMETER FailOn
    none | low | medium | high. Exit 2 if a manual change at or above this severity is found.

.PARAMETER Json
    Emit JSON.

.PARAMETER Markdown
    Emit Markdown (GitHub issue / step summary).

.PARAMETER Output
    Write the report to this file path.

.EXAMPLE
    .\out_of_band_changes.ps1 -Since 24h -AutomationActor "0oa1terraformapp"

.EXAMPLE
    .\out_of_band_changes.ps1 -Since 7d -AutomationActor "svc-terraform@example.com" -Drift .\drift.json -Markdown -Output .\report.md

.EXAMPLE
    .\out_of_band_changes.ps1 -Since 24h -AutomationActor "0oa1terraformapp" -FailOn high
#>

param(
    [string]$Since = '24h',
    [string]$Until,
    [string]$AutomationActor = '',
    [string]$SensitiveGroups = 'admin|super|privileged|break.?glass|security',
    [string]$Drift,
    [string]$InputFile,
    [switch]$IncludeFailures,
    [ValidateSet('none', 'low', 'medium', 'high')][string]$FailOn = 'none',
    [switch]$Json,
    [switch]$Markdown,
    [string]$Output
)

$ErrorActionPreference = 'Stop'

# Names checked against Okta's event type catalog (okta-event-types.csv).
$HighEvents = @(
    'user.account.privilege.grant', 'user.account.privilege.revoke',
    'group.privilege.grant', 'group.privilege.revoke',
    'app.oauth2.client.privilege.grant', 'app.oauth2.client.privilege.revoke',
    'iam.role.create', 'iam.role.permissions.add', 'iam.resourceset.bindings.add',
    'policy.lifecycle.create', 'policy.lifecycle.update', 'policy.lifecycle.delete',
    'policy.lifecycle.activate', 'policy.lifecycle.deactivate',
    'policy.rule.add', 'policy.rule.update', 'policy.rule.delete',
    'policy.rule.activate', 'policy.rule.deactivate',
    'zone.create', 'zone.update', 'zone.delete', 'zone.activate', 'zone.deactivate',
    'zone.make_blacklist', 'zone.remove_blacklist',
    'system.api_token.create', 'system.api_token.revoke'
)
$MediumEvents = @(
    'group.lifecycle.create', 'group.lifecycle.delete', 'group.profile.update',
    'group.application_assignment.add', 'group.application_assignment.remove',
    'group.application_assignment.update',
    'application.lifecycle.create', 'application.lifecycle.update',
    'application.lifecycle.delete', 'application.lifecycle.activate',
    'application.lifecycle.deactivate'
)
$LowEvents = @(
    'group.user_membership.add', 'group.user_membership.remove',
    'application.user_membership.add', 'application.user_membership.remove'
)
$AllEvents = $HighEvents + $MediumEvents + $LowEvents
$Prefixes = @('user.account.privilege', 'group.', 'app.oauth2.client.privilege',
    'iam.', 'policy.lifecycle', 'policy.rule', 'zone.', 'system.api_token',
    'application.lifecycle', 'application.user_membership')
$Rank = @{ low = 0; medium = 1; high = 2 }

function ConvertTo-SinceIso {
    param([string]$Value)
    if ($Value -match '^(\d+)([mhd])$') {
        $n = [int]$Matches[1]
        $now = [datetime]::UtcNow
        $when = switch ($Matches[2]) {
            'm' { $now.AddMinutes(-$n) }
            'h' { $now.AddHours(-$n) }
            'd' { $now.AddDays(-$n) }
        }
        return $when.ToString("yyyy-MM-ddTHH:mm:ss.000Z")
    }
    [void][datetimeoffset]::Parse($Value)  # validate
    return $Value
}

function Get-Prop {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function Get-ActorKeys {
    param($Actor)
    $keys = @()
    foreach ($k in 'id', 'alternateId', 'displayName') {
        $v = Get-Prop $Actor $k
        if ($v) { $keys += ([string]$v).ToLower() }
    }
    return $keys
}

function Get-ChangeKind {
    param($LogEvent, [string[]]$Automation)
    $actor = Get-Prop $LogEvent 'actor'
    foreach ($k in (Get-ActorKeys $actor)) { if ($Automation -contains $k) { return 'via code' } }
    $debugData = Get-Prop (Get-Prop $LogEvent 'debugContext') 'debugData'
    if (Get-Prop $debugData 'triggeredByGroupRuleId') { return 'automatic' }
    if ((Get-Prop $actor 'type') -eq 'SystemPrincipal' -or
        ([string](Get-Prop $actor 'alternateId')).ToLower() -eq 'system@okta.com') { return 'automatic' }
    return 'manual'
}

function Get-ChangeSeverity {
    param($LogEvent, [string]$Sensitive)
    $type = Get-Prop $LogEvent 'eventType'
    if ($HighEvents -contains $type) { return 'high' }
    if ($LowEvents -contains $type) {
        foreach ($t in @(Get-Prop $LogEvent 'targets')) {
            if ($null -eq $t) { continue }
            if (@('UserGroup', 'AppInstance') -contains (Get-Prop $t 'type') -and
                ([string](Get-Prop $t 'displayName')) -match "(?i)$Sensitive") { return 'high' }
        }
        return 'low'
    }
    return 'medium'
}

function Get-TargetLabel {
    param($Target)
    $name = Get-Prop $Target 'displayName'
    if (-not $name) { $name = Get-Prop $Target 'alternateId' }
    if (-not $name) { $name = Get-Prop $Target 'id' }
    return "$(Get-Prop $Target 'type'): $name"
}

function Get-ActorLabel {
    param($Actor)
    foreach ($k in 'alternateId', 'displayName', 'id') {
        $v = Get-Prop $Actor $k
        if ($v) { return [string]$v }
    }
    return '?'
}

function Get-EventTime {
    param($LogEvent)
    $p = Get-Prop $LogEvent 'published'
    if ($p -is [datetime]) { return $p.ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ss.fffZ") }
    return [string]$p
}

# ---------------------------------------------------------------- load events

try { $sinceIso = ConvertTo-SinceIso $Since }
catch { [Console]::Error.WriteLine("error: -Since: can't read '$Since'"); exit 1 }
$window = "since $sinceIso" + $(if ($Until) { " until $Until" } else { '' })

try {
    if ($InputFile) {
        $events = @(Get-Content -Raw -Path $InputFile | ConvertFrom-Json)
        $window = "from $(Split-Path -Leaf $InputFile)"
    }
    else {
        Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
        $client = New-OktaClient
        $filter = ($Prefixes | ForEach-Object { "eventType sw `"$_`"" }) -join ' or '
        $q = @{ filter = $filter; since = $sinceIso; sortOrder = 'ASCENDING' }
        if ($Until) { $q['until'] = $Until }
        $events = @(Invoke-OktaPagedGet -Client $client -Path '/api/v1/logs' -Query $q)
    }
}
catch { [Console]::Error.WriteLine("error: $_"); exit 1 }

$automation = @($AutomationActor -split ',' | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ })
if ($automation.Count -eq 0) {
    [Console]::Error.WriteLine('warning: no -AutomationActor given, so every change counts as manual')
}

# ---------------------------------------------------------------- analyze

$counts = [ordered]@{ 'via code' = 0; 'automatic' = 0; 'manual' = 0 }
$manual = @()
foreach ($ev in $events) {
    $type = Get-Prop $ev 'eventType'
    if ($AllEvents -notcontains $type) { continue }
    $result = Get-Prop (Get-Prop $ev 'outcome') 'result'
    if (-not $result) { $result = 'SUCCESS' }
    if (-not $IncludeFailures -and $result -ne 'SUCCESS') { continue }
    $kind = Get-ChangeKind $ev $automation
    $counts[$kind]++
    if ($kind -ne 'manual') { continue }
    $actor = Get-Prop $ev 'actor'
    $targets = @(Get-Prop $ev 'targets') | Where-Object { $_ }
    $summary = Get-Prop $ev 'displayMessage'
    if (-not $summary) { $summary = $type }
    $manual += [pscustomobject][ordered]@{
        severity   = Get-ChangeSeverity $ev $SensitiveGroups
        time       = Get-EventTime $ev
        actor      = Get-ActorLabel $actor
        actor_type = Get-Prop $actor 'type'
        event_type = $type
        summary    = $summary
        targets    = @($targets | ForEach-Object { Get-TargetLabel $_ })
        target_ids = @($targets | ForEach-Object { Get-Prop $_ 'id' } | Where-Object { $_ })
        ip         = Get-Prop (Get-Prop $ev 'client') 'ipAddress'
        outcome    = $result
        uuid       = Get-Prop $ev 'uuid'
    }
}
$manual = @($manual | Sort-Object @{ Expression = { $Rank[$_.severity] }; Descending = $true }, @{ Expression = { $_.time } })

$actorOrder = @($manual | Group-Object actor |
    Sort-Object @{ Expression = { ($_.Group | ForEach-Object { $Rank[$_.severity] } | Measure-Object -Maximum).Maximum }; Descending = $true } |
    ForEach-Object { $_.Name })

# ---------------------------------------------------------------- drift join

$driftRows = $null
if ($Drift) {
    $diff = Get-Content -Raw -Path $Drift | ConvertFrom-Json
    $byTarget = @{}
    foreach ($ev in $events) {
        if ($AllEvents -notcontains (Get-Prop $ev 'eventType')) { continue }
        $who = Get-ActorLabel (Get-Prop $ev 'actor')
        foreach ($t in @(Get-Prop $ev 'targets')) {
            $tid = Get-Prop $t 'id'
            if (-not $tid) { continue }
            if (-not $byTarget.ContainsKey($tid)) { $byTarget[$tid] = @() }
            $byTarget[$tid] += [pscustomobject]@{ when = (Get-EventTime $ev); who = $who; type = (Get-Prop $ev 'eventType') }
        }
    }
    $driftRows = @()
    foreach ($grp in $diff.PSObject.Properties) {
        foreach ($verb in 'added', 'removed', 'changed') {
            foreach ($item in @(Get-Prop $grp.Value $verb)) {
                if ($null -eq $item) { continue }
                if ($verb -eq 'changed') { $res = Get-Prop $item 'resource'; $key = Get-Prop $item 'key' }
                else {
                    $res = $item
                    $key = Get-Prop $res 'id'
                    if (-not $key) { $key = "$(Get-Prop $res 'user_id')::$(Get-Prop $res 'role_type')" }
                }
                $name = Get-Prop $res 'name'
                if (-not $name) { $name = Get-Prop $res 'label' }
                if (-not $name) { $name = Get-Prop $res 'login' }
                if (-not $name) { $name = $key }
                $rid = ([string]$key -split '::')[0]
                $hits = @()
                if ($byTarget.ContainsKey($rid)) { $hits = @($byTarget[$rid] | Sort-Object when) }
                $last = if ($hits.Count) { $hits[-1] } else { $null }
                $driftRows += [pscustomobject][ordered]@{
                    group      = $grp.Name
                    verb       = $verb
                    name       = $name
                    id         = $rid
                    changed_by = if ($last) { $last.who } else { $null }
                    when       = if ($last) { $last.when } else { $null }
                    event_type = if ($last) { $last.type } else { $null }
                }
            }
        }
    }
}

# ---------------------------------------------------------------- output

if ($Json) {
    $byActor = [ordered]@{}
    foreach ($a in $actorOrder) { $byActor[$a] = @($manual | Where-Object { $_.actor -eq $a }) }
    $report = [ordered]@{ window = $window; counts = $counts; manual = $manual; by_actor = $byActor; drift_attribution = $driftRows } |
        ConvertTo-Json -Depth 8
}
elseif ($Markdown) {
    $md = @("## Okta changes made outside code ($window)", '',
        "**$($counts['manual']) manual** · $($counts['via code']) via code · $($counts['automatic']) automatic", '')
    if ($manual.Count) {
        $md += '| Severity | When (UTC) | Who | What | Target |'
        $md += '|---|---|---|---|---|'
        foreach ($r in $manual) {
            $md += "| $($r.severity.ToUpper()) | $($r.time) | $($r.actor) | $($r.summary) | $((@($r.targets) | Select-Object -First 2) -join '; ') |"
        }
    }
    else { $md += 'No out-of-band changes.' }
    if ($null -ne $driftRows) {
        $md += @('', '### Drift attribution', '', '| Change | Resource | Changed by | When |', '|---|---|---|---|')
        foreach ($d in $driftRows) {
            $by = if ($d.changed_by) { $d.changed_by } else { '_not found in window_' }
            $md += "| $($d.verb) $($d.group) | $($d.name) | $by | $($d.when) |"
        }
    }
    $report = ($md -join "`n") + "`n"
}
else {
    $lines = @("Okta changes $window",
        "  via code: $($counts['via code'])   automatic: $($counts['automatic'])   manual (out of band): $($counts['manual'])", '')
    if (-not $manual.Count) { $lines += 'No out-of-band changes.' }
    foreach ($a in $actorOrder) {
        $rows = @($manual | Where-Object { $_.actor -eq $a })
        $plural = if ($rows.Count -ne 1) { 's' } else { '' }
        $lines += "== $a ($($rows.Count) change$plural)"
        foreach ($r in $rows) {
            $tgt = (@($r.targets) | Select-Object -First 3) -join '; '
            $arrow = if ($tgt) { "  -> $tgt" } else { '' }
            $ip = if ($r.ip) { $r.ip } else { '?' }
            $lines += ("  [{0,-6}] {1}  {2}{3}  (ip {4})" -f $r.severity.ToUpper(), $r.time, $r.summary, $arrow, $ip)
        }
        $lines += ''
    }
    if ($null -ne $driftRows) {
        $lines += '== Drift attribution'
        foreach ($d in $driftRows) {
            $who = if ($d.changed_by) { $d.changed_by } else { 'no matching System Log event in window' }
            $at = if ($d.when) { "  at $($d.when)" } else { '' }
            $lines += ("  {0,-7} {1}: {2}  <- {3}{4}" -f $d.verb, $d.group, $d.name, $who, $at)
        }
    }
    $report = (($lines -join "`n").TrimEnd()) + "`n"
}

if ($Output) {
    Set-Content -Path $Output -Value $report -Encoding utf8 -NoNewline
    [Console]::Error.WriteLine("wrote $Output")
}
else { Write-Output $report.TrimEnd("`n") }

if ($FailOn -ne 'none' -and @($manual | Where-Object { $Rank[$_.severity] -ge $Rank[$FailOn] }).Count -gt 0) { exit 2 }
exit 0
