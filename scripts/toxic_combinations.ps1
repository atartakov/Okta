<#
.SYNOPSIS
    Finds users holding toxic access combinations (separation of duties). Read-only.

.DESCRIPTION
    You describe access that must never sit with one person in a small JSON
    policy file ("AWS prod admin" + "finance approver", "creates vendors" +
    "approves payments", "Okta super admin" + "no phishing-resistant factor").
    The script pulls users, group memberships, app assignments (direct and via
    group) and admin role assignments, then reports every user who holds a
    toxic combination:

      * HOW they got each side: assigned directly, via a group, via a group a
        group rule fills automatically, via a directory-synced group, or via
        the Everyone group
      * the SMALLEST FIX: the fewest, most targeted changes that break the
        combination
      * a risk-ranked table, plain-English explanations, JSON and CSV

    Policy entry types (each side of a rule is "any_of" or "all_of" a list):
      {"type": "app", "value": "<app label, name or id>"}
      {"type": "app_group", "app": "<app>", "group": "<group>"}
      {"type": "group", "value": "<group name or id>"}
      {"type": "admin_role", "value": "SUPER_ADMIN | <role label> | <custom role id>"}
      {"type": "no_phishing_resistant_factor"}
    See examples/sod_policy.example.json. Mirrors scripts/toxic_combinations.py
    output for output.

    STRICTLY READ-ONLY: every HTTP call is a GET. Authentication comes from the
    OKTA_DOMAIN / OKTA_API_TOKEN environment variables only.

    Exit codes: 0 = no finding at or above -FailOn, 2 = findings at or above
    -FailOn, 1 = error.

.PARAMETER Policy
    JSON policy file (see examples/sod_policy.example.json).

.PARAMETER Snapshot
    Analyze a saved snapshot instead of calling Okta (offline).

.PARAMETER SaveSnapshot
    Write the data pulled from Okta to this file.

.PARAMETER Json
    Emit JSON instead of the text report.

.PARAMETER Csv
    Also write findings as CSV to this file.

.PARAMETER Output
    Write the report (text or JSON) to this file.

.PARAMETER FailOn
    none | low | medium | high | critical. Exit 2 if any finding is at or above this risk.

.EXAMPLE
    ./scripts/toxic_combinations.ps1 -Policy examples/sod_policy.example.json

.EXAMPLE
    ./scripts/toxic_combinations.ps1 -Policy sod.json -Json -Output sod.json -Csv sod.csv

.EXAMPLE
    ./scripts/toxic_combinations.ps1 -Policy sod.json -FailOn high
#>

param(
    [Parameter(Mandatory)][string]$Policy,
    [string]$Snapshot,
    [string]$SaveSnapshot,
    [switch]$Json,
    [string]$Csv,
    [string]$Output,
    [ValidateSet('none', 'low', 'medium', 'high', 'critical')][string]$FailOn = 'none'
)

$ErrorActionPreference = 'Stop'

$Severities = @('low', 'medium', 'high', 'critical')
$BaseScore = @{ critical = 90; high = 70; medium = 50; low = 30 }
$EntryTypes = @('app', 'app_group', 'group', 'admin_role', 'no_phishing_resistant_factor')
$DefaultPrFactors = @('webauthn', 'smart_card', 'signed_nonce')
$CanSignIn = @('ACTIVE', 'PASSWORD_EXPIRED', 'LOCKED_OUT', 'RECOVERY')
$CostEveryone = 50

# ---------------------------------------------------------------- helpers

function Get-V {
    param($Obj, [string]$Key)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) {
        if ($Obj.Contains($Key)) { return $Obj[$Key] }
        return $null
    }
    $p = $Obj.PSObject.Properties[$Key]
    if ($p) { return $p.Value }
    return $null
}

function New-List { return , ([System.Collections.Generic.List[object]]::new()) }

function Test-Eq {
    param($A, $B)
    return ($null -ne $A) -and ($null -ne $B) -and ([string]$A).ToLowerInvariant() -ceq ([string]$B).ToLowerInvariant()
}

function Get-SortedByKey {
    # Ordinal sort on a string key, stable; matches the Python port.
    param($Items, [scriptblock]$KeyFunc)
    $arr = @($Items)
    $n = $arr.Count
    $keys = [string[]]::new($n)
    $idx = [int[]]::new($n)
    for ($i = 0; $i -lt $n; $i++) { $keys[$i] = (& $KeyFunc $arr[$i]) + "`u{0}" + $i.ToString('D8'); $idx[$i] = $i }
    [Array]::Sort($keys, $idx, [StringComparer]::Ordinal)
    $out = New-List
    foreach ($i in $idx) { $out.Add($arr[$i]) }
    return , $out
}

function Get-SortedStrings {
    param($Items)
    $arr = [string[]]@($Items | Where-Object { $null -ne $_ })
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    return , $arr
}

function Get-GroupName { param($G) $n = Get-V (Get-V $G 'profile') 'name'; if ($n) { return [string]$n }; return [string](Get-V $G 'id') }
function Get-UserLogin { param($U) $l = Get-V (Get-V $U 'profile') 'login'; if ($l) { return [string]$l }; return [string](Get-V $U 'id') }

function Test-AppMatch { param($App, $Value) foreach ($k in 'id', 'label', 'name') { if (Test-Eq (Get-V $App $k) $Value) { return $true } }; return $false }
function Test-GroupMatch { param($G, $Value) return (Test-Eq (Get-V $G 'id') $Value) -or (Test-Eq (Get-GroupName $G) $Value) }
function Test-RoleMatch { param($R, $Value) foreach ($k in 'type', 'label', 'role', 'id') { if (Test-Eq (Get-V $R $k) $Value) { return $true } }; return $false }

function Get-RoleName {
    param($R)
    $label = [string](Get-V $R 'label'); $rtype = [string](Get-V $R 'type')
    if ($label -and $rtype -and $label -cne $rtype) { return "$label ($rtype)" }
    if ($label) { return $label }
    if ($rtype) { return $rtype }
    return '?'
}

function Get-SideEntries { param($Side) if ($Side.Contains('all_of')) { return , @($Side['all_of']) }; return , @(Get-V $Side 'any_of') }
function Get-SideMode { param($Side) if ($Side.Contains('all_of')) { return 'all_of' }; return 'any_of' }

# ---------------------------------------------------------------- policy

function Assert-Policy {
    param($P)
    $rules = Get-V $P 'rules'
    if (-not ($P -is [System.Collections.IDictionary]) -or $null -eq $rules -or @($rules).Count -eq 0) {
        throw 'policy needs a non-empty "rules" list'
    }
    $seen = @{}
    $i = 0
    foreach ($rule in $rules) {
        $i++
        $rid = Get-V $rule 'id'; if (-not $rid) { $rid = "rule #$i" }
        if (-not (Get-V $rule 'id') -or -not (Get-V $rule 'name')) { throw "${rid}: every rule needs an `"id`" and a `"name`"" }
        if ($seen.ContainsKey($rid)) { throw "${rid}: duplicate rule id" }
        $seen[$rid] = $true
        $sev = Get-V $rule 'severity'; if (-not $sev) { $sev = 'high' }
        if (([string]$sev).ToLowerInvariant() -notin $Severities) { throw "${rid}: severity must be one of $($Severities -join ', ')" }
        $sides = Get-V $rule 'sides'
        if ($null -eq $sides -or @($sides).Count -lt 2) { throw "${rid}: `"sides`" needs at least two entries" }
        foreach ($s in $sides) {
            $entries = Get-SideEntries $s
            if (-not (Get-V $s 'label') -or $entries.Count -eq 0 -or $null -eq $entries[0]) {
                throw "${rid}: each side needs a `"label`" and a non-empty `"any_of`" or `"all_of`" list"
            }
            foreach ($e in $entries) {
                $t = Get-V $e 'type'
                if ($t -notin $EntryTypes) { throw "${rid}: unknown entry type '$t'" }
                if ($t -in 'app', 'group', 'admin_role' -and -not (Get-V $e 'value')) { throw "${rid}: $t entry needs a `"value`"" }
                if ($t -eq 'app_group' -and -not ((Get-V $e 'app') -and (Get-V $e 'group'))) { throw "${rid}: app_group entry needs `"app`" and `"group`"" }
            }
        }
    }
}

function Get-PolicyEntries {
    param($P)
    $out = New-List
    foreach ($rule in $P['rules']) { foreach ($side in $rule['sides']) { foreach ($e in (Get-SideEntries $side)) { $out.Add($e) } } }
    return , $out
}

# ---------------------------------------------------------------- tenant index

function New-TenantIndex {
    param($Snap)
    $t = @{}
    $t.Users = New-List
    foreach ($u in @(Get-V $Snap 'users')) { if ($u -and (Get-V $u 'status') -ne 'DEPROVISIONED') { $t.Users.Add($u) } }
    $t.Groups = [ordered]@{}
    foreach ($g in @(Get-V $Snap 'groups')) { if ($g) { $t.Groups[[string]$g['id']] = $g } }
    $t.Apps = [ordered]@{}
    foreach ($a in @(Get-V $Snap 'apps')) { if ($a) { $t.Apps[[string]$a['id']] = $a } }
    foreach ($k in 'app_users', 'app_groups', 'user_roles', 'group_roles', 'factors') {
        $v = Get-V $Snap $k; if ($null -eq $v) { $v = @{} }
        $t[$k] = $v
    }
    $t.Members = @{}
    $gm = Get-V $Snap 'group_members'
    if ($gm) { foreach ($gid in $gm.Keys) { $set = [System.Collections.Generic.HashSet[string]]::new(); foreach ($x in @($gm[$gid])) { if ($x) { [void]$set.Add([string]$x) } }; $t.Members[[string]$gid] = $set } }
    $t.Everyone = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($g in $t.Groups.Values) { if ((Get-V $g 'type') -eq 'BUILT_IN' -and (Get-GroupName $g) -ceq 'Everyone') { [void]$t.Everyone.Add([string]$g['id']) } }
    foreach ($gid in $t.Everyone) {
        $set = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($u in $t.Users) { [void]$set.Add([string]$u['id']) }
        $t.Members[$gid] = $set
    }
    $t.RuleForGroup = @{}
    foreach ($r in @(Get-V $Snap 'group_rules')) {
        if (-not $r -or (Get-V $r 'status') -ne 'ACTIVE') { continue }
        $gids = Get-V (Get-V (Get-V $r 'actions') 'assignUserToGroups') 'groupIds'
        $rname = Get-V $r 'name'; if (-not $rname) { $rname = Get-V $r 'id' }
        foreach ($gid in @($gids)) {
            if (-not $gid) { continue }
            if (-not $t.RuleForGroup.ContainsKey($gid)) { $t.RuleForGroup[$gid] = New-List }
            $t.RuleForGroup[$gid].Add([string]$rname)
        }
    }
    $t.UserGroups = @{}
    foreach ($gid in $t.Members.Keys) {
        foreach ($uid in $t.Members[$gid]) {
            if (-not $t.UserGroups.ContainsKey($uid)) { $t.UserGroups[$uid] = [System.Collections.Generic.HashSet[string]]::new() }
            [void]$t.UserGroups[$uid].Add($gid)
        }
    }
    return $t
}

function Find-Apps {
    param($T, $Value)
    $out = New-List
    foreach ($a in $T.Apps.Values) {
        $st = Get-V $a 'status'; if (-not $st) { $st = 'ACTIVE' }
        if ((Test-AppMatch $a $Value) -and $st -eq 'ACTIVE') { $out.Add($a) }
    }
    return , $out
}

function Find-Groups {
    param($T, $Value)
    $out = New-List
    foreach ($g in $T.Groups.Values) { if (Test-GroupMatch $g $Value) { $out.Add($g) } }
    return , $out
}

function Get-GName { param($T, $Gid) $g = $T.Groups[$Gid]; if ($g) { return Get-GroupName $g }; return $Gid }

function New-Path { param($Via, $How, $Fix, [int]$Cost) return [ordered]@{ via = $Via; how = $How; fix = $Fix; cost = $Cost } }

function Get-MembershipPath {
    param($T, [string]$Gid, [string]$Login, [string]$Thing, [string]$ViaText)
    $name = Get-GName $T $Gid
    $g = $T.Groups[$Gid]
    if ($T.Everyone.Contains($Gid)) {
        return New-Path 'everyone' "$ViaText the Everyone group (every user gets it)" "Stop granting $Thing to the Everyone group (affects every user)" $CostEveryone
    }
    if ($T.RuleForGroup.ContainsKey($Gid)) {
        $rules = ((Get-SortedStrings $T.RuleForGroup[$Gid]) | ForEach-Object { "'$_'" }) -join ', '
        return New-Path 'rule-managed group' "$ViaText group '$name', which group rule $rules fills automatically" "Change group rule $rules (or $Login's profile attributes) so $Login no longer lands in group '$name'; removing them by hand is undone by the rule" 3
    }
    if ((Get-V $g 'type') -eq 'APP_GROUP') {
        return New-Path 'directory group' "$ViaText group '$name', which is synced in from a directory or app" "Remove $Login from group '$name' in the directory it is synced from" 3
    }
    return New-Path 'group' "$ViaText group '$name' (direct membership; no group rule feeds this group)" "Remove $Login from group '$name'" 2
}

# ---------------------------------------------------------------- evaluation

function Get-EntryMatches {
    param($T, $User, $Entry, $PrFactors)
    $uid = [string]$User['id']; $login = Get-UserLogin $User
    $mygroups = $T.UserGroups[$uid]
    if ($null -eq $mygroups) { $mygroups = [System.Collections.Generic.HashSet[string]]::new() }
    $etype = $Entry['type']
    $found = New-List
    switch ($etype) {
        'app' {
            foreach ($app in (Find-Apps $T $Entry['value'])) {
                $aid = [string]$app['id']
                $lbl = Get-V $app 'label'; if (-not $lbl) { $lbl = $aid }
                $thing = "app '$lbl'"
                $paths = New-List
                foreach ($au in @(Get-V $T.app_users $aid)) {
                    if (-not $au -or (Get-V $au 'id') -ne $uid) { continue }
                    if ((Get-V $au 'scope') -eq 'USER') {
                        $paths.Add((New-Path 'direct' 'assigned to the user directly' "Unassign $thing from $login (direct assignment)" 1))
                    }
                }
                $assigned = @(Get-V $T.app_groups $aid) | Where-Object { $_ -and $mygroups.Contains([string]$_) }
                foreach ($gid in (Get-SortedStrings $assigned)) { $paths.Add((Get-MembershipPath $T $gid $login $thing 'via')) }
                if ($paths.Count) { $found.Add([ordered]@{ item = $thing; paths = $paths }) }
            }
        }
        'app_group' {
            foreach ($app in (Find-Apps $T $Entry['app'])) {
                $aid = [string]$app['id']
                foreach ($g in (Find-Groups $T $Entry['group'])) {
                    $gid = [string]$g['id']
                    if ((@(Get-V $T.app_groups $aid) -ccontains $gid) -and $mygroups.Contains($gid)) {
                        $lbl = Get-V $app 'label'; if (-not $lbl) { $lbl = $aid }
                        $thing = "app '$lbl' via group '$(Get-GroupName $g)'"
                        $paths = New-List; $paths.Add((Get-MembershipPath $T $gid $login $thing 'member of'))
                        $found.Add([ordered]@{ item = $thing; paths = $paths })
                    }
                }
            }
        }
        'group' {
            foreach ($g in (Find-Groups $T $Entry['value'])) {
                $gid = [string]$g['id']
                if ($mygroups.Contains($gid)) {
                    $thing = "group '$(Get-GroupName $g)'"
                    $paths = New-List; $paths.Add((Get-MembershipPath $T $gid $login $thing 'member of'))
                    $found.Add([ordered]@{ item = $thing; paths = $paths })
                }
            }
        }
        'admin_role' {
            $value = $Entry['value']
            $hits = @{}
            foreach ($r in @(Get-V $T.user_roles $uid)) {
                if (-not $r) { continue }
                $at = Get-V $r 'assignmentType'; if (-not $at) { $at = 'USER' }
                if ($at -eq 'USER' -and (Test-RoleMatch $r $value)) {
                    $thing = "admin role '$(Get-RoleName $r)'"
                    if (-not $hits.ContainsKey($thing)) { $hits[$thing] = New-List }
                    $hits[$thing].Add((New-Path 'direct' 'assigned to the user directly' "Remove $thing from $login (direct assignment)" 1))
                }
            }
            foreach ($gid in (Get-SortedStrings $mygroups)) {
                foreach ($r in @(Get-V $T.group_roles $gid)) {
                    if ($r -and (Test-RoleMatch $r $value)) {
                        $thing = "admin role '$(Get-RoleName $r)'"
                        if (-not $hits.ContainsKey($thing)) { $hits[$thing] = New-List }
                        $hits[$thing].Add((Get-MembershipPath $T $gid $login $thing 'via'))
                    }
                }
            }
            foreach ($thing in (Get-SortedStrings $hits.Keys)) { $found.Add([ordered]@{ item = $thing; paths = $hits[$thing] }) }
        }
        'no_phishing_resistant_factor' {
            $active = @(@(Get-V $T.factors $uid) | Where-Object { $_ -and $(if (Get-V $_ 'status') { (Get-V $_ 'status') -eq 'ACTIVE' } else { $true }) })
            $types = Get-SortedStrings (@($active | ForEach-Object { $ft = Get-V $_ 'factorType'; if ($ft) { $ft } else { '?' } }) | Select-Object -Unique)
            $hasPr = $false
            foreach ($f in $active) { if ((Get-V $f 'factorType') -in $PrFactors) { $hasPr = $true } }
            if (-not $hasPr) {
                $has = if ($types.Count) { $types -join ', ' } else { 'none' }
                $paths = New-List
                $paths.Add((New-Path 'condition' "no ACTIVE factor of a phishing-resistant type ($((Get-SortedStrings $PrFactors) -join ', '))" "Enroll $login in a phishing-resistant factor (FIDO2/WebAuthn key or Okta FastPass)" 1))
                $found.Add([ordered]@{ item = "no phishing-resistant factor (enrolled: $has)"; paths = $paths })
            }
        }
    }
    foreach ($f in $found) { $f['paths'] = Get-SortedByKey $f['paths'] { param($p) '{0:D3}|{1}' -f $p['cost'], $p['how'] } }
    return , $found
}

function Get-FixActions {
    param($Items)
    $acts = New-List; $cost = 0; $have = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($it in $Items) {
        foreach ($p in $it['paths']) {
            if ($have.Add($p['fix'])) { $acts.Add($p['fix']); $cost += $p['cost'] }
        }
    }
    return @{ Actions = $acts; Cost = $cost }
}

function Get-SideResult {
    param($T, $User, $Side, $PrFactors)
    $mode = Get-SideMode $Side
    $perEntry = New-List
    foreach ($e in (Get-SideEntries $Side)) { $perEntry.Add((Get-EntryMatches $T $User $e $PrFactors)) }
    $holds = if ($mode -eq 'all_of') { -not (@($perEntry | Where-Object { $_.Count -eq 0 })).Count } else { [bool](@($perEntry | Where-Object { $_.Count -gt 0 })).Count }
    if (-not $holds) { return @{ Holds = $false } }
    $items = New-List; $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($lst in $perEntry) { foreach ($it in $lst) { if ($seen.Add($it['item'])) { $items.Add($it) } } }
    if ($mode -eq 'any_of') {
        $best = Get-FixActions $items
    } else {
        $best = $null
        foreach ($lst in $perEntry) {
            $c = Get-FixActions $lst
            if ($null -eq $best -or $c.Cost -lt $best.Cost) { $best = $c }
        }
    }
    return @{ Holds = $true; Items = $items; Fix = [ordered]@{ side = $Side['label']; actions = $best.Actions; cost = $best.Cost } }
}

function Get-Explanation {
    param($Login, $Status, $Rule, $Sides, $Fix)
    $labels = @($Sides | ForEach-Object { "`"$($_['label'])`"" })
    $held = if ($labels.Count -eq 1) { $labels[0] } else { ($labels[0..($labels.Count - 2)] -join ', ') + ' and ' + $labels[-1] }
    $text = if ($labels.Count -eq 2) { "$Login holds both $held." } else { "$Login holds all of $held." }
    $why = Get-V $Rule 'why'
    if ($why) { $text += ' ' + ([string]$why).Trim() }
    $n = $Fix['actions'].Count
    $plural = if ($n -ne 1) { 's' } else { '' }
    $text += " Smallest fix ($n change$plural, breaks `"$($Fix['side'])`"): " + ($Fix['actions'] -join '; ') + '.'
    if ($Status -notin $CanSignIn) { $text += " The account is $Status, so it cannot sign in today, but the access is still assigned." }
    return $text
}

function Invoke-Analysis {
    param($Snap, $P)
    $t = New-TenantIndex $Snap
    $pr = Get-V $P 'phishing_resistant_factors'
    if (-not $pr) { $pr = $DefaultPrFactors }
    $pr = @($pr)
    $findings = New-List; $excepted = New-List
    foreach ($rule in $P['rules']) {
        $exceptions = @(@(Get-V $rule 'exceptions') | Where-Object { $null -ne $_ } | ForEach-Object { ([string]$_).ToLowerInvariant() })
        $severity = Get-V $rule 'severity'; if (-not $severity) { $severity = 'high' }
        $severity = ([string]$severity).ToLowerInvariant()
        foreach ($user in $t.Users) {
            $sides = New-List; $fixes = New-List; $all = $true
            foreach ($side in $rule['sides']) {
                $r = Get-SideResult $t $user $side $pr
                if (-not $r.Holds) { $all = $false; break }
                $sides.Add([ordered]@{ label = $side['label']; items = $r.Items })
                $fixes.Add($r.Fix)
            }
            if (-not $all) { continue }
            $login = Get-UserLogin $user
            if ($exceptions -ccontains $login.ToLowerInvariant() -or $exceptions -ccontains ([string]$user['id']).ToLowerInvariant()) {
                $excepted.Add([ordered]@{ user = $login; rule_id = $rule['id'] }); continue
            }
            $best = $null
            foreach ($f in $fixes) { if ($null -eq $best -or $f['cost'] -le $best['cost']) { $best = $f } }
            $status = Get-V $user 'status'; if (-not $status) { $status = '?' }
            $indirect = $false
            foreach ($s in $sides) { foreach ($it in $s['items']) { foreach ($p in $it['paths']) { if ($p['via'] -notin 'direct', 'condition') { $indirect = $true } } } }
            $score = $BaseScore[$severity]
            if ($status -eq 'ACTIVE') { $score += 5 } elseif ($status -notin $CanSignIn) { $score -= 20 }
            if ($indirect) { $score += 3 }
            $score = [Math]::Max(0, [Math]::Min(100, $score))
            $profile = Get-V $user 'profile'
            $name = ("$(Get-V $profile 'firstName') $(Get-V $profile 'lastName')").Trim()
            $why = Get-V $rule 'why'; if ($null -eq $why) { $why = '' }
            $findings.Add([ordered]@{
                risk = $severity.ToUpperInvariant(); score = [int]$score
                user = $login; user_id = [string]$user['id']; name = $name; status = $status
                rule_id = $rule['id']; rule = $rule['name']; why = $why
                sides = $sides; smallest_fix = $best; fix_options = $fixes
                explanation = (Get-Explanation $login $status $rule $sides $best)
            })
        }
    }
    $findings = Get-SortedByKey $findings { param($f) '{0:D4}|{1}|{2}' -f (1000 - $f['score']), $f['user'].ToLowerInvariant(), $f['rule_id'] }
    $i = 0
    foreach ($f in $findings) { $i++; $f['rank'] = $i }
    return @{ findings = $findings; excepted = $excepted; users_scanned = $t.Users.Count }
}

# ---------------------------------------------------------------- collection (GET only)

function ConvertTo-Hash { param($Obj) if ($null -eq $Obj) { return $null }; return ($Obj | ConvertTo-Json -Depth 20 -Compress | ConvertFrom-Json -AsHashtable) }

function Get-IamAssigneeIds {
    param($Client)
    $ids = New-List
    $path = '/api/v1/iam/assignees/users'; $q = @{ limit = 100 }
    while ($path) {
        $body = Invoke-OktaRequest -Client $Client -Method GET -Path $path -Query $q
        foreach ($u in @($body.value)) { if ($u) { $ids.Add([string]$u.id) } }
        $next = $null
        if ($body._links -and $body._links.next) { $next = $body._links.next.href }
        if (-not $next) { break }
        $uri = [uri]$next; $path = $uri.AbsolutePath; $q = @{}
        foreach ($pair in ($uri.Query.TrimStart('?') -split '&')) { if ($pair) { $kv = $pair -split '=', 2; $q[[uri]::UnescapeDataString($kv[0])] = [uri]::UnescapeDataString($kv[1]) } }
    }
    return , $ids
}

function Get-SlimRole {
    param($R)
    $o = [ordered]@{}
    foreach ($k in 'id', 'type', 'label', 'assignmentType', 'role') { $v = Get-V $R $k; if ($null -ne $v) { $o[$k] = $v } }
    return $o
}

function Invoke-Collect {
    param($Client, $P)
    $log = { param($m) [Console]::Error.WriteLine($m) }
    $snap = [ordered]@{ users = (New-List); groups = (New-List); group_members = [ordered]@{}; group_rules = (New-List); apps = (New-List)
        app_users = [ordered]@{}; app_groups = [ordered]@{}; user_roles = [ordered]@{}; group_roles = [ordered]@{}; factors = [ordered]@{} }
    $entries = Get-PolicyEntries $P
    & $log 'reading users...'
    foreach ($u in (Get-OktaUsers -Client $Client -Status '')) {
        $snap.users.Add([ordered]@{ id = $u.id; status = $u.status; profile = [ordered]@{ login = $u.profile.login; firstName = $u.profile.firstName; lastName = $u.profile.lastName } })
    }
    & $log 'reading groups and group rules...'
    foreach ($g in (Get-OktaGroups -Client $Client)) { $snap.groups.Add([ordered]@{ id = $g.id; type = $g.type; profile = [ordered]@{ name = $(if ($g.profile.name) { $g.profile.name } else { $g.id }) } }) }
    foreach ($r in (Invoke-OktaPagedGet -Client $Client -Path '/api/v1/groups/rules')) {
        $snap.group_rules.Add([ordered]@{ id = $r.id; name = $r.name; status = $r.status; actions = (ConvertTo-Hash $r.actions) })
    }
    $needed = [System.Collections.Generic.HashSet[string]]::new()
    $appValues = @($entries | Where-Object { $_['type'] -eq 'app' } | ForEach-Object { $_['value'] }) + @($entries | Where-Object { $_['type'] -eq 'app_group' } | ForEach-Object { $_['app'] })
    if ($appValues.Count) {
        & $log 'reading apps and their assignments...'
        foreach ($a in (Get-OktaApps -Client $Client)) {
            $ah = [ordered]@{ id = $a.id; name = $a.name; label = $a.label; status = $a.status }
            $snap.apps.Add($ah)
            $hit = $false; foreach ($v in $appValues) { if (Test-AppMatch $ah $v) { $hit = $true } }
            if (-not $hit) { continue }
            $au = New-List
            foreach ($x in (Get-OktaAppUsers -Client $Client -AppId $a.id)) { $au.Add([ordered]@{ id = $x.id; scope = $x.scope }) }
            $snap.app_users[$a.id] = $au
            $ag = New-List
            foreach ($x in (Invoke-OktaPagedGet -Client $Client -Path "/api/v1/apps/$($a.id)/groups")) { $ag.Add([string]$x.id); [void]$needed.Add([string]$x.id) }
            $snap.app_groups[$a.id] = $ag
        }
    }
    foreach ($e in $entries) {
        if ($e['type'] -in 'group', 'app_group') {
            $v = if ($e['type'] -eq 'group') { $e['value'] } else { $e['group'] }
            foreach ($g in $snap.groups) { if (Test-GroupMatch $g $v) { [void]$needed.Add([string]$g['id']) } }
        }
    }
    if (@($entries | Where-Object { $_['type'] -eq 'admin_role' }).Count) {
        & $log 'reading admin role assignments...'
        foreach ($uid in (Get-IamAssigneeIds $Client)) {
            $roles = New-List
            foreach ($r in (Get-OktaUserRoles -Client $Client -UserId $uid)) {
                $at = $r.assignmentType; if (-not $at) { $at = 'USER' }
                if ($at -eq 'USER') { $roles.Add((Get-SlimRole $r)) }
            }
            if ($roles.Count) { $snap.user_roles[$uid] = $roles }
        }
        foreach ($g in $snap.groups) {
            $roles = New-List
            foreach ($r in (Get-OktaGroupRoles -Client $Client -GroupId $g['id'])) { $roles.Add((Get-SlimRole $r)) }
            if ($roles.Count) { $snap.group_roles[$g['id']] = $roles; [void]$needed.Add([string]$g['id']) }
        }
    }
    & $log "reading members of $($needed.Count) relevant groups..."
    $byId = @{}; foreach ($g in $snap.groups) { $byId[[string]$g['id']] = $g }
    foreach ($gid in (Get-SortedStrings $needed)) {
        $g = $byId[$gid]
        if ($g -and $g['type'] -eq 'BUILT_IN' -and (Get-GroupName $g) -ceq 'Everyone') { continue }
        $m = New-List
        foreach ($u in (Invoke-OktaPagedGet -Client $Client -Path "/api/v1/groups/$gid/users")) { $m.Add([string]$u.id) }
        $snap.group_members[$gid] = $m
    }
    if (@($entries | Where-Object { $_['type'] -eq 'no_phishing_resistant_factor' }).Count) {
        $pre = Invoke-Analysis $snap $P
        $cands = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($f in $pre.findings) { [void]$cands.Add($f['user_id']) }
        foreach ($x in $pre.excepted) { foreach ($u in $snap.users) { if ((Get-UserLogin $u) -ceq $x['user']) { [void]$cands.Add([string]$u['id']) } } }
        & $log "reading factors for $($cands.Count) candidate users..."
        foreach ($uid in (Get-SortedStrings $cands)) {
            $fl = New-List
            foreach ($f in (Get-OktaFactors -Client $Client -UserId $uid)) { $fl.Add([ordered]@{ factorType = $f.factorType; provider = $f.provider; status = $f.status }) }
            $snap.factors[$uid] = $fl
        }
    }
    return $snap
}

# ---------------------------------------------------------------- output

function Format-Cell {
    param($Value, [int]$Width)
    $s = [string]$Value
    if ($s.Length -gt $Width) { $s = $s.Substring(0, $Width) }
    return $s.PadRight($Width)
}

function Get-TextReport {
    param($Result, [string]$PolicyName, [int]$NRules)
    $fs = $Result.findings
    $out = New-List
    $out.Add('Toxic access combinations (separation of duties) -- read-only')
    $out.Add("Policy: $PolicyName ($NRules rules) | users scanned: $($Result.users_scanned) | findings: $($fs.Count) | excepted: $($Result.excepted.Count)")
    $out.Add('')
    if (-not $fs.Count) {
        $out.Add('No user holds a toxic combination defined in the policy.')
        return ($out -join "`n") + "`n"
    }
    $out.Add("$(Format-Cell '#' 3) $(Format-Cell 'RISK' 9) $(Format-Cell 'SCORE' 5) $(Format-Cell 'USER' 32) $(Format-Cell 'RULE' 40) SMALLEST FIX")
    $out.Add('-' * 140)
    foreach ($f in $fs) {
        $fix = $f['smallest_fix']
        $first = if ($fix['actions'].Count) { $fix['actions'][0] } else { '' }
        $more = if ($fix['actions'].Count -gt 1) { " (+$($fix['actions'].Count - 1) more)" } else { '' }
        $out.Add("$(Format-Cell $f['rank'] 3) $(Format-Cell $f['risk'] 9) $(Format-Cell $f['score'] 5) $(Format-Cell $f['user'] 32) $(Format-Cell ($f['rule_id'] + ' ' + $f['rule']) 40) $first$more")
    }
    $out.Add(''); $out.Add('Details'); $out.Add('-------')
    foreach ($f in $fs) {
        $out.Add("[$($f['rank'])] $($f['risk']) (score $($f['score']))  $($f['user']) [$($f['status'])]  $($f['rule_id']): $($f['rule'])")
        foreach ($s in $f['sides']) {
            $out.Add("    `"$($s['label'])`":")
            foreach ($it in $s['items']) { foreach ($p in $it['paths']) { $out.Add("      - $($it['item']): $($p['how'])") } }
        }
        $fix = $f['smallest_fix']
        $out.Add("    Smallest fix (breaks `"$($fix['side'])`", $($fix['actions'].Count) change(s)):")
        foreach ($a in $fix['actions']) { $out.Add("      * $a") }
        $out.Add("    In plain English: $($f['explanation'])")
        $out.Add('')
    }
    return ($out -join "`n")
}

$CsvColumns = @('rank', 'risk', 'score', 'user', 'status', 'rule_id', 'rule', 'how_they_got_it', 'smallest_fix', 'fix_changes', 'explanation')

function ConvertTo-CsvLine { param([string[]]$Fields) return (($Fields | ForEach-Object { '"' + ([string]$_).Replace('"', '""') + '"' }) -join ',') }

function Get-CsvReport {
    param($Result)
    $lines = New-List
    $lines.Add((ConvertTo-CsvLine $CsvColumns))
    foreach ($f in $Result.findings) {
        $how = (@($f['sides'] | ForEach-Object {
            $s = $_
            "$($s['label']): " + ((@($s['items'] | ForEach-Object { $it = $_; $it['paths'] | ForEach-Object { "$($it['item']) ($($_['how']))" } })) -join '; ')
        })) -join ' | '
        $lines.Add((ConvertTo-CsvLine @([string]$f['rank'], $f['risk'], [string]$f['score'], $f['user'], $f['status'], $f['rule_id'],
            $f['rule'], $how, ($f['smallest_fix']['actions'] -join ' ; '), [string]$f['smallest_fix']['actions'].Count, $f['explanation'])))
    }
    return ($lines -join "`n") + "`n"
}

function Get-JsonReport {
    param($Result, [string]$PolicyName)
    $byRisk = [ordered]@{}
    foreach ($s in 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW') { $byRisk[$s] = @($Result.findings | Where-Object { $_['risk'] -eq $s }).Count }
    $doc = [ordered]@{
        policy   = $PolicyName
        summary  = [ordered]@{ users_scanned = $Result.users_scanned; findings = $Result.findings.Count; excepted = $Result.excepted.Count; by_risk = $byRisk }
        findings = $Result.findings
        excepted = $Result.excepted
    }
    return ($doc | ConvertTo-Json -Depth 30)
}

# ---------------------------------------------------------------- main

try {
    $policyObj = Get-Content -Raw -LiteralPath $Policy | ConvertFrom-Json -AsHashtable
} catch {
    [Console]::Error.WriteLine("error: $Policy is not valid JSON: $($_.Exception.Message)"); exit 1
}
try { Assert-Policy $policyObj } catch { [Console]::Error.WriteLine("error: $($_.Exception.Message)"); exit 1 }

if ($Snapshot) {
    $snap = Get-Content -Raw -LiteralPath $Snapshot | ConvertFrom-Json -AsHashtable
} else {
    Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
    try {
        $client = New-OktaClient
        $snap = Invoke-Collect $client $policyObj
    } catch {
        [Console]::Error.WriteLine("error: $($_.Exception.Message)"); exit 1
    }
    # Normalize to the same hashtable shapes an offline snapshot has.
    $snap = $snap | ConvertTo-Json -Depth 30 | ConvertFrom-Json -AsHashtable
}
if ($SaveSnapshot) {
    $snap | ConvertTo-Json -Depth 30 | Set-Content -LiteralPath $SaveSnapshot -Encoding utf8NoBOM
    [Console]::Error.WriteLine("wrote snapshot $SaveSnapshot")
}

$result = Invoke-Analysis $snap $policyObj
$policyName = Split-Path -Leaf $Policy
$report = if ($Json) { Get-JsonReport $result $policyName } else { Get-TextReport $result $policyName @($policyObj['rules']).Count }
if (-not $report.EndsWith("`n")) { $report += "`n" }
if ($Output) {
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Output), $report, [System.Text.UTF8Encoding]::new($false))
    [Console]::Error.WriteLine("wrote $Output")
} else {
    [Console]::Out.Write($report)
}
if ($Csv) {
    [System.IO.File]::WriteAllText([System.IO.Path]::GetFullPath($Csv), (Get-CsvReport $result), [System.Text.UTF8Encoding]::new($false))
    [Console]::Error.WriteLine("wrote $Csv")
}

if ($FailOn -ne 'none') {
    $floor = [array]::IndexOf($Severities, $FailOn)
    foreach ($f in $result.findings) { if ([array]::IndexOf($Severities, $f['risk'].ToLowerInvariant()) -ge $floor) { exit 2 } }
}
exit 0
