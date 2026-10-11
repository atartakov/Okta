<#
.SYNOPSIS
    Phishing-resistant MFA enforcement what-if. READ-ONLY.

.DESCRIPTION
    PowerShell port of phishing_resistant_whatif.py; prints the same report.

    Before you require phishing-resistant MFA (passkeys / FIDO2 WebAuthn, Okta
    FastPass with phishing resistance, smart card) for a group or an app, this
    simulates who would be locked out and in what order to roll it out.

    For every user in scope it joins:
      1. what they have enrolled           GET /api/v1/users/{id}/factors
      2. what they actually used, and from System Log user.authentication.auth_via_mfa
         which OS, in the window           and user.authentication.verify events
                                           (Okta marks each method PHISHING_RESISTANT
                                           or not, so this is Okta's own verdict)
      3. the policy rules in their path    app sign-in, global session and
                                           authenticator enrollment policies

    Classes: READY, ENROLLED_NOT_USED, AT_RISK, NO_MFA, plus PLATFORM_BLOCKER
    (phishing-resistant somewhere, but not on every OS they sign in from:
    FastPass doesn't run on Linux or ChromeOS, and it is per device).

    Only GET requests are made. Nothing in Okta is changed.

.PARAMETER Group
    Target group name or id.
.PARAMETER App
    Target app label or id. With -Group, scope is group members assigned the app.
.PARAMETER LookbackDays
    System Log evidence window, 1-90 days (default 30).
.PARAMETER InputFile
    Analyze a saved snapshot instead of calling Okta.
.PARAMETER SaveSnapshot
    Also write the raw data read from Okta (for -InputFile re-runs).
.PARAMETER Json
    Emit JSON instead of text.
.PARAMETER Output
    Write the report to this file.
.PARAMETER FailOnLockout
    Exit 2 if anyone in scope would be locked out.

.EXAMPLE
    pwsh ./phishing_resistant_whatif.ps1 -Group "Engineering"
.EXAMPLE
    pwsh ./phishing_resistant_whatif.ps1 -App "Salesforce" -LookbackDays 60 -Json
.EXAMPLE
    pwsh ./phishing_resistant_whatif.ps1 -InputFile snap.json
#>

param(
    [string]$Group,
    [string]$App,
    [int]$LookbackDays = 30,
    [string]$InputFile,
    [string]$SaveSnapshot,
    [switch]$Json,
    [string]$Output,
    [switch]$FailOnLockout
)

$ErrorActionPreference = 'Stop'

$AuthEvents = @('user.authentication.auth_via_mfa', 'user.authentication.verify')
$SigninStatuses = @('ACTIVE', 'PASSWORD_EXPIRED', 'LOCKED_OUT', 'RECOVERY')
$PrFactorTypes = @('webauthn', 'u2f', 'signed_nonce')
$FastPassOs = @('Windows', 'macOS', 'iOS', 'Android')
$MaxLookback = 90
$Classes = @('READY', 'ENROLLED_NOT_USED', 'AT_RISK', 'NO_MFA')
$ClassHelp = @{
    READY             = 'enrolled in a phishing-resistant authenticator and used it in the window'
    ENROLLED_NOT_USED = 'enrolled, but no phishing-resistant sign-in in the window'
    AT_RISK           = 'only phishable factors (SMS, voice, email, push, TOTP)'
    NO_MFA            = 'no MFA factor enrolled'
    PLATFORM_BLOCKER  = 'phishing-resistant somewhere, but not on every OS they sign in from'
}
$FactorLabels = @{
    'webauthn' = 'passkey'; 'u2f' = 'U2F key'; 'push' = 'push'
    'token:software:totp' = 'TOTP'; 'token:hotp' = 'HOTP'
    'token:hardware' = 'hardware OTP'; 'token' = 'OTP token'; 'sms' = 'SMS'
    'call' = 'voice'; 'email' = 'email'; 'question' = 'security question'; 'web' = 'Duo'
}
$PlatformLabels = @{ ANDROID = 'Android'; IOS = 'iOS'; WINDOWS = 'Windows'; MACOS = 'macOS'; OSX = 'macOS' }

# ---------------------------------------------------------------- helpers

function Get-Prop {
    param($Obj, [string]$Name)
    if ($null -eq $Obj) { return $null }
    if ($Obj -is [System.Collections.IDictionary]) { return $Obj[$Name] }
    $p = $Obj.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

function ConvertTo-UtcDate {
    param($Value)
    if ($Value -is [datetime]) {
        if ($Value.Kind -eq [DateTimeKind]::Local) { return $Value.ToUniversalTime() }
        return [datetime]::SpecifyKind($Value, [DateTimeKind]::Utc)
    }
    if ($Value -is [datetimeoffset]) { return $Value.UtcDateTime }
    return [datetimeoffset]::Parse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
        [Globalization.DateTimeStyles]::AssumeUniversal).UtcDateTime
}

function ConvertTo-OrdinalSorted {
    param([object[]]$Items)
    $arr = [string[]]@($Items | Where-Object { $null -ne $_ } | ForEach-Object { [string]$_ })
    [Array]::Sort($arr, [StringComparer]::Ordinal)
    return $arr
}

function Get-SortedUnique {
    param([object[]]$Items)
    $set = [Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach ($i in $Items) { if ($null -ne $i) { [void]$set.Add([string]$i) } }
    return ConvertTo-OrdinalSorted @($set)
}

function Format-Pad {
    param($Value, [int]$Width)
    $s = [string]$Value
    if ($s.Length -gt $Width) { $s = $s.Substring(0, $Width) }
    return $s.PadRight($Width)
}

function Get-NormOs {
    param($Value)
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if (-not $s -or $s -eq 'unknown') { return $null }
    if ($s.Contains('windows')) { return 'Windows' }
    if ($s.Contains('android')) { return 'Android' }
    if ($s.Contains('chrome os') -or $s.Contains('chromeos') -or $s.Contains('cros')) { return 'ChromeOS' }
    if ($s.Contains('mac') -or $s.Contains('os x')) { return 'macOS' }
    if ($s.Contains('ios') -or $s.Contains('iphone') -or $s.Contains('ipad')) { return 'iOS' }
    foreach ($k in 'linux', 'ubuntu', 'fedora', 'debian') { if ($s.Contains($k)) { return 'Linux' } }
    return ([string]$Value).Trim()
}

function Get-NormMethod {
    param($Value)
    $s = ([string]$Value).Trim().ToLowerInvariant()
    if (-not $s -or $s.Contains('password')) { return $null }
    if ($s.Contains('fastpass') -or $s.Contains('signed_nonce')) { return 'fastpass' }
    foreach ($k in 'webauthn', 'passkey', 'fido', 'security key', 'security_key', 'u2f') { if ($s.Contains($k)) { return 'passkey' } }
    foreach ($k in 'smart', 'piv', 'x509', 'cert') { if ($s.Contains($k)) { return 'smart card' } }
    if ($s.Contains('push')) { return 'push' }
    if ($s.Contains('sms')) { return 'sms' }
    if ($s.Contains('voice') -or $s.Contains('call')) { return 'voice' }
    if ($s.Contains('email')) { return 'email' }
    foreach ($k in 'otp', 'code', 'soft_token', 'google') { if ($s.Contains($k)) { return 'totp' } }
    if ($s.Contains('question')) { return 'security question' }
    return $s
}

function Get-FactorLabel {
    param($Factor)
    $t = [string](Get-Prop $Factor 'factorType'); if (-not $t) { $t = '?' }
    if ($t -eq 'signed_nonce') {
        $plat = ([string](Get-Prop $Factor 'platform')).ToUpperInvariant()
        $label = $PlatformLabels[$plat]
        if (-not $label) {
            $label = (Get-Culture).TextInfo.ToTitleCase($plat.ToLowerInvariant())
            if (-not $label) { $label = '?' }
        }
        return "FastPass ($label)"
    }
    if ($FactorLabels.ContainsKey($t)) { return $FactorLabels[$t] }
    return $t
}

function Get-PeopleScope {
    # Returns @(applies, label): how a policy/rule's people condition relates to the target group.
    param($Conditions, $GroupId, $EveryoneId)
    $people = Get-Prop $Conditions 'people'
    $groups = Get-Prop $people 'groups'
    $users = Get-Prop $people 'users'
    $inc = @(Get-Prop $groups 'include' | Where-Object { $_ })
    $exc = @(Get-Prop $groups 'exclude' | Where-Object { $_ })
    $uinc = @(Get-Prop $users 'include' | Where-Object { $_ })
    if ($GroupId -and $exc -contains $GroupId) { return @($false, 'excludes this group') }
    if ($inc.Count) {
        if ($GroupId -and $inc -contains $GroupId) { return @($true, 'this group') }
        if ($EveryoneId -and $inc -contains $EveryoneId) { return @($true, 'everyone') }
        if ($GroupId) { return @($false, 'other groups') }
        return @($true, "only $($inc.Count) group(s)")
    }
    if ($uinc.Count) { return @($true, "only $($uinc.Count) named user(s)") }
    return @($true, 'everyone')
}

function Get-RuleConditions {
    param($Conditions)
    $out = @()
    $net = Get-Prop $Conditions 'network'
    $conn = Get-Prop $net 'connection'
    if ($conn -and $conn -ne 'ANYWHERE') { $out += 'network zone' }
    if (Get-Prop $Conditions 'device') { $out += 'device' }
    if (Get-Prop $Conditions 'platform') { $out += 'platform' }
    $risk = Get-Prop $Conditions 'riskScore'; if (-not $risk) { $risk = Get-Prop $Conditions 'risk' }
    $lvl = Get-Prop $risk 'level'
    if ($lvl -and $lvl -ne 'ANY') { $out += 'risk' }
    if (Get-Prop $Conditions 'elCondition') { $out += 'expression' }
    $ut = Get-Prop $Conditions 'userType'
    if (@(Get-Prop $ut 'include' | Where-Object { $_ }).Count -or @(Get-Prop $ut 'exclude' | Where-Object { $_ }).Count) { $out += 'user type' }
    return , $out
}

function Get-PrRequirement {
    param($Rule)
    $signOn = Get-Prop (Get-Prop $Rule 'actions') 'appSignOn'
    $vm = Get-Prop $signOn 'verificationMethod'
    if ((Get-Prop $vm 'type') -eq 'AUTH_METHOD_CHAIN') {
        $chains = Get-Prop $vm 'chains'
        $txt = if ($null -ne $chains) { ConvertTo-Json -InputObject $chains -Depth 30 -Compress } else { '[]' }
        if ($txt -match '"phishingResistant"\s*:\s*"REQUIRED"') { return 'auth method chain with phishing resistance on some steps' }
        return 'auth method chain (check its steps by hand)'
    }
    $req = @(foreach ($c in @(Get-Prop $vm 'constraints')) {
            if ($null -eq $c) { continue }
            (Get-Prop (Get-Prop $c 'possession') 'phishingResistant') -eq 'REQUIRED'
        })
    if ($req.Count -and -not ($req -contains $false)) { return 'phishing resistance REQUIRED' }
    if ($req -contains $true) { return 'phishing resistance required on some paths only' }
    return 'phishing resistance NOT required'
}

function Get-EnrollSetting {
    param($Policy, [string]$Key)
    $settings = Get-Prop $Policy 'settings'
    $aliases = if ($Key -eq 'webauthn') { @('webauthn', 'fido_webauthn') } else { @('okta_verify', 'okta_push') }
    foreach ($a in @(Get-Prop $settings 'authenticators')) {
        if ($null -ne $a -and $aliases -contains (Get-Prop $a 'key')) {
            $v = Get-Prop (Get-Prop $a 'enroll') 'self'
            if ($v) { return $v } else { return 'NOT_ALLOWED' }
        }
    }
    $factors = Get-Prop $settings 'factors'
    foreach ($k in $aliases) {
        $f = Get-Prop $factors $k
        if ($null -ne $f) {
            $v = Get-Prop (Get-Prop $f 'enroll') 'self'
            if ($v) { return $v } else { return 'NOT_ALLOWED' }
        }
    }
    return 'NOT_ALLOWED'
}

function ConvertTo-PrioritySorted {
    param([object[]]$Items)
    $list = [Collections.Generic.List[object]]::new()
    foreach ($i in $Items) { if ($null -ne $i) { $list.Add($i) } }
    $list.Sort([Comparison[object]] {
            param($a, $b)
            $pa = [int](Get-Prop $a 'priority'); $pb = [int](Get-Prop $b 'priority')
            if ($pa -ne $pb) { return $pa.CompareTo($pb) }
            return [string]::CompareOrdinal([string](Get-Prop $a 'name'), [string](Get-Prop $b 'name'))
        })
    return , $list.ToArray()
}

# ---------------------------------------------------------------- analysis

function Get-EventMethods {
    param($LogEvent)
    $out = @()
    foreach ($m in @(Get-Prop $LogEvent 'methods')) {
        if ($null -eq $m) { continue }
        $name = Get-NormMethod (Get-Prop $m 'method')
        if (-not $name) {
            $key = [string](Get-Prop $m 'key')
            if (-not $key.Contains('password')) { $name = Get-NormMethod $key }
        }
        if (-not $name) { continue }
        $props = ([string](Get-Prop $m 'props')).ToUpperInvariant()
        $out += , @($name, ($props.Contains('PHISHING_RESISTANT') -or $name -in @('passkey', 'smart card')))
    }
    if (-not $out.Count) {
        $name = Get-NormMethod (Get-Prop $LogEvent 'factor')
        if ($name) { $out += , @($name, ($name -in @('passkey', 'smart card'))) }
    }
    return , $out
}

function Get-UserVerdict {
    param($User, [object[]]$Events)
    $factors = @(Get-Prop $User 'factors' | Where-Object { $_ -and (Get-Prop $_ 'status') -eq 'ACTIVE' })
    $types = @($factors | ForEach-Object { Get-Prop $_ 'factorType' })
    $fpOs = @($factors | Where-Object { (Get-Prop $_ 'factorType') -eq 'signed_nonce' } | ForEach-Object {
            $PlatformLabels[([string](Get-Prop $_ 'platform')).ToUpperInvariant()] } | Where-Object { $_ })
    $hasKey = ($types -contains 'webauthn') -or ($types -contains 'u2f')
    $hasPr = @($types | Where-Object { $PrFactorTypes -contains $_ }).Count -gt 0

    $osSeen = @(); $prOs = @(); $used = @(); $lastPr = $null; $lastSeen = $null; $fpNotPr = $false
    foreach ($ev in $Events) {
        $os = Get-NormOs (Get-Prop $ev 'os')
        $when = ConvertTo-UtcDate (Get-Prop $ev 'published')
        if ($null -eq $lastSeen -or $when -gt $lastSeen) { $lastSeen = $when }
        if ($os) { $osSeen += $os }
        foreach ($pair in (Get-EventMethods $ev)) {
            $used += $pair[0]
            if ($pair[1]) {
                if ($null -eq $lastPr -or $when -gt $lastPr) { $lastPr = $when }
                if ($os) { $prOs += $os }
            }
            elseif ($pair[0] -eq 'fastpass') { $fpNotPr = $true }
        }
    }
    $osSeen = @(Get-SortedUnique $osSeen)

    if ($lastPr) { $cls = 'READY' }
    elseif ($hasPr) { $cls = 'ENROLLED_NOT_USED' }
    elseif ($factors.Count) { $cls = 'AT_RISK' }
    else { $cls = 'NO_MFA' }

    $uncovered = @(ConvertTo-OrdinalSorted @($osSeen | Where-Object { -not ($hasKey -or $fpOs -contains $_ -or $prOs -contains $_) }))
    $platformBlocker = ($cls -in @('READY', 'ENROLLED_NOT_USED')) -and $uncovered.Count -gt 0

    $notes = @()
    if ($cls -in @('NO_MFA', 'AT_RISK')) {
        $noFp = @($osSeen | Where-Object { $FastPassOs -notcontains $_ })
        if ($noFp.Count) { $notes += "enroll a passkey/security key (FastPass doesn't run on $($noFp -join ', '))" }
        else { $notes += 'enroll Okta Verify with FastPass, or a passkey' }
    }
    if ($platformBlocker) {
        foreach ($o in $uncovered) {
            if ($FastPassOs -contains $o) { $notes += "${o}: no FastPass there; set it up or add a passkey" }
            else { $notes += "${o}: FastPass unsupported; add a passkey/security key" }
        }
    }
    if ($cls -eq 'ENROLLED_NOT_USED') {
        if ($fpNotPr) { $notes += 'FastPass used, but never phishing-resistant (Okta Verify app or unsupported browser)' }
        else { $notes += 'ask them to sign in once with it to prove it works' }
    }
    if ($null -eq $lastSeen) { $notes += 'no sign-ins in window' }

    $login = Get-Prop $User 'login'; if (-not $login) { $login = Get-Prop $User 'id' }
    return [ordered]@{
        login                       = $login
        id                          = Get-Prop $User 'id'
        class                       = $cls
        platform_blocker            = [bool]$platformBlocker
        enrolled                    = @(Get-SortedUnique @($factors | ForEach-Object { Get-FactorLabel $_ }))
        methods_used                = @(Get-SortedUnique $used)
        os_seen                     = @($osSeen)
        os_uncovered                = @($uncovered)
        last_phishing_resistant_use = if ($lastPr) { $lastPr.ToString('yyyy-MM-dd') } else { $null }
        last_sign_in                = if ($lastSeen) { $lastSeen.ToString('yyyy-MM-dd') } else { $null }
        fix                         = $notes -join '; '
    }
}

function Get-TenantChecks {
    param($Snap, $GroupId, $EveryoneId, [int]$NeedPasskey = 0)
    $auths = @{}
    foreach ($a in @(Get-Prop $Snap 'authenticators')) { if ($a) { $auths[[string](Get-Prop $a 'key')] = $a } }
    $checks = [Collections.Generic.List[object]]::new()
    $wa = $auths['webauthn']
    $waOn = $null -ne $wa -and (Get-Prop $wa 'status') -eq 'ACTIVE'
    $ov = $auths['okta_verify']
    $fpOn = $null -ne $ov -and (Get-Prop $ov 'status') -eq 'ACTIVE' -and
    @(Get-Prop $ov 'methods' | Where-Object { $_ -and (Get-Prop $_ 'type') -eq 'signed_nonce' -and (Get-Prop $_ 'status') -eq 'ACTIVE' }).Count -gt 0
    $sc = $auths['smart_card_idp']
    $scOn = $null -ne $sc -and (Get-Prop $sc 'status') -eq 'ACTIVE'
    if (-not ($waOn -or $fpOn -or $scOn)) {
        $checks.Add(@('BLOCKER', 'No phishing-resistant authenticator is active in this tenant: enforcing now would lock out everyone in scope.'))
    }
    if ($waOn) { $checks.Add(@('OK', 'Passkey/security key (WebAuthn) authenticator is ACTIVE.')) }
    else {
        $state = if ($wa) { Get-Prop $wa 'status' } else { 'not set up' }
        $who = if ($NeedPasskey) { "$NeedPasskey user(s) in scope who sign in from an OS without FastPass" } else { "users who can't use FastPass (Linux, ChromeOS, no Okta Verify)" }
        $lvl = if ($NeedPasskey -or -not $fpOn) { 'BLOCKER' } else { 'WARN' }
        $checks.Add(@($lvl, "Passkey/security key (WebAuthn) authenticator is ${state}, so $who have no phishing-resistant option until it is activated."))
    }
    if ($fpOn) { $checks.Add(@('OK', 'Okta Verify FastPass is ACTIVE.')) }
    else { $checks.Add(@('WARN', 'Okta Verify FastPass is not active.')) }
    if ($scOn) {
        $checks.Add(@('OK', "Smart card (PIV) authenticator is ACTIVE. Smart card enrollment isn't visible in the factors API; it counts only from sign-in evidence."))
    }

    $enroll = $null
    foreach ($p in (ConvertTo-PrioritySorted @(Get-Prop $Snap 'enroll_policies' | Where-Object { $_ -and (Get-Prop $_ 'status') -eq 'ACTIVE' }))) {
        $scope = Get-PeopleScope -Conditions (Get-Prop $p 'conditions') -GroupId $GroupId -EveryoneId $EveryoneId
        if ($scope[0] -and $scope[1] -in @('this group', 'everyone')) { $enroll = $p; break }
    }
    if ($null -eq $enroll) { $checks.Add(@('WARN', 'No active authenticator enrollment policy covers this target.')) }
    else {
        $w = Get-EnrollSetting $enroll 'webauthn'
        $o = Get-EnrollSetting $enroll 'okta_verify'
        $where = "Enrollment policy `"$(Get-Prop $enroll 'name')`""
        if ($w -eq 'NOT_ALLOWED' -and $o -eq 'NOT_ALLOWED') { $checks.Add(@('BLOCKER', "$where lets these users enroll neither FastPass nor a passkey.")) }
        elseif ($w -eq 'NOT_ALLOWED') { $checks.Add(@('WARN', "$where doesn't offer passkey/security key enrollment (Okta Verify: $o): users without FastPass can't self-enroll.")) }
        elseif ($o -eq 'NOT_ALLOWED') { $checks.Add(@('WARN', "$where doesn't offer Okta Verify enrollment (passkey: $w): FastPass isn't self-service.")) }
        else { $checks.Add(@('OK', "$where offers passkey ($w) and Okta Verify ($o).")) }
    }
    return , $checks.ToArray()
}

function Get-PolicyPath {
    param($Snap, $GroupId, $EveryoneId)
    $appSignIn = @()
    foreach ($pol in @(Get-Prop $Snap 'access_policies')) {
        if ($null -eq $pol) { continue }
        $rows = @(); $matched = $false
        foreach ($r in (ConvertTo-PrioritySorted @(Get-Prop $pol 'rules' | Where-Object { $_ -and (Get-Prop $_ 'status') -eq 'ACTIVE' }))) {
            $scope = Get-PeopleScope -Conditions (Get-Prop $r 'conditions') -GroupId $GroupId -EveryoneId $EveryoneId
            if (-not $scope[0]) { continue }
            $who = $scope[1]
            $conds = Get-RuleConditions (Get-Prop $r 'conditions')
            $signOn = Get-Prop (Get-Prop $r 'actions') 'appSignOn'
            $vm = Get-Prop $signOn 'verificationMethod'
            $first = (-not $matched) -and $conds.Count -eq 0 -and -not $who.StartsWith('only')
            $matched = $matched -or $first
            $access = Get-Prop $signOn 'access'; if (-not $access) { $access = 'ALLOW' }
            $fm = Get-Prop $vm 'factorMode'; if (-not $fm) { $fm = '?' }
            $rows += [ordered]@{
                priority                  = [int](Get-Prop $r 'priority')
                name                      = Get-Prop $r 'name'
                applies_to                = $who
                only_when                 = @($conds)
                access                    = $access
                factor_mode               = $fm
                phishing_resistance       = Get-PrRequirement $r
                first_unconditional_match = [bool]$first
            }
        }
        $appSignIn += [ordered]@{
            policy = Get-Prop $pol 'name'; id = Get-Prop $pol 'id'
            apps = @(ConvertTo-OrdinalSorted @(Get-Prop $pol 'apps')); rules = @($rows)
        }
    }
    $gsp = $null
    foreach ($pol in (ConvertTo-PrioritySorted @(Get-Prop $Snap 'sign_on_policies' | Where-Object { $_ -and (Get-Prop $_ 'status') -eq 'ACTIVE' }))) {
        $scope = Get-PeopleScope -Conditions (Get-Prop $pol 'conditions') -GroupId $GroupId -EveryoneId $EveryoneId
        if (-not $scope[0] -or $scope[1] -notin @('this group', 'everyone')) { continue }
        foreach ($r in (ConvertTo-PrioritySorted @(Get-Prop $pol 'rules' | Where-Object { $_ -and (Get-Prop $_ 'status') -eq 'ACTIVE' }))) {
            $rs = Get-PeopleScope -Conditions (Get-Prop $r 'conditions') -GroupId $GroupId -EveryoneId $EveryoneId
            if (-not $rs[0] -or (Get-RuleConditions (Get-Prop $r 'conditions')).Count -or $rs[1].StartsWith('only')) { continue }
            $so = Get-Prop (Get-Prop $r 'actions') 'signon'
            $acc = Get-Prop $so 'access'; if (-not $acc) { $acc = 'ALLOW' }
            $pf = Get-Prop $so 'primaryFactor'; if (-not $pf) { $pf = '?' }
            $gsp = [ordered]@{
                policy = Get-Prop $pol 'name'; rule = Get-Prop $r 'name'; access = $acc
                require_factor = [bool](Get-Prop $so 'requireFactor'); primary_factor = $pf
            }
            break
        }
        break
    }
    return [ordered]@{ app_sign_in = @($appSignIn); global_session = $gsp }
}

function Invoke-Analysis {
    param($Snap)
    $now = ConvertTo-UtcDate (Get-Prop $Snap 'collected_at')
    $lookback = [int](Get-Prop $Snap 'lookback_days'); if (-not $lookback) { $lookback = 30 }
    $cutoff = $now.AddDays(-$lookback)
    $target = Get-Prop $Snap 'target'
    $grp = Get-Prop $target 'group'
    $groupId = if ($grp) { Get-Prop $grp 'id' } else { $null }
    $everyoneId = Get-Prop $Snap 'everyone_group_id'

    $byActor = @{}
    foreach ($ev in @(Get-Prop $Snap 'events')) {
        if ($null -eq $ev) { continue }
        if ($AuthEvents -notcontains (Get-Prop $ev 'eventType') -or (Get-Prop $ev 'result') -ne 'SUCCESS') { continue }
        if ((ConvertTo-UtcDate (Get-Prop $ev 'published')) -lt $cutoff) { continue }
        $aid = [string](Get-Prop $ev 'actor_id')
        if (-not $byActor.ContainsKey($aid)) { $byActor[$aid] = [Collections.Generic.List[object]]::new() }
        $byActor[$aid].Add($ev)
    }

    $users = [Collections.Generic.List[object]]::new(); $skipped = @{}
    foreach ($u in @(Get-Prop $Snap 'users')) {
        if ($null -eq $u) { continue }
        $st = [string](Get-Prop $u 'status')
        if ($SigninStatuses -notcontains $st) {
            if (-not $st) { $st = '?' }
            $skipped[$st] = 1 + [int]$skipped[$st]; continue
        }
        $evs = if ($byActor.ContainsKey([string](Get-Prop $u 'id'))) { $byActor[[string](Get-Prop $u 'id')].ToArray() } else { @() }
        $users.Add((Get-UserVerdict $u $evs))
    }
    $users.Sort([Comparison[object]] { param($a, $b) [string]::CompareOrdinal(([string]$a.login).ToLowerInvariant(), ([string]$b.login).ToLowerInvariant()) })
    $users = $users.ToArray()

    $counts = [ordered]@{}
    foreach ($c in $Classes) { $counts[$c] = @($users | Where-Object { $_.class -eq $c }).Count }
    $counts['PLATFORM_BLOCKER'] = @($users | Where-Object { $_.platform_blocker }).Count
    $rank = @{ NO_MFA = 0; AT_RISK = 1; ENROLLED_NOT_USED = 2; READY = 3 }
    $lockList = [Collections.Generic.List[object]]::new()
    foreach ($r in $users) { if ($r.class -in @('NO_MFA', 'AT_RISK') -or $r.platform_blocker) { $lockList.Add($r) } }
    $lockList.Sort([Comparison[object]] {
            param($a, $b)
            $d = $rank[$a.class].CompareTo($rank[$b.class])
            if ($d) { return $d }
            return [string]::CompareOrdinal(([string]$a.login).ToLowerInvariant(), ([string]$b.login).ToLowerInvariant())
        })
    $lockout = $lockList.ToArray()
    $waves = [ordered]@{
        wave1_enforce_now  = @($users | Where-Object { $_.class -eq 'READY' -and -not $_.platform_blocker } | ForEach-Object { $_.login })
        wave2_nudge        = @($users | Where-Object { $_.class -eq 'ENROLLED_NOT_USED' -and -not $_.platform_blocker } | ForEach-Object { $_.login })
        wave3_enroll_first = @($users | Where-Object { $_.class -eq 'AT_RISK' } | ForEach-Object { $_.login })
        hold               = @($users | Where-Object { $_.class -eq 'NO_MFA' -or $_.platform_blocker } | ForEach-Object { $_.login })
    }
    $skippedSorted = [ordered]@{}
    foreach ($k in (ConvertTo-OrdinalSorted @($skipped.Keys))) { $skippedSorted[$k] = $skipped[$k] }
    $needPasskey = @($users | Where-Object { ($_.class -ne 'READY' -or $_.platform_blocker) -and @($_.os_seen | Where-Object { $FastPassOs -notcontains $_ }).Count }).Count

    return [ordered]@{
        target             = $target
        collected_at       = $now.ToString('yyyy-MM-dd')
        lookback_days      = $lookback
        users_in_scope     = $users.Count
        skipped_not_active = $skippedSorted
        summary            = $counts
        would_lock_out     = $lockout.Count
        tenant_checks      = Get-TenantChecks -Snap $Snap -GroupId $groupId -EveryoneId $everyoneId -NeedPasskey $needPasskey
        policies           = Get-PolicyPath -Snap $Snap -GroupId $groupId -EveryoneId $everyoneId
        lockout            = @($lockout)
        waves              = $waves
        users              = @($users)
    }
}

# ---------------------------------------------------------------- output

function Get-TargetLabel {
    param($Target)
    $g = Get-Prop $Target 'group'; $a = Get-Prop $Target 'app'
    $parts = @()
    if ($g) { $parts += "group `"$(Get-Prop $g 'name')`" ($(Get-Prop $g 'id'))" }
    if ($a) { $parts += "app `"$(Get-Prop $a 'label')`" ($(Get-Prop $a 'id'))" }
    if ($parts.Count) { return $parts -join ' on ' }
    return '?'
}

function Format-Report {
    param($Res)
    $n = $Res.users_in_scope; $lock = $Res.would_lock_out; $s = $Res.summary
    $skipTxt = ''
    if ($Res.skipped_not_active.Count) {
        $skipTxt = " (skipped, can't sign in: " + (@($Res.skipped_not_active.Keys | ForEach-Object { "$($Res.skipped_not_active[$_]) $_" }) -join ', ') + ')'
    }
    $L = @('Phishing-resistant MFA enforcement what-if (read-only; nothing in Okta was changed)',
        "Target:   $(Get-TargetLabel $Res.target)",
        "Evidence: System Log sign-ins over the last $($Res.lookback_days) days (through $($Res.collected_at) UTC)",
        "Scope:    $n user(s) who can sign in$skipTxt", '')
    if ($n -eq 0) { $L += 'VERDICT: nobody in scope can sign in, so nobody would be locked out.' }
    else {
        $pct = [Math]::Floor((200 * $lock + $n) / (2 * $n))
        $L += "VERDICT: enforcing phishing-resistant MFA for this target today would lock out $lock of $n user(s) ($pct%)."
        if ($s['ENROLLED_NOT_USED']) {
            $L += "         $($s['ENROLLED_NOT_USED']) more are enrolled but haven't used it in the window (unproven)."
        }
    }
    $L += @('', 'SUMMARY')
    foreach ($c in ($Classes + 'PLATFORM_BLOCKER')) {
        $L += ('  {0} {1,3}  {2}' -f (Format-Pad $c 18), $s[$c], $ClassHelp[$c])
    }
    $L += @('', 'TENANT READINESS')
    foreach ($chk in $Res.tenant_checks) { $L += "  $(Format-Pad $chk[0] 8) $($chk[1])" }

    $L += @('', 'POLICY RULES IN THE PATH (read with GET only)')
    $pols = $Res.policies
    if (-not $pols.app_sign_in.Count) { $L += '  No app sign-in policy in scope (pass --app, or assign apps to the group).' }
    foreach ($p in $pols.app_sign_in) {
        $apps = if ($p.apps.Count) { $p.apps -join ', ' } else { '-' }
        $L += "  App sign-in policy `"$($p.policy)`" (apps: $apps)"
        if (-not $p.rules.Count) { $L += '    no active rule applies to this target' }
        foreach ($r in $p.rules) {
            $when = if ($r.only_when.Count) { "only when: $($r.only_when -join ', '); " } else { '' }
            $what = if ($r.access -eq 'DENY') { 'denies access' } else { "$($r.factor_mode); $($r.phishing_resistance)" }
            $mark = ''
            if ($r.first_unconditional_match) {
                $mark = if ($r.phishing_resistance -eq 'phishing resistance REQUIRED') {
                    '  <- first unconditional match: ALREADY enforces it (the lockout list is who it blocks today)'
                } else { "  <- first unconditional match: the rule you'd tighten" }
            }
            $L += "    priority $(Format-Pad $r.priority 3) `"$($r.name)`": applies to $($r.applies_to); $when$what$mark"
        }
    }
    $g = $pols.global_session
    if ($g) {
        $mfa = if ($g.require_factor) { 'MFA required' } else { 'no MFA at session level' }
        $pw = if ($g.primary_factor -eq 'PASSWORD_IDP_ANY_FACTOR') { ' (passwordless allowed)' } else { '' }
        $L += "  Global session policy `"$($g.policy)`" rule `"$($g.rule)`": $mfa; primary factor $($g.primary_factor)$pw"
    }

    $L += @('', "WOULD BE LOCKED OUT ($lock)")
    if (-not $Res.lockout.Count) { $L += '  nobody' }
    else {
        $L += "  $(Format-Pad 'LOGIN' 34) $(Format-Pad 'CLASS' 18) $(Format-Pad 'ENROLLED' 28) $(Format-Pad 'LAST PR USE' 11) $(Format-Pad 'SIGN-IN OS' 18) FIX"
        foreach ($r in $Res.lockout) {
            $cls = $r.class + $(if ($r.platform_blocker) { '+PLATFORM' } else { '' })
            $enr = if ($r.enrolled.Count) { $r.enrolled -join ', ' } else { '-' }
            $lpr = if ($r.last_phishing_resistant_use) { $r.last_phishing_resistant_use } else { 'never' }
            $os = if ($r.os_seen.Count) { $r.os_seen -join ', ' } else { '-' }
            $L += "  $(Format-Pad $r.login 34) $(Format-Pad $cls 18) $(Format-Pad $enr 28) $(Format-Pad $lpr 11) $(Format-Pad $os 18) $($r.fix)"
        }
    }

    $w = $Res.waves
    $L += @('', 'SUGGESTED ROLLOUT ORDER')
    foreach ($pair in @(@('wave1_enforce_now', 'Wave 1  enforce now'), @('wave2_nudge', 'Wave 2  nudge (enrolled, unproven)'),
            @('wave3_enroll_first', 'Wave 3  enroll first, then enforce'), @('hold', 'Hold    fix before enforcing'))) {
        $list = @($w[$pair[0]])
        $names = if ($list.Count) { $list -join ', ' } else { '-' }
        $L += "  $($pair[1]) ($($list.Count)): $names"
    }

    $L += @('', 'NEXT STEP')
    if (@($Res.tenant_checks | Where-Object { $_[0] -eq 'BLOCKER' }).Count) {
        $L += '  Clear the tenant BLOCKER(s) above first; until then the users in Wave 3 and Hold have no path to comply.'
    }
    $marked = @($pols.app_sign_in | ForEach-Object { $_.rules } | Where-Object { $_.first_unconditional_match }).Count -gt 0
    if (@($w['wave1_enforce_now']).Count) {
        $where = if ($marked) { 'above the rule marked <-' } else { 'in the app sign-in policy' }
        $L += "  Start with Wave 1 only: put those users in a pilot group and add a phishing-resistant rule for it $where."
    }
    else { $L += '  Nobody is ready yet: get users enrolled (Wave 3 / Hold) before any enforcement.' }
    $L += "  Re-run this after each wave; it only reads."
    return ($L -join "`n") + "`n"
}

# ---------------------------------------------------------------- collection (GET only)

function ConvertTo-TrimmedEvent {
    param($LogEvent)
    $methods = @()
    foreach ($t in @(Get-Prop $LogEvent 'target')) {
        if ($null -eq $t) { continue }
        $de = Get-Prop $t 'detailEntry'
        $mtu = Get-Prop $de 'methodTypeUsed'
        if ((Get-Prop $t 'type') -in @('AuthenticatorEnrollment', 'AuthenticatorMethod') -or $mtu) {
            $m = if ($mtu) { $mtu } else { Get-Prop $t 'displayName' }
            $pr = Get-Prop $de 'methodUsedVerifiedProperties'; if (-not $pr) { $pr = '' }
            $k = Get-Prop $de 'authenticatorKey'; if (-not $k) { $k = '' }
            $methods += [ordered]@{ method = $m; props = $pr; key = $k }
        }
    }
    $pub = Get-Prop $LogEvent 'published'
    if ($pub -is [datetime]) { $pub = (ConvertTo-UtcDate $pub).ToString('yyyy-MM-ddTHH:mm:ss.fffZ') }
    return [ordered]@{
        published = $pub
        eventType = Get-Prop $LogEvent 'eventType'
        actor_id  = Get-Prop (Get-Prop $LogEvent 'actor') 'id'
        result    = Get-Prop (Get-Prop $LogEvent 'outcome') 'result'
        os        = Get-Prop (Get-Prop (Get-Prop $LogEvent 'client') 'userAgent') 'os'
        factor    = Get-Prop (Get-Prop (Get-Prop $LogEvent 'debugContext') 'debugData') 'factor'
        methods   = @($methods)
    }
}

function Invoke-Collect {
    param($Client, [string]$GroupArg, [string]$AppArg, [int]$Lookback)
    $now = [datetime]::SpecifyKind([datetime]::UtcNow, [DateTimeKind]::Utc)
    $now = $now.AddTicks(-($now.Ticks % [TimeSpan]::TicksPerSecond))
    $target = [ordered]@{ group = $null; app = $null }
    $grp = $null; $theApp = $null
    if ($GroupArg) {
        if ($GroupArg -cmatch '^00g[A-Za-z0-9]{17}$') { $grp = Invoke-OktaRequest -Client $Client -Method GET -Path "/api/v1/groups/$GroupArg" }
        else {
            $hits = @(Get-OktaGroups -Client $Client -Query $GroupArg | Where-Object { ([string]$_.profile.name).ToLowerInvariant() -eq $GroupArg.ToLowerInvariant() })
            if ($hits.Count -ne 1) { throw "--group '$GroupArg': $($hits.Count) groups have that exact name; pass the group id instead" }
            $grp = $hits[0]
        }
        $target.group = [ordered]@{ id = $grp.id; name = $grp.profile.name }
    }
    if ($AppArg) {
        if ($AppArg -cmatch '^0oa[A-Za-z0-9]{17}$') { $theApp = Invoke-OktaRequest -Client $Client -Method GET -Path "/api/v1/apps/$AppArg" }
        else {
            $cands = @(Invoke-OktaPagedGet -Client $Client -Path '/api/v1/apps' -Query @{ q = $AppArg })
            $hits = @($cands | Where-Object { ([string]$_.label).ToLowerInvariant() -eq $AppArg.ToLowerInvariant() })
            if (-not $hits.Count) { $hits = @($cands | Where-Object { ([string]$_.name).ToLowerInvariant() -eq $AppArg.ToLowerInvariant() }) }
            if ($hits.Count -ne 1) { throw "--app '$AppArg': $($hits.Count) apps have that exact label; pass the app id instead" }
            $theApp = $hits[0]
        }
        $target.app = [ordered]@{ id = $theApp.id; label = $theApp.label }
    }
    $everyoneId = $null
    foreach ($g in @(Get-OktaGroups -Client $Client -Query 'Everyone')) {
        if ($g.type -eq 'BUILT_IN' -and $g.profile.name -eq 'Everyone') { $everyoneId = $g.id }
    }

    [Console]::Error.WriteLine('... reading users in scope')
    $members = [ordered]@{}
    if ($grp) { foreach ($u in @(Invoke-OktaPagedGet -Client $Client -Path "/api/v1/groups/$($grp.id)/users")) { $members[$u.id] = $u } }
    if ($theApp) {
        $appIds = @(Invoke-OktaPagedGet -Client $Client -Path "/api/v1/apps/$($theApp.id)/users" | ForEach-Object { $_.id })
        if ($grp) {
            $m2 = [ordered]@{}
            foreach ($i in $appIds) { if ($members.Contains($i)) { $m2[$i] = $members[$i] } }
            $members = $m2
        }
        else { foreach ($i in $appIds) { $members[$i] = Invoke-OktaRequest -Client $Client -Method GET -Path "/api/v1/users/$i" } }
    }
    $users = @(); $n = 0
    foreach ($u in $members.Values) {
        $n++
        $factors = if ($SigninStatuses -contains $u.status) { @(Get-OktaFactors -Client $Client -UserId $u.id) } else { @() }
        $users += [ordered]@{
            id = $u.id; status = $u.status; login = $u.profile.login
            factors = @($factors | ForEach-Object { [ordered]@{ factorType = $_.factorType; status = $_.status; provider = $_.provider; platform = (Get-Prop $_.profile 'platform') } })
        }
        if ($n % 50 -eq 0) { [Console]::Error.WriteLine("... read factors for $n users") }
    }

    [Console]::Error.WriteLine('... reading System Log sign-in evidence')
    $ids = @($users | ForEach-Object { $_.id })
    $filter = ($AuthEvents | ForEach-Object { "eventType eq `"$_`"" }) -join ' or '
    $q = @{ filter = $filter; since = $now.AddDays(-$Lookback).ToString('yyyy-MM-ddTHH:mm:ss.000Z')
        until = $now.ToString('yyyy-MM-ddTHH:mm:ss.000Z'); sortOrder = 'ASCENDING'; limit = 1000 }
    $events = @(Invoke-OktaPagedGet -Client $Client -Path '/api/v1/logs' -Query $q |
        Where-Object { $ids -contains $_.actor.id } | ForEach-Object { ConvertTo-TrimmedEvent $_ })

    [Console]::Error.WriteLine('... reading authenticators and policies')
    $auths = @()
    foreach ($a in @(Invoke-OktaPagedGet -Client $Client -Path '/api/v1/authenticators')) {
        $methods = @()
        if ($a.key -eq 'okta_verify') {
            $methods = @(Invoke-OktaRequest -Client $Client -Method GET -Path "/api/v1/authenticators/$($a.id)/methods" | ForEach-Object { [ordered]@{ type = $_.type; status = $_.status } })
        }
        $auths += [ordered]@{ key = $a.key; status = $a.status; methods = @($methods) }
    }
    $apps = @()
    if ($theApp) { $apps = @($theApp) }
    elseif ($grp) {
        $apps = @(Invoke-OktaPagedGet -Client $Client -Path '/api/v1/apps' -Query @{ filter = "group.id eq `"$($grp.id)`"" } | Where-Object { $_.status -eq 'ACTIVE' })
    }
    $access = [ordered]@{}
    foreach ($a in $apps) {
        $href = Get-Prop (Get-Prop (Get-Prop $a '_links') 'accessPolicy') 'href'
        if (-not $href) { continue }
        $pid_ = $href.TrimEnd('/').Split('/')[-1]
        if (-not $access.Contains($pid_)) {
            $pol = Invoke-OktaRequest -Client $Client -Method GET -Path "/api/v1/policies/$pid_"
            $access[$pid_] = [ordered]@{ id = $pid_; name = $pol.name; apps = [Collections.Generic.List[string]]::new()
                rules = @(Get-OktaPolicyRules -Client $Client -PolicyId $pid_) }
        }
        $access[$pid_].apps.Add($a.label)
    }
    $signOn = @(Get-OktaPolicies -Client $Client -Type 'OKTA_SIGN_ON' | ForEach-Object {
            [ordered]@{ id = $_.id; name = $_.name; priority = $_.priority; status = $_.status; conditions = $_.conditions
                rules = @(Get-OktaPolicyRules -Client $Client -PolicyId $_.id) } })
    $enroll = @(Get-OktaPolicies -Client $Client -Type 'MFA_ENROLL' | ForEach-Object {
            [ordered]@{ id = $_.id; name = $_.name; priority = $_.priority; status = $_.status; conditions = $_.conditions; settings = $_.settings } })

    return [ordered]@{
        collected_at      = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
        lookback_days     = $Lookback
        target            = $target
        everyone_group_id = $everyoneId
        users             = @($users)
        events            = @($events)
        authenticators    = @($auths)
        access_policies   = @($access.Values | ForEach-Object { [ordered]@{ id = $_.id; name = $_.name; apps = @($_.apps); rules = @($_.rules) } })
        sign_on_policies  = @($signOn)
        enroll_policies   = @($enroll)
    }
}

# ---------------------------------------------------------------- main

if (-not $InputFile -and -not ($Group -or $App)) {
    [Console]::Error.WriteLine('error: give -Group and/or -App (or -InputFile SNAPSHOT_JSON)'); exit 1
}
if ($LookbackDays -lt 1 -or $LookbackDays -gt $MaxLookback) {
    [Console]::Error.WriteLine("error: -LookbackDays must be 1-$MaxLookback (System Log retention)"); exit 1
}

try {
    if ($InputFile) {
        $snap = Get-Content -Raw -Path $InputFile | ConvertFrom-Json
    }
    else {
        Import-Module "$PSScriptRoot/../lib/OktaClient.psm1" -Force
        $client = New-OktaClient
        $collected = Invoke-Collect -Client $client -GroupArg $Group -AppArg $App -Lookback $LookbackDays
        $snapJson = $collected | ConvertTo-Json -Depth 40
        if ($SaveSnapshot) {
            Set-Content -Path $SaveSnapshot -Value $snapJson -Encoding utf8
            [Console]::Error.WriteLine("wrote $SaveSnapshot")
        }
        # Round-trip so live and -InputFile runs analyze identical shapes.
        $snap = $snapJson | ConvertFrom-Json
    }
}
catch { [Console]::Error.WriteLine("error: $_"); exit 1 }

$res = Invoke-Analysis $snap
if ($Json) { $report = ($res | ConvertTo-Json -Depth 40) + "`n" }
else { $report = Format-Report $res }

if ($Output) {
    Set-Content -Path $Output -Value $report -Encoding utf8 -NoNewline
    [Console]::Error.WriteLine("wrote $Output")
}
else { Write-Output $report.TrimEnd("`n") }
if ($FailOnLockout -and $res.would_lock_out) { exit 2 }
exit 0
