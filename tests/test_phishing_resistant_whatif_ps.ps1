# Offline checks for scripts/phishing_resistant_whatif.ps1 against the shared
# snapshot fixture. Mirrors tests/test_phishing_resistant_whatif.py, and when
# python3 is on PATH also diffs text and JSON output against the Python
# version. Exits 1 on failure.
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '..'
$script = Join-Path $root 'scripts' 'phishing_resistant_whatif.ps1'
$pyScript = Join-Path $root 'scripts' 'phishing_resistant_whatif.py'
$snap = Join-Path $PSScriptRoot 'fixtures' 'phishing_resistant_snapshot.json'

$res = & pwsh -NoProfile -File $script -InputFile $snap -Json | Out-String | ConvertFrom-Json
$cls = @{}
foreach ($u in $res.users) { $cls[$u.login] = $u.class }
$src = Get-Content -Raw -Path $script

$cases = @(
    @{ Name = 'alice READY'; Got = $cls['alice@example.com']; Want = 'READY' }
    @{ Name = 'carol enrolled not used'; Got = $cls['Carol@example.com']; Want = 'ENROLLED_NOT_USED' }
    @{ Name = 'ivan PR use outside window'; Got = $cls['ivan@example.com']; Want = 'ENROLLED_NOT_USED' }
    @{ Name = 'dave AT_RISK (failed PR ignored)'; Got = $cls['dave@example.com']; Want = 'AT_RISK' }
    @{ Name = 'frank NO_MFA'; Got = $cls['frank@example.com']; Want = 'NO_MFA' }
    @{ Name = 'platform blockers'; Got = $res.summary.PLATFORM_BLOCKER; Want = 2 }
    @{ Name = 'skipped not active'; Got = "$($res.skipped_not_active.STAGED)/$($res.skipped_not_active.SUSPENDED)"; Want = '1/1' }
    @{ Name = 'would lock out'; Got = $res.would_lock_out; Want = 5 }
    @{ Name = 'lockout order'; Got = ($res.lockout.login -join ','); Want = 'frank@example.com,dave@example.com,erin@example.com,bob@example.com,jill@example.com' }
    @{ Name = 'wave 1'; Got = ($res.waves.wave1_enforce_now -join ','); Want = 'alice@example.com' }
    @{ Name = 'first unconditional rule'; Got = (@($res.policies.app_sign_in[0].rules | Where-Object { $_.first_unconditional_match }).name); Want = 'Engineering 2FA' }
    @{ Name = 'webauthn inactive is blocker'; Got = $res.tenant_checks[0][0]; Want = 'BLOCKER' }
    @{ Name = 'only GET requests'; Got = ((([regex]::Matches($src, '-Method\s+(\w+)') | ForEach-Object { $_.Groups[1].Value }) | Sort-Object -Unique) -join ','); Want = 'GET' }
)

$failed = 0
foreach ($c in $cases) {
    if ($c.Got -ne $c.Want) { Write-Host "FAIL $($c.Name): got $($c.Got), want $($c.Want)"; $failed++ }
    else { Write-Host "ok   $($c.Name)" }
}

$python = Get-Command python3 -ErrorAction SilentlyContinue
if ($python) {
    $pyTxt = (& python3 $pyScript --input $snap | Out-String)
    $psTxt = (& pwsh -NoProfile -File $script -InputFile $snap | Out-String)
    if ($pyTxt -ne $psTxt) { Write-Host 'FAIL text output differs from Python'; $failed++ } else { Write-Host 'ok   text parity with Python' }
    $pyJson = (& python3 $pyScript --input $snap --json | Out-String | ConvertFrom-Json | ConvertTo-Json -Depth 40 -Compress)
    $psJson = (& pwsh -NoProfile -File $script -InputFile $snap -Json | Out-String | ConvertFrom-Json | ConvertTo-Json -Depth 40 -Compress)
    if ($pyJson -ne $psJson) { Write-Host 'FAIL JSON output differs from Python'; $failed++ } else { Write-Host 'ok   JSON parity with Python' }
}
else { Write-Host 'skip parity: python3 not found' }

if ($failed) { exit 1 }
Write-Host "$($cases.Count) checks passed"
