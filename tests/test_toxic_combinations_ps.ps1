# Offline checks for scripts/toxic_combinations.ps1 against tests/fixtures/sod_snapshot.json.
# Mirrors tests/test_toxic_combinations.py, then diffs text/CSV/JSON against the
# Python port when python3 is on PATH. Exits 1 on failure.
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '..'
$ps1 = Join-Path $root 'scripts' 'toxic_combinations.ps1'
$py = Join-Path $root 'scripts' 'toxic_combinations.py'
$snap = Join-Path $PSScriptRoot 'fixtures' 'sod_snapshot.json'
$policy = Join-Path $root 'examples' 'sod_policy.example.json'
$edge = Join-Path $PSScriptRoot 'fixtures' 'sod_policy_edge.json'
$tmp = Join-Path ([System.IO.Path]::GetTempPath()) "sodtest_$PID"
New-Item -ItemType Directory -Force -Path $tmp | Out-Null

& pwsh -NoProfile -File $ps1 -Policy $policy -Snapshot $snap -Json -Output (Join-Path $tmp 'ps.json') -Csv (Join-Path $tmp 'ps.csv') 2>$null
$r = Get-Content -Raw (Join-Path $tmp 'ps.json') | ConvertFrom-Json
$pairs = @($r.findings | ForEach-Object { "$($_.user)|$($_.rule_id)" } | Sort-Object)
$carol = $r.findings | Where-Object { $_.user -eq 'carol.cloud@example.com' }
$dave = $r.findings | Where-Object { $_.user -eq 'dave.ap@example.com' }
$frank = $r.findings | Where-Object { $_.user -eq 'frank.ops@example.com' }
& pwsh -NoProfile -File $ps1 -Policy $policy -Snapshot $snap -FailOn critical *> $null
$failOnExit = $LASTEXITCODE
& pwsh -NoProfile -File $ps1 -Policy $edge -Snapshot $snap -Json -Output (Join-Path $tmp 'edge.json') 2>$null
$e = Get-Content -Raw (Join-Path $tmp 'edge.json') | ConvertFrom-Json

$cases = @(
    @{ Name = '8 findings, deprovisioned user ignored'; Got = "$($r.summary.findings)/$($r.summary.users_scanned)"; Want = '8/8' }
    @{ Name = 'bob (active WebAuthn) not flagged for SOD-001'; Got = ($pairs -contains 'bob.lead@example.com|SOD-001'); Want = $false }
    @{ Name = 'alice (pending WebAuthn only) flagged for SOD-001'; Got = ($pairs -contains 'alice.admin@example.com|SOD-001'); Want = $true }
    @{ Name = 'rule-managed path explained'; Got = $carol.sides[0].items[0].paths[0].via; Want = 'rule-managed group' }
    @{ Name = 'cheapest side chosen'; Got = $carol.smallest_fix.side; Want = 'Finance approver' }
    @{ Name = 'direct assignment preferred'; Got = $dave.smallest_fix.actions[0]; Want = "Unassign app 'Bill.com' from dave.ap@example.com (direct assignment)" }
    @{ Name = 'suspended user scored down'; Got = $dave.score; Want = 73 }
    @{ Name = 'tie goes to last side'; Got = $frank.smallest_fix.side; Want = 'No phishing-resistant factor' }
    @{ Name = 'fail-on exits 2'; Got = $failOnExit; Want = 2 }
    @{ Name = 'edge: exception by user id'; Got = "$($e.excepted[0].user)|$($e.excepted[0].rule_id)"; Want = 'frank.ops@example.com|E-3' }
    @{ Name = 'edge: all_of + custom role'; Got = (@($e.findings | Where-Object { $_.rule_id -eq 'E-1' }).user -join ','); Want = 'ivan.pay@example.com' }
)
$failed = 0
foreach ($c in $cases) {
    if ($c.Got -ne $c.Want) { Write-Host "FAIL $($c.Name): got $($c.Got), want $($c.Want)"; $failed++ }
    else { Write-Host "ok   $($c.Name)" }
}

$python = Get-Command python3 -ErrorAction SilentlyContinue
if ($python) {
    foreach ($pol in $policy, $edge) {
        $leaf = Split-Path -Leaf $pol
        $pyText = (& python3 $py --policy $pol --snapshot $snap --csv (Join-Path $tmp 'py.csv') 2>$null) -join "`n"
        $psText = (& pwsh -NoProfile -File $ps1 -Policy $pol -Snapshot $snap -Csv (Join-Path $tmp 'ps.csv') 2>$null) -join "`n"
        if ($pyText -cne $psText) { Write-Host "FAIL text parity ($leaf)"; $failed++ } else { Write-Host "ok   text parity ($leaf)" }
        $a = Get-Content -Raw (Join-Path $tmp 'py.csv'); $b = Get-Content -Raw (Join-Path $tmp 'ps.csv')
        if ($a -cne $b) { Write-Host "FAIL csv parity ($leaf)"; $failed++ } else { Write-Host "ok   csv parity ($leaf)" }
    }
} else {
    Write-Host 'skip parity diff: python3 not on PATH'
}
Remove-Item -Recurse -Force $tmp
if ($failed) { exit 1 }
Write-Host "$($cases.Count) checks passed"
