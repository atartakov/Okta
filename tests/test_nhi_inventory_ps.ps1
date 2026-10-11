# Offline parity check: scripts/nhi_inventory.ps1 must print exactly what
# scripts/nhi_inventory.py prints (text and CSV byte-for-byte, JSON by content)
# for the saved snapshot tests/fixtures/nhi_raw.json. Exits 1 on failure.
# Run: pwsh -NoProfile -File tests/test_nhi_inventory_ps.ps1
$ErrorActionPreference = 'Stop'
$root = Join-Path $PSScriptRoot '..'
$py = Join-Path $root 'scripts' 'nhi_inventory.py'
$ps = Join-Path $root 'scripts' 'nhi_inventory.ps1'
$raw = Join-Path $PSScriptRoot 'fixtures' 'nhi_raw.json'
$now = '2026-10-11T12:00:00Z'
# The script writes straight to stdout, so run it as a child pwsh like CI does.
$pwsh = (Get-Process -Id $PID).Path
$python = if (Get-Command python3 -ErrorAction SilentlyContinue) { 'python3' } else { 'python' }

$cases = @(
    @{ Name = 'text'; Py = @(); Ps = @() }
    @{ Name = 'csv'; Py = @('--csv'); Ps = @('-Csv') }
    @{ Name = 'min-risk high'; Py = @('--min-risk', 'high'); Ps = @('-MinRisk', 'high') }
    @{ Name = 'json'; Py = @('--json'); Ps = @('-Json'); IsJson = $true }
)
$failed = 0
foreach ($c in $cases) {
    $pyOut = (& $python $py --input $raw --now $now @($c.Py)) -join "`n"
    $psOut = (& $pwsh -NoProfile -File $ps -InputFile $raw -Now $now @($c.Ps)) -join "`n"
    if ($c.IsJson) {
        $same = (($pyOut | ConvertFrom-Json | ConvertTo-Json -Depth 12 -Compress) -eq ($psOut | ConvertFrom-Json | ConvertTo-Json -Depth 12 -Compress))
    } else {
        $same = ($pyOut -ceq $psOut)
    }
    if ($same) { Write-Host "ok   $($c.Name)" } else { Write-Host "FAIL $($c.Name): outputs differ"; $failed++ }
}
if ($failed) { exit 1 }
Write-Host "$($cases.Count) passed"
