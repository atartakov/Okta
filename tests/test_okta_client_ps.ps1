# Offline checks for Get-OktaRetryDelay in lib/OktaClient.psm1.
# Mirrors tests/test_okta_client.py so both clients agree. Exits 1 on failure.
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSScriptRoot '..' 'lib' 'OktaClient.psm1') -Force

$now = 1791000000
$date = 'Sun, 11 Oct 2026 08:40:00 GMT'
$dateEpoch = 1791708000
$cases = @(
    @{ Name = 'epoch reset measured from now'; Got = (Get-OktaRetryDelay -Headers @{ 'x-rate-limit-reset' = "$($now + 3)" } -Now $now); Want = 4 }
    @{ Name = 'reset already passed'; Got = (Get-OktaRetryDelay -Headers @{ 'x-rate-limit-reset' = "$($now - 10)" } -Now $now); Want = 1 }
    @{ Name = 'far future reset capped'; Got = (Get-OktaRetryDelay -Headers @{ 'x-rate-limit-reset' = "$($now + 600)" } -Now $now); Want = 61 }
    @{ Name = 'uses Okta Date header'; Got = (Get-OktaRetryDelay -Headers @{ 'X-Rate-Limit-Reset' = @("$($dateEpoch + 2)"); 'Date' = @($date) }); Want = 3 }
    @{ Name = 'missing header defaults to 5'; Got = (Get-OktaRetryDelay -Headers @{}); Want = 5 }
    @{ Name = 'garbage header defaults to 5'; Got = (Get-OktaRetryDelay -Headers @{ 'x-rate-limit-reset' = 'soon' }); Want = 5 }
    @{ Name = 'small value is a duration'; Got = (Get-OktaRetryDelay -Headers @{ 'x-rate-limit-reset' = '7' }); Want = 8 }
)
$failed = 0
foreach ($c in $cases) {
    if ($c.Got -ne $c.Want) { Write-Host "FAIL $($c.Name): got $($c.Got), want $($c.Want)"; $failed++ }
    else { Write-Host "ok   $($c.Name)" }
}
if ($failed) { exit 1 }
Write-Host "$($cases.Count) passed"
