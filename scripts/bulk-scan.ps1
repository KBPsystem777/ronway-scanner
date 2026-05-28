# bulk-scan.ps1 — Scan multiple targets against the RonwayScanner API
# Usage: .\bulk-scan.ps1 [-ApiBase <url>] [-OutFile <path>] [-DelayMs <ms>]
#
# Rate limit: 10 req/min per IP. Default 6-second delay keeps you safely under.
# To skip delay (e.g. scanning localhost): -DelayMs 0

param(
    [string]$ApiBase  = "https://ronway-api.bpxai.com",
    [string]$OutFile  = "scan-results.json",
    [int]   $DelayMs  = 6100   # 6.1s → ~9.8 req/min, safely under 10/min limit
)

$Domains = @(
    "gov.ph"
    "op-proper.gov.ph"
    "ovp.gov.ph"
    "senate.gov.ph"
    "congress.gov.ph"
    "sc.judiciary.gov.ph"
    "ca.judiciary.gov.ph"
    "sb.judiciary.gov.ph"
    "dbm.gov.ph"
    "dof.gov.ph"
    "dti.gov.ph"
    "dict.gov.ph"
    "dost.gov.ph"
    "deped.gov.ph"
    "ched.gov.ph"
    "tesda.gov.ph"
    "dole.gov.ph"
    "dfa.gov.ph"
    "immigration.gov.ph"
    "nbi.gov.ph"
    "pnp.gov.ph"
    "bfp.gov.ph"
    "bjmp.gov.ph"
    "napolcom.gov.ph"
    "dswd.gov.ph"
    "philhealth.gov.ph"
    "sss.gov.ph"
    "pagibigfund.gov.ph"
    "bir.gov.ph"
    "boi.gov.ph"
    "peza.gov.ph"
    "sec.gov.ph"
    "ltfrb.gov.ph"
    "lto.gov.ph"
    "marina.gov.ph"
    "caap.gov.ph"
    "dotr.gov.ph"
    "dpwh.gov.ph"
    "denr.gov.ph"
    "pagasa.dost.gov.ph"
    "phivolcs.dost.gov.ph"
    "da.gov.ph"
    "bfar.da.gov.ph"
    "neda.gov.ph"
    "psa.gov.ph"
    "comelec.gov.ph"
    "csc.gov.ph"
    "coa.gov.ph"
    "ombudsman.gov.ph"
    "dilg.gov.ph"
    "doh.gov.ph"
    "tourism.gov.ph"
    "pcso.gov.ph"
    "landbank.com"
    "dbp.ph"
    "bsp.gov.ph"
    "customs.gov.ph"
    "tariffcommission.gov.ph"
    "ipophil.gov.ph"
    "cdrrmo.gov.ph"
    "e.gov.ph"
    "open.gov.ph"
    "officialgazette.gov.ph"
)

$Total   = $Domains.Count
$Results = [System.Collections.Generic.List[object]]::new()
$Passed  = 0
$Failed  = 0
$Errors  = 0

Write-Host ""
Write-Host "RonwayScanner Bulk Scan — $Total targets" -ForegroundColor Cyan
Write-Host "API: $ApiBase" -ForegroundColor DarkGray
Write-Host "Output: $OutFile" -ForegroundColor DarkGray
Write-Host ("-" * 60)

$i = 0
foreach ($Domain in $Domains) {
    $i++
    $Pct = [int](($i / $Total) * 100)
    Write-Host "[$i/$Total] $Domain ... " -NoNewline

    $Body = @{ target = $Domain } | ConvertTo-Json -Compress

    try {
        $Response = Invoke-RestMethod `
            -Method POST `
            -Uri "$ApiBase/api/scan" `
            -ContentType "application/json" `
            -Body $Body `
            -TimeoutSec 30 `
            -ErrorAction Stop

        $Score   = $Response.risk_score.value
        $Level   = $Response.risk_score.level
        $Harvest = $Response.risk_score.harvest_risk

        $Color = switch ($Level) {
            "Critical" { "Red" }
            "High"     { "DarkRed" }
            "Medium"   { "Yellow" }
            "Low"      { "Cyan" }
            "Pass"     { "Green" }
            default    { "Gray" }
        }

        $HarvestTag = if ($Harvest) { " [HARVEST RISK]" } else { "" }
        Write-Host "$Level ($Score)$HarvestTag" -ForegroundColor $Color

        $Results.Add([PSCustomObject]@{
            domain       = $Domain
            risk_score   = $Score
            risk_level   = $Level
            harvest_risk = $Harvest
            quantum_ready = $Response.quantum_ready
            tls_version  = $Response.tls?.version
            raw          = $Response
        })

        if ($Level -eq "Pass") { $Passed++ } else { $Failed++ }

    } catch {
        $ErrMsg = $_.Exception.Message
        Write-Host "ERROR: $ErrMsg" -ForegroundColor DarkGray

        $Results.Add([PSCustomObject]@{
            domain       = $Domain
            risk_score   = $null
            risk_level   = "error"
            harvest_risk = $false
            quantum_ready = $false
            tls_version  = $null
            error        = $ErrMsg
            raw          = $null
        })
        $Errors++
    }

    if ($i -lt $Total -and $DelayMs -gt 0) {
        Start-Sleep -Milliseconds $DelayMs
    }
}

# ── Summary ──────────────────────────────────────────────────────────────────

Write-Host ""
Write-Host ("=" * 60)
Write-Host "SCAN COMPLETE" -ForegroundColor Cyan
Write-Host "  Total   : $Total"
Write-Host "  Passed  : $Passed" -ForegroundColor Green
Write-Host "  At Risk : $Failed" -ForegroundColor Yellow
Write-Host "  Errors  : $Errors" -ForegroundColor DarkGray

$HarvestCount = ($Results | Where-Object { $_.harvest_risk -eq $true }).Count
if ($HarvestCount -gt 0) {
    Write-Host "  Harvest Risk targets: $HarvestCount" -ForegroundColor Red
}

# Top 10 riskiest
Write-Host ""
Write-Host "Top 10 riskiest:" -ForegroundColor Yellow
$Results `
    | Where-Object { $_.risk_score -ne $null } `
    | Sort-Object risk_score -Descending `
    | Select-Object -First 10 `
    | ForEach-Object { Write-Host ("  {0,-40} {1,3}  {2}" -f $_.domain, $_.risk_score, $_.risk_level) }

# Save full JSON
$Results | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutFile -Encoding utf8
Write-Host ""
Write-Host "Full results saved to: $OutFile" -ForegroundColor Cyan
