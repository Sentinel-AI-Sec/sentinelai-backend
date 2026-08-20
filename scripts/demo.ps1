<#
.SYNOPSIS
    SEC-44 - drive the full three-layer chain end to end and capture the evidence.

.DESCRIPTION
    The PowerShell sibling of scripts/demo.sh, for the same reason corpus.ps1 sits beside
    corpus.sh: the demo is rehearsed and given on Windows, and asking someone to find a bash
    five minutes before a presentation is not a plan.

    What it does, in the order a demo shows it:

        pack  ->  POST /v1/scans  ->  poll  ->  graph stage  ->  audit stage  ->  read back

    and writes every response to an evidence directory, so the run can be shown again from disk
    when the live one cannot be repeated.

    WHAT THIS IS NOT. It is not the acceptance criterion. SEC-44 says "on the fixture PR", and
    the fixture PR runs the *Action*: the runner's own scanners produce the SARIF, the collector
    gathers the graph inputs, and the Action uploads and polls. This drives the same backend flow
    without GitHub in front of it. Use it to rehearse, to warm a cold start, and as the fallback
    when the live PR run fails in front of an audience - never as the thing you claim was demoed.

.PARAMETER Api
    Backend base URL.

.PARAMETER Token
    Machine token carrying scan:write, scan:read and report:read.

.PARAMETER ProjectId
    A project id this token's tenant owns.

.PARAMETER BundleDir
    Directory to pack. Defaults to samples/golden-bundle - the same one the SEC-49 regression
    harness runs over, so the demo shows exactly what CI proves.

.PARAMETER OutDir
    Evidence directory. Defaults to ./demo-evidence/<timestamp>.

.PARAMETER TimeoutSeconds
    How long to wait for the audit stage. Defaults to 600.

.PARAMETER PackOnly
    Build the bundle and stop. Needs no Api, Token or ProjectId.

.EXAMPLE
    ./scripts/demo.ps1 -Api https://sentinelai.azurecontainerapps.io -Token $env:SENTINELAI_TOKEN `
                       -ProjectId 11111111-1111-1111-1111-111111111111
#>
[CmdletBinding()]
param(
    [string] $Api,
    [string] $Token,
    [string] $ProjectId,
    [string] $BundleDir = (Join-Path (Split-Path -Parent $PSScriptRoot) 'samples/golden-bundle'),
    [string] $OutDir = (Join-Path (Get-Location) "demo-evidence/$(Get-Date -Format 'yyyyMMdd-HHmmss')"),
    [string] $CommitSha = ([guid]::NewGuid().ToString('N').Substring(0, 8)),
    [int]    $TimeoutSeconds = 600,
    [switch] $PackOnly
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string] $Text) Write-Host "`n== $Text" -ForegroundColor Cyan }
function Stop-Demo  { param([string] $Text) Write-Host "FAILED: $Text" -ForegroundColor Red; exit 2 }

if (-not $PackOnly) {
    if (-not $Api -or -not $Token -or -not $ProjectId) {
        Get-Help $PSCommandPath -Detailed
        exit 1
    }

    $Api = $Api.TrimEnd('/')
}

if ($PackOnly -and -not $ProjectId) { $ProjectId = '11111111-1111-1111-1111-111111111111' }

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Write-Host "evidence -> $OutDir"

# ---- 1. Pack the bundle -----------------------------------------------------------------
# metadata.json is generated rather than committed, because it carries this run's project and
# commit. README.md is excluded: it is documentation for a human opening the directory, and the
# bundle layout allowlist refuses it - correctly, since the collector does not produce it.

Write-Step "Packing $BundleDir"

if (-not (Test-Path (Join-Path $BundleDir 'graph-inputs/infra/iam.tf'))) {
    Stop-Demo "$BundleDir does not look like a bundle (no graph-inputs/infra/iam.tf)"
}

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ([guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Force -Path $stage | Out-Null

try {
    Copy-Item -Path (Join-Path $BundleDir '*') -Destination $stage -Recurse -Force
    Remove-Item -Path (Join-Path $stage 'README.md') -Force -ErrorAction SilentlyContinue

    $metadata = "{`"project_id`":`"$ProjectId`",`"commit_sha`":`"$CommitSha`",`"pr_ref`":`"pr/49`",`"retain_report`":true,`"runner_secret_scan`":`"passed`"}"

    # utf8 explicitly: Set-Content defaults to the system ANSI codepage, and a metadata.json in
    # codepage 1252 is not JSON the backend will parse the same way.
    Set-Content -Path (Join-Path $stage 'metadata.json') -Value $metadata -Encoding utf8 -NoNewline

    $bundle = Join-Path $OutDir 'bundle.tar.gz'

    # bsdtar, which ships with Windows 10 1803 and later. Run from inside the staging directory
    # so the archive's paths are bundle-relative - an archive carrying the staging path is
    # refused by the layout allowlist, and the error names files nobody recognises.
    Push-Location $stage
    try { tar -czf $bundle . } finally { Pop-Location }

    if (-not (Test-Path $bundle)) { Stop-Demo "tar produced no archive - is tar.exe on PATH?" }

    $entries = tar -tzf $bundle
    Write-Host ("  {0} entries, {1} bytes" -f $entries.Count, (Get-Item $bundle).Length)
    $entries | ForEach-Object { Write-Host "    $_" }

    # The three entries whose absence or misnaming is refused at ingest with a 422, checked here
    # so a packing mistake is caught before an audience sees it. terraform-graph.dot in
    # particular is named exactly: the layout allowlist knows that name and refuses
    # "terraform.dot".
    foreach ($required in @('./metadata.json', './findings/osv.sarif', './graph-inputs/terraform-graph.dot')) {
        if ($entries -notcontains $required) {
            Stop-Demo "the bundle has no $required - ingest will refuse it with 422"
        }
    }

    if ($PackOnly) {
        Write-Step 'Packed'
        Write-Host "  $bundle"
        exit 0
    }

    $headers = @{ Authorization = "Bearer $Token" }

    # ---- 2. Upload ------------------------------------------------------------------------

    Write-Step "POST $Api/v1/scans"

    # -Form is what makes this multipart. Handing the file as a FileInfo rather than as text is
    # load-bearing: a gzip stream read as a string is corrupted by encoding before it is sent,
    # and the backend rejects it as a malformed archive.
    $submit = Invoke-RestMethod -Uri "$Api/v1/scans" -Method Post -Headers $headers -Form @{
        metadata = $metadata
        bundle   = Get-Item $bundle
    }

    $submit | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir '01-submit.json') -Encoding utf8
    $submit.data | Format-List | Out-String | Write-Host

    $job = $submit.data.scanJobId
    if (-not $job) { Stop-Demo 'no scan job id in the response' }

    Write-Host "  job $job"
    Set-Content (Join-Path $OutDir 'scan-job-id.txt') $job -Encoding utf8

    # ---- 3. Poll ---------------------------------------------------------------------------
    # The Action polls this after upload, so it is part of the flow rather than a convenience.
    # It is also where a cold start shows up: the serverless database auto-pauses, and the first
    # request after that can take a minute with nothing wrong.

    Write-Step "GET $Api/v1/scans/$job"

    $poll = Invoke-RestMethod -Uri "$Api/v1/scans/$job" -Headers $headers
    $poll | ConvertTo-Json -Depth 6 | Set-Content (Join-Path $OutDir '02-poll.json') -Encoding utf8
    Write-Host ("  status {0}, stage {1}, corpus {2}" -f $poll.data.status, $poll.data.stage, $poll.data.corpusVersion)

    # ---- 4. Graph stage ----------------------------------------------------------------------
    # normalize -> rule-map -> redact -> four seams -> bounded traversal. Fast: parsing and graph
    # work, no model calls.

    Write-Step "POST $Api/v1/scans/$job/graph"

    $graph = Invoke-RestMethod -Uri "$Api/v1/scans/$job/graph" -Method Post -Headers $headers
    $graph | ConvertTo-Json -Depth 10 | Set-Content (Join-Path $OutDir '03-graph.json') -Encoding utf8

    Write-Host ("  {0} finding(s), {1} tf, {2} lock, {3} dockerfile -> {4} candidate chain(s)" -f `
        $graph.data.findings, $graph.data.terraformFiles, $graph.data.lockFiles,
        $graph.data.dockerfiles, $graph.data.candidateChains)

    Write-Host '  chains:'
    foreach ($chain in $graph.data.chains) {
        Write-Host ("    [{0}] {1}" -f $chain.minConfidence, ($chain.path -join ' -> '))
    }

    # The demo's whole claim, checked rather than eyeballed. A four-hop chain crossing
    # dep -> code -> infra -> role -> resource is the thing no single-layer scanner produces, and
    # a run that quietly did not find it should stop here rather than proceed to a debate about
    # nothing.
    if (-not ($graph.data.chains | Where-Object { $_.hopCount -eq 4 })) {
        Stop-Demo 'no four-hop chain in the candidates - the three-layer claim did not reconstruct'
    }

    # ---- 5. Audit stage -----------------------------------------------------------------------
    # retrieve -> Red/Blue debate -> Reporter adjudicates -> report -> retention. This is the slow
    # one: real model calls, tens of seconds per turn.

    Write-Step "POST $Api/v1/scans/$job/audit   (this is the slow one)"

    $started = Get-Date
    $audit = Invoke-RestMethod -Uri "$Api/v1/scans/$job/audit" -Method Post -Headers $headers `
        -TimeoutSec $TimeoutSeconds
    $elapsed = [int]((Get-Date) - $started).TotalSeconds

    $audit | ConvertTo-Json -Depth 8 | Set-Content (Join-Path $OutDir '04-audit.json') -Encoding utf8

    Write-Host "  ${elapsed}s"
    $audit.data | Format-List | Out-String | Write-Host

    $reportId = $audit.data.report_id

    # ---- 6. Read it back -----------------------------------------------------------------------
    # The seam the dashboard sits on. Showing the pipeline's own response and stopping there
    # proves the backend; showing the read API proves the thing the screen will render.

    Write-Step 'Read API'

    foreach ($route in @('bundle', 'findings', 'graph', 'chains')) {
        $response = Invoke-RestMethod -Uri "$Api/v1/scans/$job/$route" -Headers $headers
        $path = Join-Path $OutDir "05-$route.json"
        $response | ConvertTo-Json -Depth 12 | Set-Content $path -Encoding utf8
        Write-Host ("  GET /v1/scans/{{id}}/{0} -> {1} bytes" -f $route, (Get-Item $path).Length)
    }

    if ($reportId) {
        $report = Invoke-RestMethod -Uri "$Api/v1/reports/$reportId" -Headers $headers
        $report | ConvertTo-Json -Depth 12 | Set-Content (Join-Path $OutDir '06-report.json') -Encoding utf8

        Write-Host "  GET /v1/reports/$reportId"
        Write-Host ("  framing: {0}" -f $report.framing)
        Write-Host ("  summary: {0}" -f $report.summary)
        Write-Host ("  citations: {0}" -f $report.citations.Count)

        Write-Host '  chains as the screen will draw them:'
        foreach ($chain in $report.chains) {
            $path = ($chain.hops | Sort-Object order | ForEach-Object { if ($_.node_key) { $_.node_key } else { '?' } }) -join ' -> '
            Write-Host ("    [{0}] {1}" -f $chain.min_confidence, $path)
        }

        # 42-A's other half. The read API serves each chain's hops including the seed, so a path
        # rendered here should be as long as the one the graph stage returned. When it is not,
        # the screen draws the flagship chain without its dependency layer and the three-layer
        # claim becomes a two-layer one, with nothing failing.
        if (-not ($report.chains | Where-Object { $_.hops.Count -ge 5 })) {
            Write-Host '    WARNING: no chain has five hops here, though the graph stage found one - check ChainView.HopsOf' -ForegroundColor Yellow
        }
    }
    else {
        Write-Host '  no report retained (metadata.retain_report was not set) - nothing to read back'
    }

    Write-Step 'Done'
    Write-Host "  job       $job"
    Write-Host "  audit     ${elapsed}s"
    Write-Host "  evidence  $OutDir"
    Write-Host ''
    Write-Host '  Screenshot list is in docs/Demo_Run_Of_Show.md.'
}
finally {
    Remove-Item -Recurse -Force $stage -ErrorAction SilentlyContinue
}
