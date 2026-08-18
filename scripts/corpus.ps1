<#
.SYNOPSIS
  Move a filled corpus between machines (SEC-48 support). PowerShell twin of corpus.sh.

.DESCRIPTION
  The corpus is 32,432 chunks and ~130 MB of vectors, produced by an ingest that wants source
  data and a GPU. Re-running it per teammate costs an afternoon and produces a DIFFERENT
  corpus_version -- which SEC-48 then refuses to run against. A snapshot is the same bytes
  everywhere, so everyone retrieves against one corpus with one version stamp.

.EXAMPLE
  ./scripts/corpus.ps1 status
  ./scripts/corpus.ps1 snapshot     # on the machine that HAS a corpus
  ./scripts/corpus.ps1 restore      # on every other machine
#>
param(
  [ValidateSet('status', 'snapshot', 'restore')]
  [string]$Command = 'status',

  [string]$QdrantUrl = $(if ($env:QDRANT_URL) { $env:QDRANT_URL } else { 'http://localhost:6333' }),
  [string]$QdrantKey = $env:QDRANT_KEY,
  [string]$SnapDir   = $(Join-Path (Split-Path $PSScriptRoot -Parent) '.corpus/snapshots')
)

$ErrorActionPreference = 'Stop'
$Collections = @('offense', 'defense')
$Headers = @{ 'Content-Type' = 'application/json' }
if ($QdrantKey) { $Headers['api-key'] = $QdrantKey }

function Test-Qdrant {
  try { Invoke-RestMethod -Uri "$QdrantUrl/readyz" -Headers $Headers -TimeoutSec 5 | Out-Null }
  catch {
    Write-Host "!! No Qdrant at $QdrantUrl"
    Write-Host "   docker compose -f compose.knowledge.yaml up -d qdrant"
    exit 1
  }
}

function Get-Count($Collection) {
  try {
    $r = Invoke-RestMethod -Method Post -Uri "$QdrantUrl/collections/$Collection/points/count" `
      -Headers $Headers -Body '{"exact":true}'
    return [int]$r.result.count
  } catch { return 0 }
}

function Show-Status {
  Test-Qdrant
  Write-Host "Qdrant at $QdrantUrl"
  foreach ($c in $Collections) {
    $n = Get-Count $c
    $note = switch ("${c}:$n") {
      'offense:28950' { '  (expected)' }
      'defense:31179' { '  (expected)' }
      default { if ($n -eq 0) { '  <- empty. restore, or run the ingest' }
                else { '  <- unexpected; a partial ingest looks exactly like this' } }
    }
    Write-Host ("  {0,-8} {1,8} points{2}" -f $c, $n, $note)
  }
}

function New-Snapshot {
  Test-Qdrant
  if (-not (Test-Path $SnapDir)) { New-Item -ItemType Directory -Force -Path $SnapDir | Out-Null }

  foreach ($c in $Collections) {
    $n = Get-Count $c
    if ($n -eq 0) {
      Write-Host "!! '$c' is empty - refusing to snapshot nothing."
      Write-Host "   A zero-point snapshot restores cleanly and leaves retrieval silently ungrounded."
      exit 1
    }
    Write-Host "snapshotting $c ($n points)..."
    $r = Invoke-RestMethod -Method Post -Uri "$QdrantUrl/collections/$c/snapshots" -Headers $Headers
    Write-Host "   -> $($r.result.name)"
  }

  Write-Host ""
  Write-Host "Snapshots are in $SnapDir"
  Write-Host "Share that folder and run 'corpus.ps1 restore' there."
}

function Restore-Snapshot {
  Test-Qdrant
  if (-not (Test-Path $SnapDir)) { Write-Host "!! No snapshot folder at $SnapDir"; exit 1 }

  foreach ($c in $Collections) {
    $file = Get-ChildItem -Path $SnapDir -Filter "$c-*.snapshot" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $file) { Write-Host "!! No snapshot for '$c' in $SnapDir"; exit 1 }

    Write-Host "restoring $c from $($file.Name)..."

    # The file:// path is the CONTAINER's view; compose mounts .corpus/snapshots there.
    $body = @{ location = "file:///qdrant/snapshots/$($file.Name)"; priority = 'snapshot' } | ConvertTo-Json
    $r = Invoke-RestMethod -Method Put -Uri "$QdrantUrl/collections/$c/snapshots/recover" `
      -Headers $Headers -Body $body

    if ($r.status -eq 'ok') { Write-Host "   -> $(Get-Count $c) points" }
    else { Write-Host "!! restore failed: $($r | ConvertTo-Json -Compress)"; exit 1 }
  }

  Write-Host ""
  Show-Status
}

switch ($Command) {
  'status'   { Show-Status }
  'snapshot' { New-Snapshot }
  'restore'  { Restore-Snapshot }
}
