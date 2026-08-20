#!/usr/bin/env bash
# SEC-44 — drive the full three-layer chain end to end and capture the evidence.
#
#     ./scripts/demo.sh --api https://sentinelai.azurecontainerapps.io \
#                       --token "$SENTINELAI_TOKEN" \
#                       --project 11111111-1111-1111-1111-111111111111
#
# What it does, in the order a demo shows it:
#
#     pack  ->  POST /v1/scans  ->  poll  ->  graph stage  ->  audit stage  ->  read back
#
# and writes every response to an evidence directory, so the run can be shown again from disk
# when the live one cannot be repeated.
#
# WHAT THIS IS NOT. It is not the acceptance criterion. SEC-44 says "on the fixture PR", and the
# fixture PR runs the *Action*: the runner's own scanners produce the SARIF, the collector
# gathers the graph inputs, and the Action uploads and polls. This drives the same backend flow
# without GitHub in front of it. Use it to rehearse, to warm a cold start, and as the fallback
# when the live PR run fails in front of an audience — never as the thing you claim was demoed.
#
# Requires: bash, curl, tar, and jq for readable output (it degrades without jq).

set -euo pipefail

API=""
TOKEN=""
PROJECT=""
PACK_ONLY=0
BUNDLE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/samples/golden-bundle"
OUT_DIR="$(pwd)/demo-evidence/$(date +%Y%m%d-%H%M%S)"
COMMIT_SHA="$(date +%s | sha1sum | cut -c1-8)"
POLL_TIMEOUT=600

usage() {
  sed -n '2,22p' "${BASH_SOURCE[0]}" | sed 's/^# \?//'
  cat <<'USAGE'

Options:
  --api <url>        Backend base URL. Required.
  --token <jwt>      Machine token with scan:write, scan:read and report:read. Required.
  --project <guid>   A project id this token's tenant owns. Required.
  --bundle <dir>     Directory to pack. Default: samples/golden-bundle.
  --out <dir>        Evidence directory. Default: ./demo-evidence/<timestamp>.
  --commit <sha>     Commit sha to record. Default: a fresh one, so each run is a new job.
  --timeout <secs>   How long to wait for the audit stage. Default: 600.
  --pack-only        Build the bundle and stop. Needs no --api, --token or --project.

Exit codes: 0 the chain came out end to end, 1 bad arguments, 2 a stage failed.
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --api)      API="$2"; shift 2 ;;
    --token)    TOKEN="$2"; shift 2 ;;
    --project)  PROJECT="$2"; shift 2 ;;
    --bundle)   BUNDLE_DIR="$2"; shift 2 ;;
    --out)      OUT_DIR="$2"; shift 2 ;;
    --commit)   COMMIT_SHA="$2"; shift 2 ;;
    --timeout)  POLL_TIMEOUT="$2"; shift 2 ;;
    --pack-only) PACK_ONLY=1; shift ;;
    -h|--help)  usage; exit 0 ;;
    *)          echo "unknown option: $1" >&2; usage >&2; exit 1 ;;
  esac
done

# --pack-only exists so the packing half — which is where the bundle contract lives, and the
# only half that can be wrong without a server — is exercisable by CI. Everything after it
# needs a running backend and a credential.
if [[ "$PACK_ONLY" == "1" ]]; then
  PROJECT="${PROJECT:-11111111-1111-1111-1111-111111111111}"
else
  [[ -n "$API" && -n "$TOKEN" && -n "$PROJECT" ]] || { usage >&2; exit 1; }
  API="${API%/}"
fi

have_jq() { command -v jq >/dev/null 2>&1; }

# Pretty-print when jq is available, pass through when it is not. A missing jq should cost
# readability, not the run — the demo machine is not always the developer's.
show() { if have_jq; then jq -r "$@"; else cat; fi; }

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
fail() { printf '\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 2; }

mkdir -p "$OUT_DIR"
echo "evidence -> $OUT_DIR"

# ---- 1. Pack the bundle -------------------------------------------------------------------
# The same directory the SEC-49 regression harness runs over, so the demo shows exactly what CI
# proves. metadata.json is generated because it carries this run's project and commit.

step "Packing $BUNDLE_DIR"

[[ -f "$BUNDLE_DIR/graph-inputs/infra/iam.tf" ]] \
  || fail "$BUNDLE_DIR does not look like a bundle (no graph-inputs/infra/iam.tf)"

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT

# --exclude README.md: it is documentation for a human opening the directory, and the bundle
# layout allowlist refuses it — correctly, since the collector does not produce it.
tar -C "$BUNDLE_DIR" --exclude 'README.md' -cf - . | tar -C "$STAGE" -xf -

cat > "$STAGE/metadata.json" <<JSON
{"project_id":"$PROJECT","commit_sha":"$COMMIT_SHA","pr_ref":"pr/49","retain_report":true,"runner_secret_scan":"passed"}
JSON

BUNDLE="$OUT_DIR/bundle.tar.gz"
tar -C "$STAGE" -czf "$BUNDLE" .

# Listed once into a variable rather than re-read per check: under `set -o pipefail`, piping
# tar into `grep -q` makes grep close the pipe on its first match and tar exit on SIGPIPE, so
# the pipeline reports failure for a check that just succeeded.
ENTRIES="$(tar -tzf "$BUNDLE")"

echo "  $(echo "$ENTRIES" | grep -c .) entries, $(wc -c < "$BUNDLE") bytes"
echo "$ENTRIES" | sed 's/^/    /'

# The three entries whose absence or misnaming is refused at ingest with a 422, checked here so
# a packing mistake is caught before an audience sees it. terraform-graph.dot in particular is
# named exactly: the layout allowlist knows that name and refuses "terraform.dot".
for required in ./metadata.json ./findings/osv.sarif ./graph-inputs/terraform-graph.dot; do
  grep -qx -- "$required" <<< "$ENTRIES" \
    || fail "the bundle has no $required — ingest will refuse it with 422"
done

if [[ "$PACK_ONLY" == "1" ]]; then
  step "Packed"
  echo "  $BUNDLE"
  exit 0
fi

# ---- 2. Upload ------------------------------------------------------------------------------

step "POST $API/v1/scans"

HTTP=$(curl -sS -o "$OUT_DIR/01-submit.json" -w '%{http_code}' \
  -X POST "$API/v1/scans" \
  -H "Authorization: Bearer $TOKEN" \
  -F "metadata=<$STAGE/metadata.json" \
  -F "bundle=@$BUNDLE;type=application/gzip")

cat "$OUT_DIR/01-submit.json" | show '.'

[[ "$HTTP" == "202" ]] || fail "expected 202, got $HTTP"

if have_jq; then
  JOB=$(jq -r '.data.scanJobId' "$OUT_DIR/01-submit.json")
else
  JOB=$(grep -o '"scanJobId":"[^"]*"' "$OUT_DIR/01-submit.json" | cut -d'"' -f4)
fi

[[ -n "$JOB" && "$JOB" != "null" ]] || fail "no scan job id in the 202 response"
echo "  job $JOB"
echo "$JOB" > "$OUT_DIR/scan-job-id.txt"

# ---- 3. Poll ---------------------------------------------------------------------------------
# The Action polls this after upload, so it is part of the flow rather than a convenience. It is
# also where a cold start shows up: the serverless database auto-pauses, and the first request
# after that can take a minute with nothing wrong.

step "GET $API/v1/scans/$JOB"

curl -sS "$API/v1/scans/$JOB" -H "Authorization: Bearer $TOKEN" \
  | tee "$OUT_DIR/02-poll.json" | show '.data | {scanJobId, status, stage, corpusVersion}'

# ---- 4. Graph stage --------------------------------------------------------------------------
# normalize -> rule-map -> redact -> four seams -> bounded traversal. Fast: parsing and graph
# work, no model calls.

step "POST $API/v1/scans/$JOB/graph"

HTTP=$(curl -sS -o "$OUT_DIR/03-graph.json" -w '%{http_code}' \
  -X POST "$API/v1/scans/$JOB/graph" -H "Authorization: Bearer $TOKEN")

[[ "$HTTP" == "200" ]] || { cat "$OUT_DIR/03-graph.json"; fail "graph stage answered $HTTP"; }

if have_jq; then
  jq -r '.data | "  \(.findings) finding(s), \(.terraformFiles) tf, \(.lockFiles) lock, \(.dockerfiles) dockerfile -> \(.candidateChains) candidate chain(s)"' "$OUT_DIR/03-graph.json"

  echo "  chains:"
  jq -r '.data.chains[] | "    [\(.minConfidence)] " + (.path | join(" -> "))' "$OUT_DIR/03-graph.json"

  # The demo's whole claim, checked rather than eyeballed. A four-hop chain that crosses
  # dep -> code -> infra -> role -> resource is the thing no single-layer scanner produces, and
  # a run that quietly did not find it should stop here rather than proceed to a debate about
  # nothing.
  jq -e '.data.chains[] | select(.hopCount == 4)' "$OUT_DIR/03-graph.json" >/dev/null \
    || fail "no four-hop chain in the candidates — the three-layer claim did not reconstruct"
fi

# ---- 5. Audit stage ---------------------------------------------------------------------------
# retrieve -> Red/Blue debate -> Reporter adjudicates -> report -> retention. This is the slow
# one: real model calls, tens of seconds per turn.

step "POST $API/v1/scans/$JOB/audit   (this is the slow one)"

START=$(date +%s)

HTTP=$(curl -sS --max-time "$POLL_TIMEOUT" -o "$OUT_DIR/04-audit.json" -w '%{http_code}' \
  -X POST "$API/v1/scans/$JOB/audit" -H "Authorization: Bearer $TOKEN")

ELAPSED=$(( $(date +%s) - START ))

[[ "$HTTP" == "200" ]] || { cat "$OUT_DIR/04-audit.json"; fail "audit stage answered $HTTP after ${ELAPSED}s"; }

echo "  ${ELAPSED}s"
cat "$OUT_DIR/04-audit.json" | show '.data'

if have_jq; then
  REPORT=$(jq -r '.data.report_id // empty' "$OUT_DIR/04-audit.json")
else
  REPORT=$(grep -o '"report_id":"[^"]*"' "$OUT_DIR/04-audit.json" | cut -d'"' -f4)
fi

# ---- 6. Read it back --------------------------------------------------------------------------
# The seam the dashboard sits on. Showing the pipeline's own response and stopping there proves
# the backend; showing the read API proves the thing the screen will render.

step "Read API"

for route in bundle findings graph chains; do
  curl -sS "$API/v1/scans/$JOB/$route" -H "Authorization: Bearer $TOKEN" \
    > "$OUT_DIR/05-$route.json"
  echo "  GET /v1/scans/{id}/$route -> $(wc -c < "$OUT_DIR/05-$route.json") bytes"
done

if [[ -n "${REPORT:-}" && "$REPORT" != "null" ]]; then
  curl -sS "$API/v1/reports/$REPORT" -H "Authorization: Bearer $TOKEN" \
    > "$OUT_DIR/06-report.json"

  echo "  GET /v1/reports/$REPORT"

  if have_jq; then
    echo
    jq -r '"  framing: \(.framing)\n  summary: \(.summary)\n  citations: \(.citations | length)"' \
      "$OUT_DIR/06-report.json"

    echo "  chains as the screen will draw them:"
    jq -r '.chains[] | "    [\(.min_confidence)] " + ([.hops[] | .node_key // "?"] | join(" -> "))' \
      "$OUT_DIR/06-report.json"

    # 42-A's other half. The read API serves each chain's hops including the seed, so a path
    # rendered here should be as long as the one the graph stage returned. When it is not, the
    # screen draws the flagship chain without its dependency layer and the three-layer claim
    # becomes a two-layer one, with nothing failing.
    jq -e '[.chains[] | select([.hops[]] | length >= 5)] | length > 0' "$OUT_DIR/06-report.json" >/dev/null \
      || echo "    WARNING: no chain has five hops here, though the graph stage found one — check ChainView.HopsOf"
  fi
else
  echo "  no report retained (metadata.retain_report was not set) — nothing to read back"
fi

step "Done"
cat <<SUMMARY
  job       $JOB
  audit     ${ELAPSED}s
  evidence  $OUT_DIR

  Screenshot list is in docs/Demo_Run_Of_Show.md.
SUMMARY
