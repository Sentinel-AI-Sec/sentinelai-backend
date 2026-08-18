#!/usr/bin/env bash
# Move a filled corpus between machines (SEC-48 support).
#
#     ./scripts/corpus.sh status
#     ./scripts/corpus.sh snapshot          # on the machine that HAS a corpus
#     ./scripts/corpus.sh restore           # on every other machine
#
# Why this exists: the corpus is 32,432 chunks and ~130 MB of vectors, produced by an ingest
# that wants source data and a GPU. Asking each teammate to re-run that is asking them to spend
# an afternoon reproducing a thing that already exists — and to end up with a *different*
# corpus_version, which is exactly what SEC-48 then refuses to run against.
#
# A snapshot is the same bytes on every machine, so everyone retrieves against one corpus with
# one version stamp, and audits stay comparable.
#
# Env:
#   QDRANT_URL   REST endpoint          (default http://localhost:6333)
#   QDRANT_KEY   api-key, if any        (default empty — a local container needs none)
#   SNAP_DIR     host snapshot folder   (default ./.corpus/snapshots, mounted by compose)

set -euo pipefail

QDRANT_URL="${QDRANT_URL:-http://localhost:6333}"
QDRANT_KEY="${QDRANT_KEY:-}"
SNAP_DIR="${SNAP_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/.corpus/snapshots}"
COLLECTIONS=(offense defense)

curl_q() {
  if [ -n "$QDRANT_KEY" ]; then
    curl -sS -H "api-key: $QDRANT_KEY" -H "Content-Type: application/json" "$@"
  else
    curl -sS -H "Content-Type: application/json" "$@"
  fi
}

count_of() {
  curl_q -X POST "$QDRANT_URL/collections/$1/points/count" -d '{"exact":true}' 2>/dev/null \
    | grep -oE '"count":[0-9]+' | cut -d: -f2 || echo "0"
}

require_qdrant() {
  if ! curl_q "$QDRANT_URL/readyz" >/dev/null 2>&1; then
    echo "!! No Qdrant at $QDRANT_URL"
    echo "   docker compose -f compose.knowledge.yaml up -d qdrant"
    exit 1
  fi
}

cmd_status() {
  require_qdrant
  echo "Qdrant at $QDRANT_URL"
  for c in "${COLLECTIONS[@]}"; do
    n="$(count_of "$c")"
    printf "  %-8s %8s points" "$c" "${n:-0}"
    # The numbers a healthy corpus reports. Anything else and retrieval will look "empty"
    # rather than broken, which is the confusing failure this line exists to pre-empt.
    case "$c:$n" in
      offense:28950|defense:31179) echo "  (expected)";;
      *:0) echo "  <- empty. restore, or run the ingest";;
      *) echo "  <- unexpected; a partial ingest looks exactly like this";;
    esac
  done
}

cmd_snapshot() {
  require_qdrant
  mkdir -p "$SNAP_DIR"

  for c in "${COLLECTIONS[@]}"; do
    n="$(count_of "$c")"
    if [ "${n:-0}" = "0" ]; then
      echo "!! '$c' is empty — refusing to snapshot nothing."
      echo "   A zero-point snapshot restores cleanly and leaves retrieval silently ungrounded."
      exit 1
    fi

    echo "snapshotting $c ($n points)..."
    out="$(curl_q -X POST "$QDRANT_URL/collections/$c/snapshots")"
    name="$(echo "$out" | grep -oE '"name":"[^"]+"' | head -1 | cut -d'"' -f4)"

    if [ -z "$name" ]; then
      echo "!! Qdrant did not return a snapshot name. Response: $out"
      exit 1
    fi
    echo "   -> $name"
  done

  echo
  echo "Snapshots are in $SNAP_DIR"
  echo "Share that folder (or the two .snapshot files in it) and run 'corpus.sh restore' there."
}

cmd_restore() {
  require_qdrant

  if [ ! -d "$SNAP_DIR" ]; then
    echo "!! No snapshot folder at $SNAP_DIR"
    exit 1
  fi

  for c in "${COLLECTIONS[@]}"; do
    # Newest snapshot for this collection. Qdrant names them <collection>-<timestamp>.snapshot.
    file="$(ls -1t "$SNAP_DIR"/${c}-*.snapshot 2>/dev/null | head -1 || true)"

    if [ -z "$file" ]; then
      echo "!! No snapshot for '$c' in $SNAP_DIR"
      exit 1
    fi

    echo "restoring $c from $(basename "$file")..."

    # file:// path is the CONTAINER's view. compose mounts ./.corpus/snapshots there, so a file
    # visible on the host at $SNAP_DIR is visible to Qdrant at /qdrant/snapshots.
    body="{\"location\":\"file:///qdrant/snapshots/$(basename "$file")\",\"priority\":\"snapshot\"}"
    out="$(curl_q -X PUT "$QDRANT_URL/collections/$c/snapshots/recover" -d "$body")"

    if echo "$out" | grep -q '"status":"ok"'; then
      echo "   -> $(count_of "$c") points"
    else
      echo "!! restore failed: $out"
      exit 1
    fi
  done

  echo
  cmd_status
}

case "${1:-status}" in
  status)   cmd_status ;;
  snapshot) cmd_snapshot ;;
  restore)  cmd_restore ;;
  *)
    echo "usage: $0 {status|snapshot|restore}"
    exit 2
    ;;
esac
