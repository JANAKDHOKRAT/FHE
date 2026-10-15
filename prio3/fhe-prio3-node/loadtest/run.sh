#!/usr/bin/env bash
# Load test of a split-key deployment (one aggregator and the collector,
# each holding a key share), as separate OS processes over TLS:
#
#   1. TLS: a throwaway CA and a localhost server certificate (openssl);
#   2. the task (`task-config --topology split`, production silent-mode
#      parameters: ring 65536, depth 28, 64 groups, 7 repetitions), with
#      `--upload shares` Prio3's secret-shared upload: each key party first
#      makes its upload key (`upload-key`, sealed under its seal key) and the
#      task lists both public keys;
#   3. keys: `--keys ceremony` runs the distributed key ceremony, one
#      process per key party, each with its own seal key (the deployment
#      path; no process sees both shares). At the production parameters its
#      two processes do not fit together in 15 GiB (the kernel kills one),
#      so on one such machine use `--keys keygen`: the same keys from one
#      dealer process (a trial setup; the load does not depend on how the
#      keys were made, and the report records which was used);
#   4. the collector and the aggregator, each with a metrics listener;
#   5. `fhe-prio3-node loadtest`: real clients, the close, the exact check;
#   6. the nodes are stopped with SIGTERM; logs, the report, the metrics
#      timeline, the database sizes and the machine description stay in the
#      output directory.
#
# A run stopped at any point (the machine restarted, a node killed) is
# continued with `--resume --out DIR`: the nodes restart from their
# databases (their crash recovery) and the load test from its client state
# (every report counted once), with the secrets and arguments of the first
# run (DIR/run.env, readable by its owner only: it holds the seal keys and
# the token of this throwaway deployment).
#
# Usage: loadtest/run.sh --out DIR --reports N [--type histogram:16]
#          [--min-batch K] [--min-cell C] [--workers W] [--invalid-every M]
#          [--seed S] [--keys ceremony|keygen] [--upload ciphertext|shares]
#        loadtest/run.sh --resume --out DIR
# Exit status: that of the load test (0 only when the released result is
# exactly the expected one).
set -euo pipefail

OUT="" REPORTS="" TYPE="histogram:16" MIN_BATCH=1 MIN_CELL=0 WORKERS=2 INVALID_EVERY=0 SEED=1 KEYS=ceremony UPLOAD=ciphertext RESUME=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --resume) RESUME=1; shift ;;
    --out) OUT="$2"; shift 2 ;;
    --reports) REPORTS="$2"; shift 2 ;;
    --type) TYPE="$2"; shift 2 ;;
    --min-batch) MIN_BATCH="$2"; shift 2 ;;
    --min-cell) MIN_CELL="$2"; shift 2 ;;
    --workers) WORKERS="$2"; shift 2 ;;
    --invalid-every) INVALID_EVERY="$2"; shift 2 ;;
    --seed) SEED="$2"; shift 2 ;;
    --keys) KEYS="$2"; shift 2 ;;
    --upload) UPLOAD="$2"; shift 2 ;;
    *) echo "unknown argument $1" >&2; exit 2 ;;
  esac
done
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN="${FHE_PRIO3_NODE_BIN:-$HERE/../target/release/fhe-prio3-node}"
[[ -x "$BIN" ]] || { echo "build first: cargo build --release (or set FHE_PRIO3_NODE_BIN)" >&2; exit 2; }
if (( RESUME )); then
  [[ -n "$OUT" && -f "$OUT/run.env" ]] || { echo "--resume needs --out DIR of an earlier run (DIR/run.env)" >&2; exit 2; }
  OUT="$(cd "$OUT" && pwd)"
  # shellcheck disable=SC1091
  source "$OUT/run.env"
else
  [[ -n "$OUT" && -n "$REPORTS" ]] || { echo "usage: $0 --out DIR --reports N [options]" >&2; exit 2; }
  [[ "$KEYS" == ceremony || "$KEYS" == keygen ]] || { echo "--keys is ceremony or keygen" >&2; exit 2; }
  [[ "$UPLOAD" == ciphertext || "$UPLOAD" == shares ]] || { echo "--upload is ciphertext or shares" >&2; exit 2; }
  [[ ! -e "$OUT/run.env" ]] || { echo "$OUT holds a run: continue it with --resume, or use another --out" >&2; exit 2; }
  mkdir -p "$OUT"
  OUT="$(cd "$OUT" && pwd)"
  TOKEN="$(openssl rand -hex 24)"
  SEAL0="$(openssl rand -hex 32)"
  SEAL1="$(openssl rand -hex 32)"
  # one dealer process holds both parties' secrets under one seal key
  [[ "$KEYS" == keygen ]] && SEAL1="$SEAL0"
fi
UPLOAD="${UPLOAD:-ciphertext}"

free_port() { python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()'; }

PIDS=()
cleanup() {
  for p in "${PIDS[@]:-}"; do
    [[ -n "$p" ]] && kill -TERM "$p" 2>/dev/null || true
  done
  for p in "${PIDS[@]:-}"; do
    [[ -n "$p" ]] && wait "$p" 2>/dev/null || true
  done
}
trap cleanup EXIT
# a signal ends the script through its EXIT trap, which stops every child
trap 'exit 130' INT
trap 'exit 143' TERM

log() { echo "[$(date -u +%H:%M:%S)] $*"; }

# Peak resident memory of a running process, from the kernel's high-water
# mark (VmHWM), sampled until it exits; printed in kB.
peak_rss() {
  local pid="$1" peak=0 v
  while v=$(awk '/^VmHWM:/ {print $2}' "/proc/$pid/status" 2>/dev/null) && [[ -n "$v" ]]; do
    (( v > peak )) && peak=$v
    sleep 1
  done
  echo "$peak"
}

if (( ! RESUME )); then
# ---- the machine this ran on ------------------------------------------------
{
  echo "date: $(date -u +%FT%TZ)"
  echo "nproc: $(nproc)"
  grep -m1 'model name' /proc/cpuinfo || true
  grep -E 'MemTotal|MemAvailable' /proc/meminfo
  echo "binary: $BIN"
  echo "args: reports=$REPORTS type=$TYPE min_batch=$MIN_BATCH min_cell=$MIN_CELL workers=$WORKERS invalid_every=$INVALID_EVERY seed=$SEED keys=$KEYS upload=$UPLOAD"
} > "$OUT/machine.txt"

# ---- TLS ----------------------------------------------------------------------
log "TLS material"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 2 \
  -subj "/CN=fhe-prio3 loadtest CA" -keyout "$OUT/ca.key" -out "$OUT/ca.pem" 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localhost" -keyout "$OUT/server.key" -out "$OUT/server.csr" 2>/dev/null
printf 'subjectAltName=DNS:localhost\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature\nextendedKeyUsage=serverAuth\n' > "$OUT/ext.cnf"
openssl x509 -req -in "$OUT/server.csr" -CA "$OUT/ca.pem" -CAkey "$OUT/ca.key" -CAcreateserial \
  -days 2 -extfile "$OUT/ext.cnf" -out "$OUT/leaf.pem" 2>/dev/null
cat "$OUT/leaf.pem" "$OUT/ca.pem" > "$OUT/server.pem"

# ---- task ------------------------------------------------------------------------
mkdir -p "$OUT/m0" "$OUT/m1"
UPLOAD_ARGS=()
if [[ "$UPLOAD" == shares ]]; then
  log "upload keys"
  U0="$(FHE_PRIO3_SEAL_KEY="$SEAL0" "$BIN" upload-key --out "$OUT/m0/upload.key")"
  U1="$(FHE_PRIO3_SEAL_KEY="$SEAL1" "$BIN" upload-key --out "$OUT/m1/upload.key")"
  UPLOAD_ARGS=(--upload shares --upload-keys "$U0,$U1")
fi
log "task"
"$BIN" task-config --out "$OUT/task.bin" --type "$TYPE" --aggregators 1 --mode silent \
  --topology split --min-batch "$MIN_BATCH" --min-cell "$MIN_CELL" "${UPLOAD_ARGS[@]}" | tee "$OUT/task.txt"

# ---- keys: party 0 = aggregator, party 1 = collector ---------------------
T0=$(date +%s)
if [[ "$KEYS" == ceremony ]]; then
  log "key ceremony (two processes)"
  {
    echo "# key party identity keys (0: aggregator, 1: collector)"
    FHE_PRIO3_SEAL_KEY="$SEAL0" "$BIN" init-identity --index 0 --out-dir "$OUT/m0"
    FHE_PRIO3_SEAL_KEY="$SEAL1" "$BIN" init-identity --index 1 --out-dir "$OUT/m1"
  } > "$OUT/aggregator-keys.txt"
  SESSION="$(openssl rand -hex 32)"
  CP0="$(free_port)"; CP1="$(free_port)"
  CURLS="https://localhost:$CP0,https://localhost:$CP1"
  start_ceremony() {
    local i="$1" port="$2" seal="$3"
    # exec: the background job's PID is the party's process itself
    FHE_PRIO3_SEAL_KEY="$seal" exec "$BIN" ceremony --task "$OUT/task.bin" --index "$i" \
      --identity "$OUT/m$i/aggregator-$i.identity.sealed" --aggregator-keys "$OUT/aggregator-keys.txt" \
      --session "$SESSION" --listen "127.0.0.1:$port" --aggregators "$CURLS" --token "$TOKEN" \
      --tls-cert "$OUT/server.pem" --tls-key "$OUT/server.key" --ca "$OUT/ca.pem" --out-dir "$OUT/m$i" \
      > "$OUT/m$i/ceremony.log" 2>&1
  }
  # tracked like the nodes: a party left waiting for a dead peer is stopped
  # on exit
  start_ceremony 0 "$CP0" "$SEAL0" & C0=$!; PIDS+=("$C0")
  start_ceremony 1 "$CP1" "$SEAL1" & C1=$!; PIDS+=("$C1")
  peak_rss "$C0" > "$OUT/m0/peak_rss_kb" & peak_rss "$C1" > "$OUT/m1/peak_rss_kb" &
  wait "$C0" || { echo "ceremony party 0 failed"; tail -20 "$OUT/m0/ceremony.log"; exit 1; }
  wait "$C1" || { echo "ceremony party 1 failed"; tail -20 "$OUT/m1/ceremony.log"; exit 1; }
  sleep 2
  echo "ceremony_peak_rss_kb: party0=$(cat "$OUT/m0/peak_rss_kb") party1=$(cat "$OUT/m1/peak_rss_kb")" >> "$OUT/machine.txt"
  cmp "$OUT/m0/material.bin" "$OUT/m1/material.bin"
  MATERIAL="$OUT/m0/material.bin"
else
  log "keys from one dealer process (keygen)"
  # one deployment key seals both shares
  SEAL1="$SEAL0"
  FHE_PRIO3_SEAL_KEY="$SEAL0" "$BIN" keygen --task "$OUT/task.bin" --out-dir "$OUT/keys" > "$OUT/keygen.log" 2>&1 &
  KG=$!; PIDS+=("$KG")
  peak_rss "$KG" > "$OUT/keygen_peak_rss_kb" &
  wait "$KG" || { echo "keygen failed"; tail -20 "$OUT/keygen.log"; exit 1; }
  sleep 2
  echo "keygen_peak_rss_kb: $(cat "$OUT/keygen_peak_rss_kb")" >> "$OUT/machine.txt"
  ln -sf "$OUT/keys/share-0.sealed" "$OUT/m0/share-0.sealed"
  ln -sf "$OUT/keys/share-1.sealed" "$OUT/m1/share-1.sealed"
  MATERIAL="$OUT/keys/material.bin"
fi
echo "keys_seconds: $(( $(date +%s) - T0 ))" >> "$OUT/machine.txt"
ls -l "$MATERIAL" >> "$OUT/machine.txt"
# what clients get: no evaluation keys
"$BIN" client-material --material "$MATERIAL" --out "$OUT/client-material.bin" | tee -a "$OUT/machine.txt"
# what --resume needs: the throwaway deployment's secrets and the arguments
( umask 077
  {
    printf 'TOKEN=%q\nSEAL0=%q\nSEAL1=%q\nMATERIAL=%q\nKEYS=%q\nUPLOAD=%q\n' "$TOKEN" "$SEAL0" "$SEAL1" "$MATERIAL" "$KEYS" "$UPLOAD"
    printf 'REPORTS=%q\nTYPE=%q\nMIN_BATCH=%q\nMIN_CELL=%q\nWORKERS=%q\nINVALID_EVERY=%q\nSEED=%q\n' \
      "$REPORTS" "$TYPE" "$MIN_BATCH" "$MIN_CELL" "$WORKERS" "$INVALID_EVERY" "$SEED"
  } > "$OUT/run.env" )
else
  log "resuming the run in $OUT"
  echo "resumed: $(date -u +%FT%TZ)" >> "$OUT/machine.txt"
fi
# one numbered set of client-side files per invocation
RUN=1
while [[ -e "$OUT/report-$RUN.json" || -e "$OUT/loadtest-$RUN.log" ]]; do RUN=$((RUN + 1)); done

# ---- nodes ---------------------------------------------------------------------
AP="$(free_port)"; CP="$(free_port)"; AM="$(free_port)"; CM="$(free_port)"
AGG_UPLOAD=() COL_UPLOAD=()
if [[ "$UPLOAD" == shares ]]; then
  AGG_UPLOAD=(--upload-key "$OUT/m0/upload.key")
  COL_UPLOAD=(--upload-key "$OUT/m1/upload.key")
fi
log "collector :$CP (metrics :$CM)"
# the collector uses the context and the joint public key only: it gets the
# client material (no evaluation keys)
FHE_PRIO3_SEAL_KEY="$SEAL1" "$BIN" collector --task "$OUT/task.bin" --material "$OUT/client-material.bin" \
  --key-share "$OUT/m1/share-1.sealed" --db "$OUT/collector.db" --listen "127.0.0.1:$CP" \
  --token "$TOKEN" --tls-cert "$OUT/server.pem" --tls-key "$OUT/server.key" \
  --metrics-listen "127.0.0.1:$CM" "${COL_UPLOAD[@]}" >> "$OUT/collector.log" 2>&1 &
COL_PID=$!; PIDS+=("$COL_PID")
log "aggregator :$AP (metrics :$AM)"
FHE_PRIO3_SEAL_KEY="$SEAL0" "$BIN" aggregator --index 0 --task "$OUT/task.bin" --material "$MATERIAL" \
  --share "$OUT/m0/share-0.sealed" --db "$OUT/aggregator.db" --listen "127.0.0.1:$AP" \
  --aggregators "https://localhost:$AP" --collectors "https://localhost:$CP" --token "$TOKEN" \
  --tls-cert "$OUT/server.pem" --tls-key "$OUT/server.key" --ca "$OUT/ca.pem" \
  --metrics-listen "127.0.0.1:$AM" "${AGG_UPLOAD[@]}" >> "$OUT/aggregator.log" 2>&1 &
AGG_PID=$!; PIDS+=("$AGG_PID")

wait_ready() {
  local name="$1" port="$2" pid="$3" deadline=$(( $(date +%s) + 900 ))
  until curl -sf "http://127.0.0.1:$port/readyz" > /dev/null; do
    kill -0 "$pid" 2>/dev/null || { echo "$name exited during start-up"; tail -20 "$OUT/$name.log"; exit 1; }
    (( $(date +%s) < deadline )) || { echo "$name not ready after 900 s"; exit 1; }
    sleep 2
  done
}
T0=$(date +%s)
wait_ready collector "$CM" "$COL_PID"
wait_ready aggregator "$AM" "$AGG_PID"
echo "node_startup_seconds[$RUN]: $(( $(date +%s) - T0 ))" >> "$OUT/machine.txt"
log "nodes ready"

# ---- load -------------------------------------------------------------------------
set +e
OMP_NUM_THREADS=1 "$BIN" loadtest --task "$OUT/task.bin" --material "$OUT/client-material.bin" \
  --leader "https://localhost:$AP" --ca "$OUT/ca.pem" --token "$TOKEN" \
  --reports "$REPORTS" --workers "$WORKERS" --seed "$SEED" --invalid-every "$INVALID_EVERY" \
  --metrics "aggregator=http://127.0.0.1:$AM" --metrics "collector=http://127.0.0.1:$CM" \
  --state-dir "$OUT/client-state" \
  --timeline "$OUT/timeline-$RUN.jsonl" --out "$OUT/report-$RUN.json" 2>&1 | tee "$OUT/loadtest-$RUN.log"
STATUS=${PIPESTATUS[0]}
set -e
[[ -f "$OUT/report-$RUN.json" ]] && cp "$OUT/report-$RUN.json" "$OUT/report.json"
{
  echo "loadtest_exit[$RUN]: $STATUS"
  ls -l "$OUT"/aggregator.db* "$OUT"/collector.db* 2>/dev/null || true
} >> "$OUT/machine.txt"
log "done (exit $STATUS); output in $OUT"
exit "$STATUS"
