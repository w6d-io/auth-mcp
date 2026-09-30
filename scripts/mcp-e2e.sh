#!/usr/bin/env bash
# End-to-end acceptance test of the admin MCP (auth-mcp) in the auth-dev sandbox. Sandbox only:
# context example/dev-aws-1, namespace auth-dev (with its auth-dev-sandbox-marker ConfigMap).
#
# ── RUNBOOK ──────────────────────────────────────────────────────────────────────────────────────
# What the owner prepares (once per run):
#   1. kubectl on context example/dev-aws-1 with exec rights in auth-dev (your own credentials).
#      The script execs into auth-jinbe (Kratos/Hydra admin, with jinbe's own tokens, which never
#      leave the pod) and into auth-mcp (to call jinbe's delegation gate directly for A3).
#   2. The sandbox as the test expects it (the script checks what it can and stops otherwise):
#        - auth-mcp with MCP_READ_ONLY=false, and a jinbe with wave17/mcp-endpoints (bulk, email,
#          verification routes) and SITES_PRODUCTION off (publish applies directly);
#        - Settings → AI assistants: MCP on, and staff-support, staff-developers, staff-ops,
#          staff-security and super_admins allowed to use it;
#        - Kratos: recovery by link and TOTP enabled (sandbox steps 13 and earlier).
#   3. Sign in to https://kuma.authdev.dev.example.com WITH YOUR SECOND FACTOR, right before the
#      run, and copy the session cookie (devtools → Application → Cookies → .dev.example.com →
#      ory_kratos_session_sandbox):
#        read -rs E2E_OWNER_COOKIE && export E2E_OWNER_COOKIE="ory_kratos_session_sandbox=$E2E_OWNER_COOKIE"
#      That one cookie is the only manual step. It is used for: putting the role holders into their
#      staff-* groups (needs a second factor < 15 min old), minting your two test keys (admin, and
#      admin-noprotect without protected actions), reading group memberships for A3, and cleanup.
#      Keys for the four role holders are NOT made by you: the script creates each holder, opens a
#      Kratos recovery link for them, enrols an authenticator app whose secret exists only in the
#      script's memory, steps up to aal2 and lets the holder mint their own key (the fresh second
#      factor POST /api/me/api-keys requires). Prefer your own keys? export E2E_KEY_ADMIN and
#      E2E_KEY_ADMIN_NOPROTECT (stk_mcp_…); A11 revokes them at the end.
#
# How to run (from the auth-mcp repo; nothing is committed or pushed):
#   scripts/mcp-e2e.sh --dry-run            print the plan; calls nothing (no kubectl, no network)
#   scripts/mcp-e2e.sh                      run: guard → bindings → fixtures → cases → report → cleanup
#   scripts/mcp-e2e.sh --cleanup-only <id>  remove what run <id> left (fresh cookie in E2E_OWNER_COOKIE)
# Optional: E2E_EMAIL_DOMAIN (example.com), E2E_SITE_DOMAIN (dev.example.com; a zone must cover it),
# E2E_UPSTREAM (echo:auth-dev:80), E2E_RATE_LIMIT=on (run A10: 65 writes, ~1 min), E2E_SCRATCH (where state/report go).
#
# Expected duration: 8–12 min. Setup ~2 min (TOTP windows), recipes 3–5 min (publish waits for the
# apply, write budgets pace the calls), audit ≤ 2 min (Loki lag), rate limit + revocation ~2 min,
# cleanup ~1 min. Site and group deletion need your second factor < 15 min old at cleanup time: if
# cleanup reports leftovers, step up in kuma again and it asks for the new cookie (in a terminal), or
# run --cleanup-only later.
#
# Output: scratchpad/research/mcp-e2e-report-<run>.md (bound to the pod image digests and repo HEADs)
# and scratchpad/e2e/<run>/state.json (ids and names only; never a key, cookie, link or TOTP secret).
# Every object is named e2e-<utc ts>-* (identities, site) or mcpe_<ts as letters> (groups).
# ─────────────────────────────────────────────────────────────────────────────────────────────────
set -euo pipefail
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

CTX=example/dev-aws-1
NS=auth-dev
WS=${WS:-/Users/glider/.ghq/github.com/auth}
E2E_SCRATCH=${E2E_SCRATCH:-/private/tmp/claude-501/-Users-glider--ghq-github-com-auth/9e349111-2689-4f03-bb61-8cbccee8d2ad/scratchpad}
CLIENT=scripts/mcp-e2e-client.mjs

die() { echo "FAIL: $*" >&2; exit 1; }
ok() { echo "  ok: $*"; }
k() { kubectl --context="$CTX" -n "$NS" "$@"; }

usage() { sed -n '/^# How to run/,/^# Optional/p' "$SELF" | sed 's/^# \{0,1\}//'; exit "${1:-0}"; }

DRY=0; CLEANUP_ONLY=
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1 ;;
    --cleanup-only) CLEANUP_ONLY=${2:-}; [ -n "$CLEANUP_ONLY" ] || die "--cleanup-only needs a run id"; shift ;;
    -h|--help) usage ;;
    *) echo "unknown argument $1" >&2; usage 2 ;;
  esac
  shift
done

RUN=${CLEANUP_ONLY:-e2e-$(date -u +%Y%m%d%H%M%S)}
[[ "$RUN" =~ ^e2e-[0-9]{14}$ ]] || die "run id must look like e2e-YYYYmmddHHMMSS, got $RUN"
export E2E_RUN_ID=$RUN E2E_CONTEXT=$CTX E2E_NAMESPACE=$NS
export E2E_STATE_DIR="$E2E_SCRATCH/e2e/$RUN" E2E_REPORT_DIR="$E2E_SCRATCH/research"

if [ "$DRY" = 1 ]; then
  echo "DRY RUN — nothing is called. Run id would be $RUN."
  echo "Guard: current kube context must be $CTX; namespace $NS must hold ConfigMap auth-dev-sandbox-marker;"
  echo "       URLs must point at *.authdev.dev.example.com; E2E_OWNER_COOKIE must be set."
  echo "Bindings: pod imageIDs of auth-jinbe, auth-kuma, auth-mcp; auth-mcp env; git HEADs of jinbe, kuma, auth-mcp."
  echo "State: $E2E_STATE_DIR/state.json   Report: $E2E_REPORT_DIR/mcp-e2e-report-$RUN.md"
  echo
  node "$CLIENT" plan
  exit 0
fi

guard() {
  for t in kubectl node git; do command -v "$t" >/dev/null || die "missing tool $t"; done
  [ -d node_modules/@modelcontextprotocol/sdk ] || die "run npm ci in auth-mcp first (the client uses its MCP SDK)"
  [ "$(kubectl config current-context)" = "$CTX" ] || die "current kube context is $(kubectl config current-context), not $CTX — refusing"
  k get cm auth-dev-sandbox-marker >/dev/null 2>&1 || die "namespace $NS has no auth-dev-sandbox-marker ConfigMap — refusing"
  for u in "${E2E_MCP_URL:-https://mcp.authdev.dev.example.com/mcp}" "${E2E_JINBE_URL:-https://kuma.authdev.dev.example.com}" "${E2E_KRATOS_URL:-https://auth.authdev.dev.example.com}"; do
    [[ "$u" =~ ^https://[a-z0-9.-]+\.authdev\.dev\.example\.com(/|$) ]] || die "$u is not a sandbox (authdev) URL — refusing"
  done
  [ -n "${E2E_OWNER_COOKIE:-}" ] || die "E2E_OWNER_COOKIE is not set (see RUNBOOK step 3)"
  ok "context $CTX, marker in $NS, sandbox URLs, owner cookie present"
}

# name → {image, imageID, revision}: what really runs, from the pods (not the Deployment spec).
image_of() { # <label selector or name pattern> <container>
  local pod
  pod=$(k get pods --no-headers -o custom-columns=N:.metadata.name 2>/dev/null | grep -E "$1" | head -1 || true)
  [ -n "$pod" ] || { echo '{}'; return; }
  local img id rev=null
  img=$(k get pod "$pod" -o jsonpath="{.status.containerStatuses[?(@.name==\"$2\")].image}")
  id=$(k get pod "$pod" -o jsonpath="{.status.containerStatuses[?(@.name==\"$2\")].imageID}")
  if [ -z "$img" ]; then # container named otherwise: the first one
    img=$(k get pod "$pod" -o jsonpath='{.status.containerStatuses[0].image}')
    id=$(k get pod "$pod" -o jsonpath='{.status.containerStatuses[0].imageID}')
  fi
  if command -v crane >/dev/null && [ -n "$id" ]; then
    rev=$(crane config "${id#docker-pullable://}" 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const l=JSON.parse(s).config.Labels||{};console.log(JSON.stringify(l["org.opencontainers.image.revision"]||null))}catch{console.log("null")}})')
  fi
  [ -n "$rev" ] || rev=null
  node -e 'console.log(JSON.stringify({image:process.argv[1],imageID:process.argv[2],revision:JSON.parse(process.argv[3])}))' "$img" "$id" "$rev"
}
repo_of() {
  local d=$1
  [ -d "$d/.git" ] || { echo '{}'; return; }
  node -e 'console.log(JSON.stringify({head:process.argv[1]||null,branch:process.argv[2],dirty:process.argv[3]!=="0"}))' \
    "$(git -C "$d" rev-parse --short=12 HEAD 2>/dev/null || true)" "$(git -C "$d" branch --show-current 2>/dev/null)" "$(git -C "$d" status --porcelain 2>/dev/null | wc -l | tr -d ' ')"
}
bindings() {
  local mcpenv
  mcpenv=$(k get deploy auth-mcp -o json 2>/dev/null | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{const o={};try{for(const e of JSON.parse(s).spec.template.spec.containers[0].env||[])if(/^(MCP_READ_ONLY|MCP_ENABLED|RATE_|TOKEN_VERIFIER|MCP_EXPOSE)/.test(e.name))o[e.name]=e.value??"(from ref)"}catch{}console.log(JSON.stringify(o))})')
  E2E_BINDINGS=$(node -e 'const [c,n,j,ku,m,rj,rk,rm,e]=process.argv.slice(1);console.log(JSON.stringify({context:c,namespace:n,images:{jinbe:JSON.parse(j),kuma:JSON.parse(ku),mcp:JSON.parse(m)},repos:{jinbe:JSON.parse(rj),kuma:JSON.parse(rk),"auth-mcp":JSON.parse(rm)},mcpEnv:JSON.parse(e)}))' \
    "$CTX" "$NS" "$(image_of '^auth-jinbe-' jinbe)" "$(image_of '^auth-kuma-' kuma)" "$(image_of '^auth-mcp-' mcp)" \
    "$(repo_of "$WS/jinbe")" "$(repo_of "$WS/kuma")" "$(repo_of "$PWD")" "$mcpenv")
  export E2E_BINDINGS
  ok "bindings recorded (pod image digests, repo HEADs, auth-mcp env)"
  node -e 'const b=JSON.parse(process.env.E2E_BINDINGS);if(b.mcpEnv.MCP_READ_ONLY==="true"){console.error("FAIL: auth-mcp has MCP_READ_ONLY=true: no write tool can run");process.exit(1)}'
}

CLEANED=0
cleanup() {
  [ "$CLEANED" = 1 ] && return; CLEANED=1
  echo; echo "== cleanup ($RUN)"
  [ -f "$E2E_STATE_DIR/state.json" ] || { echo "  nothing was created"; return; }
  if ! node "$CLIENT" cleanup && [ -t 0 ]; then
    echo "  Leftovers usually mean your second factor is now older than 15 minutes."
    echo "  Step up in kuma (sign out/in with your second factor), then paste the new cookie value (hidden), or press Enter to skip:"
    local c; read -rs c || true
    if [ -n "$c" ]; then
      case "$c" in *=*) E2E_OWNER_COOKIE=$c ;; *) E2E_OWNER_COOKIE="ory_kratos_session_sandbox=$c" ;; esac
      export E2E_OWNER_COOKIE
      node "$CLIENT" cleanup || echo "  still left: run scripts/mcp-e2e.sh --cleanup-only $RUN later"
    fi
  fi
}

guard
if [ -n "$CLEANUP_ONLY" ]; then
  cleanup
  exit 0
fi
trap cleanup EXIT
trap 'exit 130' INT TERM
bindings
echo "== run $RUN (state $E2E_STATE_DIR)"
rc=0
node "$CLIENT" run || rc=$?
exit "$rc"
