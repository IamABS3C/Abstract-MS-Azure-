#!/usr/bin/env bash
# Runs templates/destinations/scripts/sentinel-app-deploymentscript.sh against a stubbed
# Azure CLI (ci/stub-az) and checks the decisions that protect customers: which app it
# will reuse, which secret it will overwrite, and that a secret never reaches a command
# line. Nothing here talks to Azure. Exit 1 on the first failed case.
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
SCRIPT="$ROOT/templates/destinations/scripts/sentinel-app-deploymentscript.sh"
STUB="$ROOT/ci/stub-az"
WORK="$(mktemp -d)"; trap 'rm -rf "$WORK"' EXIT
FAIL=0
TAGGED='[{"appId":"app-1","tags":["abstract:sentinel-destination"]}]'
FUTURE="2099-01-01T00:00:00Z"

run() {  # run <name> <expected rc> <assertion> [VAR=value ...]
  local name=$1 want=$2 check=$3; shift 3
  rm -rf "$WORK/state"; mkdir -p "$WORK/state"; : > "$WORK/az.log"
  env -i PATH="$STUB:/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin" HOME="$WORK" \
    AZLOG="$WORK/az.log" STATE="$WORK/state" AZ_SCRIPTS_OUTPUT_PATH="$WORK/state/out.json" \
    APP_NAME=Abstract-Sentinel-App KEY_VAULT_MODE=Create KV_NAME=kv1 VAULT_URI=https://kv1.vault.azure.net/ \
    "$@" bash "$SCRIPT" > "$WORK/out.txt" 2>&1
  local rc=$?
  local sets resets deletes onargv
  sets=$(grep -c 'keyvault secret set' "$WORK/az.log"); resets=$(grep -c 'credential reset' "$WORK/az.log")
  deletes=$(grep -c 'credential delete' "$WORK/az.log"); onargv=$(grep -c 's3cr3t-value' "$WORK/az.log")
  if [ "$rc" -ne "$want" ] || [ "$onargv" -ne 0 ] || ! eval "$check"; then
    echo "FAIL $name (rc=$rc sets=$sets resets=$resets deletes=$deletes secret-on-argv=$onargv)"; sed 's/^/     /' "$WORK/out.txt" | tail -5; FAIL=1
  else
    echo "ok   $name"
  fi
}

run "new app: creates and stores a secret"       0 '[ $sets -eq 1 ] && [ $resets -eq 1 ]' APPS_JSON='[]' KV_SHOW=notfound
run "valid secret for this app: reused"          0 '[ $sets -eq 0 ] && [ $resets -eq 0 ]' APPS_JSON="$TAGGED" KV_SHOW="{\"appId\":\"app-1\",\"expires\":\"$FUTURE\"}" CREDS_JSON="[\"$FUTURE\"]"
run "secret of another app: refused"             1 '[ $sets -eq 0 ] && [ $resets -eq 0 ]' APPS_JSON="$TAGGED" KV_SHOW="{\"appId\":\"other\",\"expires\":\"$FUTURE\"}" CREDS_JSON="[\"$FUTURE\"]"
run "secret of another app, forced: refused"     1 '[ $sets -eq 0 ] && [ $resets -eq 0 ]' APPS_JSON="$TAGGED" KV_SHOW="{\"appId\":\"other\",\"expires\":\"$FUTURE\"}" FORCE_ROTATE=true
run "untagged secret: refused"                   1 '[ $sets -eq 0 ] && [ $resets -eq 0 ]' APPS_JSON="$TAGGED" KV_SHOW="{\"expires\":\"$FUTURE\"}"
run "untagged secret, forced: replaced"          0 '[ $sets -eq 1 ] && [ $resets -eq 1 ]' APPS_JSON="$TAGGED" KV_SHOW="{\"expires\":\"$FUTURE\"}" FORCE_ROTATE=true
run "same-named app without the tag: refused"    1 '[ $resets -eq 0 ]' APPS_JSON='[{"appId":"app-9","tags":[]}]'
run "two apps with the name: refused"            1 '[ $resets -eq 0 ]' APPS_JSON='[{"appId":"a","tags":["abstract:sentinel-destination"]},{"appId":"b","tags":[]}]'
run "Key Vault write fails: new credential removed" 1 '[ $deletes -eq 1 ]' APPS_JSON='[]' KV_SHOW=notfound KV_SET_FAIL=1 KEYS_BEFORE="k1" KEYS_AFTER="k1 k2"
exit $FAIL
