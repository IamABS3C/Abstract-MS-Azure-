#!/usr/bin/env bash
# =============================================================================
#  Abstract Security - committed-secret scan
#
#  These templates handle Event Hub SAS keys, storage keys and Entra client
#  secrets, so a leaked literal is the highest-consequence mistake available in
#  this repo. This fails the build on anything that looks like a real one, while
#  deliberately allowing the placeholders and ARM expressions that must be there.
#
#  A file rather than inline YAML on purpose: regexes full of quotes and braces
#  inside a YAML block scalar are a reliable way to break a workflow silently.
# =============================================================================
set -uo pipefail

ROOT="${1:-.}"
fail=0
EXCL=(--exclude-dir=.git --exclude-dir=.venv --exclude-dir=node_modules --exclude-dir=__pycache__)

report() { printf '::error::%s\n' "$*"; fail=1; }

echo "=== Event Hubs / Service Bus SharedAccessKey literals ==="
if grep -rIn "${EXCL[@]}" -E 'SharedAccessKey=[A-Za-z0-9+/]{20,}' "$ROOT"; then
  report "A SharedAccessKey literal is committed."
else
  echo "clean"
fi

echo "=== Storage AccountKey literals ==="
if grep -rIn "${EXCL[@]}" -E 'AccountKey=[A-Za-z0-9+/]{40,}' "$ROOT"; then
  report "A storage AccountKey literal is committed."
else
  echo "clean"
fi

# Inline secret assignments. Excluded on purpose:
#   "[...]"        ARM/Bicep expressions - the whole point is that the value is
#                  resolved at deploy time, not stored
#   <angle>        documentation placeholders
#   $VAR / @{...}  shell and Logic Apps references
#   secretText     the Graph response FIELD NAME, not a value
#
# "password" is deliberately NOT matched as a key. In createUiDefinition, a
# PasswordBox declares its LABELS as {"password": "...", "confirmPassword": "..."} -
# human-readable UI text, never a value. Matching it produced a false positive on
# solution/Package/createUiDefinition.json. secureString parameters are the real
# control for actual passwords, and those never carry a literal.
echo "=== inline clientSecret / password literals ==="
if grep -rIn "${EXCL[@]}" \
     -E '"(clientSecret|client_secret|secretValue|adminPassword|apiKey|api_key)"[[:space:]]*:[[:space:]]*"[^"<$@[][^"]{15,}"' "$ROOT" \
   | grep -viE 'example|placeholder|xxx+|redacted|your-|dummy|sample|secretText|changeme|\.md:'; then
  report "An inline secret value looks committed."
else
  echo "clean"
fi

echo "=== PEM private keys ==="
if grep -rIn "${EXCL[@]}" -E 'BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY' "$ROOT"; then
  report "A private key is committed."
else
  echo "clean"
fi

# Bare GUIDs are fine (tenant ids, role ids, sample subscription ids are all
# non-sensitive), so they are intentionally NOT flagged.

if [ "$fail" -eq 0 ]; then
  echo
  echo "No secret-shaped literals found."
fi
exit "$fail"
