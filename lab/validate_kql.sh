#!/usr/bin/env bash
# Run Sigma rules as real KQL against real rows in Log Analytics.
#
# This is the step that upgrades a finding from "this field is not in the schema
# I read" to "I ran it against real data and it returned nothing". Those are
# different classes of evidence and only the second one survives a maintainer
# who disagrees with you about which representation the rule targets.
set -uo pipefail

WS="${WS:-$(az monitor log-analytics workspace show -g rg-detection-lab -n law-detection-lab --query customerId -o tsv 2>/dev/null)}"
[ -n "$WS" ] || { echo "no workspace"; exit 1; }

run() {
  local label="$1" q="$2"
  printf '\n--- %s ---\n' "$label"
  printf 'query: %s\n' "$q"
  local out
  out=$(az monitor log-analytics query -w "$WS" --analytics-query "$q" -o json --only-show-errors 2>&1)
  if echo "$out" | grep -qiE "BadArgumentError|SemanticError|Failed to resolve|SyntaxError"; then
    echo "RESULT: QUERY REJECTED BY KUSTO"
    echo "$out" | grep -oE "'[^']+' could not be resolved|Failed to resolve [a-z ]+ '[^']+'|SemanticError[^\"]{0,120}" | head -2
    return
  fi
  local n
  n=$(echo "$out" | python -c "import sys,json
try: print(len(json.load(sys.stdin)))
except Exception: print('?')" 2>/dev/null)
  echo "RESULT: $n row(s)"
  [ "$n" != "0" ] && [ "$n" != "?" ] && echo "$out" | head -c 600
}

echo "workspace: $WS"
echo "NOTE: rows only exist from the moment diagnostic settings were enabled."

run "control: is ANY data flowing yet?" \
    "AuditLogs | summarize rows=count(), earliest=min(TimeGenerated), latest=max(TimeGenerated)"

run "PR #6276 rule, as KQL. EXPECTED: fires" \
    "AuditLogs | where OperationName == 'Add owner to service principal' | project TimeGenerated, OperationName, Result, Identity"

run "azure_user_password_change.yml, the Status clause. EXPECTED: rejected, Status is not a column" \
    "AuditLogs | where Status == 'Success' | count"

run "same rule, the InitiatedBy=='UPN' clause with the CORRECT field name. EXPECTED: 0 rows" \
    "AuditLogs | where tostring(InitiatedBy) == 'UPN' | count"

run "what a real password reset actually looks like" \
    "AuditLogs | where Category == 'UserManagement' | project TimeGenerated, OperationName, Result | take 10"

run "azure_app_end_user_consent.yml flat field. EXPECTED: rejected, not a column" \
    "AuditLogs | where ConsentContext.IsAdminConsent == 'false' | count"
