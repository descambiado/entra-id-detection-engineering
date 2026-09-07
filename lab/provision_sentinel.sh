#!/usr/bin/env bash
# Provision a Log Analytics workspace with Sentinel, on the free Azure credit.
#
# The credit EXPIRES 2026-09-19. It is not a budget to spend, it is a door that
# closes. This tenant produces a few MB a day, so Log Analytics plus Sentinel
# costs on the order of 1 to 5 EUR a month. The number that matters is how many
# verified findings come out before the date, not how much of the credit is used.
#
# Safe to re-run: every step is idempotent and checks before creating.
set -euo pipefail

RG="${RG:-rg-detection-lab}"
LOC="${LOC:-westeurope}"          # European region, keeps data in the EU
WS="${WS:-law-detection-lab}"
RETENTION="${RETENTION:-30}"      # days. 30 is the free tier, do not raise it
QUOTA_GB="${QUOTA_GB:-0.5}"       # hard daily cap. Ingestion stops, no surprise bill

say() { printf '\n=== %s ===\n' "$1"; }

say "identity and subscription"
az account show --query "{subscription:name, id:id, user:user.name}" -o table

say "credit still alive?"
az consumption budget list -o table 2>/dev/null || \
  echo "(no budgets configured, this is informational only)"

say "resource group ${RG} in ${LOC}"
if az group show -n "$RG" -o none 2>/dev/null; then
  echo "already exists, not touching it"
else
  az group create -n "$RG" -l "$LOC" -o table
fi

say "Log Analytics workspace ${WS}"
if az monitor log-analytics workspace show -g "$RG" -n "$WS" -o none 2>/dev/null; then
  echo "already exists, not touching it"
else
  az monitor log-analytics workspace create \
      -g "$RG" -n "$WS" -l "$LOC" \
      --retention-time "$RETENTION" \
      --quota "$QUOTA_GB" \
      -o table
fi

say "daily ingestion cap, the thing that prevents a surprise bill"
az monitor log-analytics workspace show -g "$RG" -n "$WS" \
   --query "{name:name, retentionDays:retentionInDays, dailyQuotaGb:workspaceCapping.dailyQuotaGb}" -o table

say "workspace id, needed to point the Entra diagnostic setting at it"
az monitor log-analytics workspace show -g "$RG" -n "$WS" --query id -o tsv

cat <<'NEXT'

NEXT, and these two are deliberately NOT automated:

1. Sentinel onboarding needs the SecurityInsights solution on the workspace.
   Do it in the portal so you see what it turns on, and what it would cost.

2. Entra ID diagnostic settings: Entra admin center > Monitoring & health >
   Diagnostic settings > Add. Send AuditLogs and SignInLogs to the workspace
   above. Logs only start flowing AFTER this, and only forwards, never
   backwards. Nothing from before this moment will appear.

Then, and this is the whole point:

   the rules audit_rules.py marks LIKELY can be run as real KQL against real
   rows. A field that is genuinely absent returns zero, and "I ran it and it
   returned nothing" is a different class of evidence from "this field is not
   in the schema I read".

BEFORE 19/09, decide: move to pay-as-you-go or let it die. If it dies, export
first. A finding that only exists inside a workspace that gets switched off
does not exist.
NEXT
