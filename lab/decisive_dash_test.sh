#!/usr/bin/env bash
# The one question that decides whether the en dash is a bug in Elastic's ruleset
# or a correct choice for their representation.
#
# Background. Entra Graph (/auditLogs/directoryAudits) returns:
#     'Update application – Certificates and secrets management '   EN DASH + trailing space
# SigmaHQ's merged rule (PR #6247, by descambiado) uses:
#     'Update application - Certificates and secrets management'        HYPHEN, no trailing space
# and a maintainer merged that, so the hyphen is presumably right for the
# representation SigmaHQ targets.
#
# Elastic's persistence_entra_id_application_credential_modification.toml (2020)
# also uses a HYPHEN, against azure.auditlogs.operation_name, which their Azure
# integration sources from the Event Hub / diagnostic-settings export.
#
# So: does the diagnostic-settings export carry the EN DASH like Graph, or the
# HYPHEN like both rules assume? Log Analytics is fed by that same export, so
# asking this workspace answers it.
#
# If HYPHEN  -> both rules are correct, there is NO finding, drop it.
# If EN DASH -> Elastic's rule cannot match, and the same class of bug that was
#               fixed in SigmaHQ is live in Elastic since 2020.
#
# Do not report either way until this has actually returned rows.
set -uo pipefail
WS="${WS:-$(az monitor log-analytics workspace show -g rg-detection-lab -n law-detection-lab --query customerId -o tsv 2>/dev/null)}"

echo "workspace: $WS"
echo
echo ">>> rows present at all?"
az monitor log-analytics query -w "$WS" --analytics-query "AuditLogs | count" -o tsv --only-show-errors 2>/dev/null | head -1

echo
echo ">>> every OperationName containing 'Certificates', with the separator decoded"
az monitor log-analytics query -w "$WS" --analytics-query \
"AuditLogs
| where OperationName has 'Certificates'
| extend sep = substring(OperationName, 18, 3)
| extend endsWithSpace = OperationName endswith ' '
| extend hasEnDash = OperationName contains '–'
| extend hasHyphen = OperationName contains '-'
| distinct OperationName, sep, endsWithSpace, hasEnDash, hasHyphen" -o json --only-show-errors 2>&1 | head -40

echo
echo ">>> does Elastic's exact literal match anything here?"
az monitor log-analytics query -w "$WS" --analytics-query \
"AuditLogs | where OperationName == 'Update application - Certificates and secrets management' | count" \
  -o tsv --only-show-errors 2>/dev/null | head -1
echo "   ^ 0 means Elastic's literal does not match this representation"

echo
echo ">>> and the en dash version?"
az monitor log-analytics query -w "$WS" --analytics-query \
"AuditLogs | where OperationName startswith 'Update application' and OperationName has 'Certificates' | count" \
  -o tsv --only-show-errors 2>/dev/null | head -1
