# Anomalous Non-Interactive Token Issuance After Interactive Sign-In (AiTM Pattern)

## Technique
**MITRE ATT&CK**: [T1539 — Steal Web Session Cookie](https://attack.mitre.org/techniques/T1539/) | [T1550 — Use Alternate Authentication Material](https://attack.mitre.org/techniques/T1550/)  
**Tactic**: Credential Access, Initial Access

## What the attacker is doing

In an AiTM (Adversary-in-the-Middle) phishing attack, the victim is directed to a reverse proxy that sits between them and a legitimate Microsoft login page. The victim completes real MFA against the real IdP. The proxy captures the session cookie issued on successful authentication.

The attacker then replays that cookie from their own infrastructure. From Entra ID's perspective, this looks like a non-interactive sign-in from a new IP — no password, no MFA challenge, because the session was already established.

The pattern this detection targets:

1. User authenticates interactively from IP `1.2.3.4` (ASN: Telefonica, for example)
2. Within 10 minutes, a non-interactive token is issued for the same user from IP `5.6.7.8` (ASN: DigitalOcean, Hetzner, or similar VPS provider)
3. No registered device is associated with the non-interactive sign-in

This is the fingerprint of a stolen session token being replayed, not a legitimate roaming scenario. Legitimate roaming (airplane mode, VPN toggle) rarely produces a different autonomous system in under 10 minutes.

## Why standard detections miss it

Most sign-in anomaly detections look at each sign-in event in isolation and compare it to a historical baseline for the user. AiTM token replay passes those checks because:

- No brute force, no spray — single successful sign-in
- Token is valid (was issued against real credentials + MFA)
- Non-interactive sign-ins often have lower signal fidelity in SIEM pipelines — many environments ingest SigninLogs but not AADNonInteractiveUserSignInLogs
- The time gap (under 10 minutes) is short enough that velocity rules don't fire

This detection joins the two log streams with a tight correlation window, making the IP/ASN divergence the signal rather than raw sign-in failure counts.

## Detection

### KQL (Microsoft Sentinel)

```kql
let timeframe = 1d;
let correlationWindow = 10m;
let InteractiveSessions =
    SigninLogs
    | where TimeGenerated >= ago(timeframe)
    | where ResultType == 0
    | where isnotempty(UserPrincipalName)
    | project
        InteractiveTime   = TimeGenerated,
        UserUpn           = tolower(UserPrincipalName),
        InteractiveIp     = IPAddress,
        InteractiveAsn    = AutonomousSystemNumber,
        InteractiveDevice = tostring(DeviceDetail.deviceId),
        SessionId         = CorrelationId;
AADNonInteractiveUserSignInLogs
| where TimeGenerated >= ago(timeframe)
| where ResultType == 0
| where isnotempty(UserPrincipalName)
| extend UserUpn = tolower(UserPrincipalName)
| join kind=inner InteractiveSessions on UserUpn
| where TimeGenerated between (InteractiveTime .. (InteractiveTime + correlationWindow))
| where IPAddress != InteractiveIp
| where AutonomousSystemNumber != InteractiveAsn
| where isempty(tostring(DeviceDetail.deviceId))
      or tostring(DeviceDetail.deviceId) != InteractiveDevice
| extend AccountName      = tostring(split(UserUpn, "@")[0])
| extend AccountUPNSuffix = tostring(split(UserUpn, "@")[1])
| project
    TimeGenerated,
    UserUpn,
    AccountName,
    AccountUPNSuffix,
    AppDisplayName,
    NonInteractiveIp  = IPAddress,
    NonInteractiveAsn = AutonomousSystemNumber,
    InteractiveIp,
    InteractiveAsn,
    InteractiveTime,
    SessionId,
    CorrelationId
| sort by TimeGenerated desc
```

**Contributed**: [Azure/Azure-Sentinel#14276](https://github.com/Azure/Azure-Sentinel/pull/14276)

## False Positives

- Users who connect interactively over a corporate VPN and then a background sync process reconnects over a split-tunnel or mobile data connection in the same window
- Automated pipelines that trigger token refreshes immediately after a user interactive sign-in from a different service node

**Analyst note**: The most reliable triage signal is the ASN. Legitimate roaming within the same carrier rarely changes ASN in under 10 minutes. An interactive sign-in from a residential ISP followed by a non-interactive token from a cloud hosting provider (AWS, Hetzner, DigitalOcean, OVH) is the classic AiTM fingerprint. Also check `AppDisplayName` — if the non-interactive token was issued to Exchange Online or SharePoint and the user did not use those apps interactively, treat it as high confidence.

## Investigation Steps

1. Confirm the interactive sign-in IP belongs to the user's known location or ISP
2. Geolocate and ASN-lookup the non-interactive IP — hosting providers are strong IOC
3. Review post-token activity: email forwarding rule creation, file downloads, inbox rule modifications via Unified Audit Log
4. Check if the user received a phishing email within 30 minutes before `InteractiveTime`
5. If confirmed: revoke all sessions (`Revoke-AzureADUserAllRefreshTokens` or Entra ID > User > Revoke sessions), reset password, review MFA methods for attacker-added authenticators

## References

- [Microsoft: Detect and respond to AiTM phishing](https://learn.microsoft.com/en-us/microsoft-365/security/defender/defender-aitm-protection)
- [MITRE T1539](https://attack.mitre.org/techniques/T1539/)
- [MITRE T1550](https://attack.mitre.org/techniques/T1550/)
