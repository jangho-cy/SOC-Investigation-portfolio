# Case 001: Phishing Investigation — Credential Harvesting via Spoofed Microsoft 365 Login Page

| Field | Detail |
|---|---|
| **Case ID** | 001 |
| **Date of Investigation** | 2026-07-05 |
| **Analyst** | Jangho H. |
| **Alert Source** | SIEM — "Suspicious Email Detected: Possible Phishing" |
| **Severity (as triggered)** | Medium |
| **Category** | Phishing / Credential Harvesting |
| **Verdict** | ✅ True Positive |

## 1. Alert Summary

The email gateway flagged an inbound message to a finance department user, sent from a domain visually similar to a legitimate Microsoft service domain. The message urged the recipient to "verify account activity" via an embedded link. The alert fired on a combination of newly registered sender domain and URL reputation mismatch.

## 2. Initial Triage Questions

- Is the sender domain legitimate, spoofed, or a lookalike registration?
- Did the recipient click the link, and if so, did they submit credentials?
- Does the landing page attempt credential capture or payload delivery?
- Have other mailboxes in the organization received the same or similar messages?
- Are there post-click signs of account compromise (anomalous logins)?

## 3. Investigation Timeline

| Time (UTC) | Event / Action | Source |
|---|---|---|
| 08:47 | Email delivered to victim mailbox from `no-reply@micros0ft-account[.]com` | Email gateway log |
| 08:53 | Recipient clicked embedded URL | Proxy log |
| 08:54 | HTTP POST request to phishing domain observed (form submission) | Proxy log |
| 09:02 | Alert triggered in SIEM; assigned for triage | SIEM |
| 09:05–09:40 | Investigation: header analysis, URL detonation, log correlation | Analyst |
| 09:41 | Verdict recorded as True Positive; escalated for account containment | Case record |

## 4. Evidence & Analysis

### 4.1 Email Header Analysis

```
From: Microsoft Account Team <no-reply@micros0ft-account[.]com>
Return-Path: <bounce@micros0ft-account[.]com>
Authentication-Results: spf=fail; dkim=none; dmarc=fail
Received: from mail.micros0ft-account[.]com (203.0.113.45)
```

**Analysis:** The sender domain uses a zero ("0") substitution for "o" — a classic lookalike technique. All three email authentication checks (SPF, DKIM, DMARC) failed, confirming the message did not originate from Microsoft infrastructure. WHOIS lookup showed the domain was registered 4 days before the email was sent, a strong phishing indicator.

### 4.2 URL Analysis

The embedded link resolved to `hxxps://micros0ft-account[.]com/secure/login`. Detonation in a sandboxed browser showed a pixel-accurate clone of the Microsoft 365 login portal. The page source contained a form posting credentials to `/collect.php` on the same host — no legitimate authentication flow (no OAuth redirect, no microsoftonline.com involvement).

**Analysis:** The page exists solely to capture credentials. The absence of any redirect to legitimate Microsoft endpoints rules out a benign misconfiguration.

### 4.3 Proxy Log Correlation

```
08:53:12 GET  hxxps://micros0ft-account[.]com/secure/login  user=j.smith  status=200
08:54:03 POST hxxps://micros0ft-account[.]com/collect.php   user=j.smith  status=302  bytes_out=412
```

**Analysis:** The POST request with a non-trivial payload size (412 bytes) 51 seconds after page load indicates the user submitted the form. Credentials should be treated as compromised.

## 5. Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Domain | `micros0ft-account[.]com` | Lookalike phishing domain, registered 2026-07-06 |
| IP | `203.0.113.45` | Hosting server for phishing page and mail origin |
| URL | `hxxps://micros0ft-account[.]com/secure/login` | Credential harvesting page |
| Email | `no-reply@micros0ft-account[.]com` | Sender address |

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Credential Access | Input Capture: Web Portal Capture | T1056.003 |

## 7. Verdict & Rationale

**True Positive.** Three independent lines of evidence converge: (1) failed SPF/DKIM/DMARC on a 4-day-old lookalike domain, (2) a cloned login page posting credentials to a local PHP endpoint with no legitimate authentication flow, and (3) proxy logs confirming the victim submitted the form. The alternative hypothesis — a legitimate but misconfigured Microsoft notification — is ruled out by the domain registration date and the credential collection endpoint.

## 8. Scope Assessment

Email gateway search for the sender domain returned **3 additional recipients** in the same organization; none clicked based on proxy logs. One user (j.smith) submitted credentials and requires immediate containment. No anomalous logins were observed yet for the affected account at the time of investigation, suggesting a window for preemptive action.

## 9. Containment & Remediation Actions

1. Force password reset and revoke active sessions for the affected account.
2. Enable/verify MFA on the affected account.
3. Purge the phishing email from all 4 recipient mailboxes.
4. Block the domain and IP at the email gateway, proxy, and firewall.
5. Notify affected users and monitor the account for anomalous authentication for 14 days.

## 10. Recommendations

- **Detection improvement:** Add a rule flagging inbound mail where the sender domain was registered within the last 30 days (newly registered domain feed integration). This would have caught the message pre-delivery rather than post-click.
- **User-facing control:** Deploy a banner on external emails containing login-related keywords ("verify", "account activity") to slow down reflexive clicks.

---
*Scenario source: LetsDefend SOC simulation environment. All indicators shown are from a simulated lab environment and have been sanitized for publication.*
