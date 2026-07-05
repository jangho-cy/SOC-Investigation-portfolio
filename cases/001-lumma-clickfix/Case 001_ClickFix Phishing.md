# SOC Investigation Case Report — Template & Example

> 이 파일은 두 부분으로 구성됨:
> **PART 1** = 빈 템플릿 + 각 항목 작성 가이드 (한국어 가이드는 실제 리포트에서 삭제)
> **PART 2** = 실제로 채운 영어 예시 (피싱 케이스) — 톤과 분량 참고용
>
> 스크린샷 규칙: LetsDefend 알림 상세/정답 화면 캡처 금지.
> 대신 로그 발췌(코드블록), IOC 테이블, 타임라인 표로 증거를 재구성.
> 본인이 주석을 단 분석 화면 1장까지는 OK (예: 이메일 헤더에 화살표 표시한 것).

---

# PART 1 — TEMPLATE

# Case 00X: [시나리오 설명형 제목 — 플랫폼 이름 X]

<!-- 제목 예시: "Phishing Investigation: Credential Harvesting via Spoofed Microsoft Login"
     나쁜 예: "LetsDefend SOC101 Alert #245" -->

| Field | Detail |
|---|---|
| **Case ID** | 001 |
| **Date of Investigation** | YYYY-MM-DD |
| **Analyst** | Jangho [성] |
| **Alert Source** | SIEM — [rule name 그대로] |
| **Severity (as triggered)** | Medium / High 등 |
| **Category** | Phishing / Malware / Unauthorized Access 등 |
| **Verdict** | ✅ True Positive / ❌ False Positive |

---

## 1. Alert Summary

<!-- 2~3문장. 어떤 룰이 왜 발화했는지. 알림 화면을 옮겨 적는 게 아니라
     "무슨 일이 벌어졌다고 시스템이 주장하는가"를 본인 말로 요약. -->

## 2. Initial Triage Questions

<!-- 차별화 포인트. 조사 시작 전 스스로에게 던진 질문 3~5개를 bullet로.
     "프로세스가 있는 분석가"임을 보여주는 섹션. 예:
     - Is the sender domain legitimate or newly registered?
     - Did the recipient interact with the payload (click/download/credentials)?
     - Are other users targeted by the same campaign? -->

## 3. Investigation Timeline

<!-- 표로. 시간은 로그 기준 UTC. 각 행 = 사건 or 조사 행위.
     이 표가 스크린샷 나열을 대체하는 핵심 장치. -->

| Time (UTC) | Event / Action | Source |
|---|---|---|
| 09:12 | Suspicious email delivered to user inbox | Email gateway log |
| 09:15 | User clicked embedded URL | Proxy log |
| 10:30 | Alert triggered; investigation started | SIEM |

## 4. Evidence & Analysis

<!-- 리포트의 본체. 소제목으로 나눠서 서술 + 로그 발췌.
     로그는 코드블록으로, 민감/플랫폼 고유 값은 일부 마스킹해도 됨.
     각 증거마다 "이게 무엇을 의미하는가" 해석 한 줄을 반드시 붙일 것.
     증거 나열이 아니라 추론 과정을 보여주는 게 목적. -->

### 4.1 Email Header Analysis
```
(관련 헤더 필드만 발췌 — Return-Path, SPF/DKIM/DMARC 결과 등)
```
**Analysis:** [이 헤더가 왜 수상한지 1~2문장]

### 4.2 URL / Payload Analysis
### 4.3 Endpoint / Log Analysis

## 5. Indicators of Compromise (IOCs)

| Type | Value | Context |
|---|---|---|
| Domain | `example-phish[.]com` | Credential harvesting page |
| IP | `203.0.113.45` | Hosting server |
| SHA-256 | `abc123...` | Attachment hash |

<!-- IOC는 defang 처리 (http → hxxp, . → [.]) — 실무 관례이자 디테일 어필 -->

## 6. MITRE ATT&CK Mapping

| Tactic | Technique | ID |
|---|---|---|
| Initial Access | Phishing: Spearphishing Link | T1566.002 |
| Credential Access | Input Capture | T1056 |

## 7. Verdict & Rationale

<!-- TP/FP 판정과 그 근거를 3~4문장으로. 면접에서 "왜 TP라고 판단했나"
     질문의 답이 되는 섹션. 반대 가설을 왜 기각했는지도 한 줄 넣으면 강함. -->

## 8. Scope Assessment

<!-- 영향 범위: 몇 명의 사용자, 몇 대의 호스트, 자격증명 유출 여부 등.
     "이 알림 하나"를 넘어 캠페인 전체를 봤다는 증거. -->

## 9. Containment & Remediation Actions

<!-- 취한/취해야 할 조치를 순서대로. 시뮬레이션 환경이라도
     "실제라면 이렇게 했을 것"을 적으면 됨. -->

## 10. Recommendations

<!-- Tier 2급 어필 섹션. 탐지 개선 제안 1~2개 포함:
     "이런 Sigma 룰/이메일 필터 규칙을 추가하면 유사 공격을 더 빨리 잡는다" -->

---
*Scenario source: LetsDefend SOC simulation environment. All indicators are from a simulated lab and sanitized for publication.*

---
---

# PART 2 — WORKED EXAMPLE (참고용 완성본)

# Case 001: Phishing Investigation — Credential Harvesting via Spoofed Microsoft 365 Login Page

| Field | Detail |
|---|---|
| **Case ID** | 001 |
| **Date of Investigation** | 2026-07-10 |
| **Analyst** | Jangho K. |
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
