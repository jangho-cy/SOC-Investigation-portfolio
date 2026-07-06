# SOC Investigation Portfolio

A collection of security operations investigations documenting my alert 
triage, analysis, and incident response process. Each case follows a 
consistent structure: alert summary, investigation timeline, evidence 
analysis, IOCs, MITRE ATT&CK mapping, verdict, and remediation.

## About

Digital forensics and threat intelligence analyst with 120+ completed 
investigations, transitioning that investigative experience into SOC 
operations. These reports apply structured investigation methodology to 
realistic SOC alert scenarios.

## Case Reports

| # | Case | Category | Key Techniques | Verdict | Report |
|---|------|----------|----------------|---------|--------|
| 001 | ClickFix Phishing – Lumma Stealer | Phishing / Malware | Mshta LOLBin, PowerShell obfuscation | True Positive | [Link](./cases/001-lumma-clickfix/case-001-clickfix-phishing.md) |

## Structure

Each case report includes:
- Alert triage and initial hypothesis
- Timeline reconstructed from multi-source logs
- Evidence analysis with fact/analysis separation
- Defanged IOCs and MITRE ATT&CK mapping
- Verdict with rationale, containment, and detection recommendations

---
*Investigations conducted in simulated SOC environments (LetsDefend). 
All indicators are from lab scenarios and sanitized for publication.*
