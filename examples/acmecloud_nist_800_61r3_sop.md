# AcmeCloud Production Incident & NIST SP 800-61r3 Escalation SOP v2.4

## 1. Incident Classification & Federal Alignment {#NIST-800-61R3-S1.1}
[NIST-800-61R3-P1] Per NIST SP 800-61r3 (17 USC 105 US Federal Public Domain), a computer security incident is a violation or imminent threat of violation of computer security policies, acceptable use policies, or standard security practices.
[SOP-CLASS-1.2] AcmeCloud classifies production security events into three operational tiers: Severity-1 (active credential exfiltration or multi-tenant data exposure), Severity-2 (single-service degradation or anomalous internal token use), and Severity-3 (isolated policy non-compliance with zero egress).

## 2. Volatile Evidence Snapshot Before Revocation {#SOP-FORENSICS-2.1}
[SOP-FORENSICS-2.1] Before revoking any compromised IAM session token or terminating a suspect container, the on-call Incident Commander must snapshot cloud audit logs, memory state, and active network socket tables into an immutable write-once forensic bucket.
[SOP-FORENSICS-2.2] Every forensic snapshot must record its SHA-256 digest in the incident ticket within 10 minutes of collection to preserve chain-of-custody integrity.

## 3. Credential Isolation & Network Containment {#SOP-CONTAIN-3.1}
[SOP-CONTAIN-3.1] Once the forensic snapshot hash is recorded, rotate affected signing keys, revoke active OAuth refresh tokens, and apply a deny-all egress security group to the isolated workload.
[SOP-CONTAIN-3.2] Do not delete container images or local disk volumes during containment; detach volumes and tag them `FORENSIC_HOLD` for post-incident root-cause analysis.

## 4. Executive, Legal & Customer Escalation SLAs {#SOP-SLA-4.1}
[SOP-SLA-4.1] The Incident Commander must open an encrypted bridge channel (`#inc-sev1-bridge`) and page the Security Duty Officer immediately upon confirming a Severity-1 indicator.
[SOP-SLA-4.2] Severity-1 incidents require initial executive and legal escalation within 4 Hours of containment confirmation, including affected tenant IDs and forensic snapshot hashes.

## 5. Post-Incident Recovery & Lessons-Learned Gate {#NIST-800-61R3-S5.1}
[NIST-800-61R3-S5.1] Restoration to production traffic requires dual sign-off from the Incident Commander and Principal Security Engineer verifying that the root vulnerability vector is patched and regression-tested.
[SOP-POST-5.2] Conduct a blameless post-incident review within 5 business days and update linked training modules whenever an SOP paragraph hash changes.
