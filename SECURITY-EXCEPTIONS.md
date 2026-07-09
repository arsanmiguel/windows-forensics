# Security exceptions — windows-forensics

Intentional design choices for this **Administrator-run diagnostic script**. Not a daemon or cloud deployment.

**Related:** [README.md](README.md)

---

## CSE / security scan handoff

**What this is:** PowerShell diagnostics (`Invoke-WindowsForensics.ps1`) for read-mostly Windows performance forensics, optional AWS Support case attachment. Legacy helper scripts (`ps-getperfcounters.ps1`, `Measure-DiskPerformance.ps1`) remain for standalone use but are not the primary entry point.

**Run local automated scans (Docker / Colima):**

```bash
colima start   # if needed
./security-scan.sh
```

Reports default to `/tmp/windows-forensics-security-scan/` (Gitleaks, Trivy on repo, optional PSScriptAnalyzer on the main script).

**Amazon Git Security Scanner (internal):** run `cse init` in this repo for `.security-scan/config.yaml`, then your team’s snapshot scanner for full agent review.

**Scope:**

| Path | Role |
|------|------|
| `Invoke-WindowsForensics.ps1` | Primary product |
| `ps-getperfcounters.ps1` | Legacy performance-counter collector |
| `Measure-DiskPerformance.ps1` | Legacy disk characterization helper |
| `README.md` | Operator docs (example IAM JSON is template only) |

**Before filing findings, read this doc.**

---

## Requires Administrator (by design)

**Design:** Full diagnostics require **Administrator** privileges (performance counters, storage WMI, disk tests, database probes). The main script warns and continues with reduced coverage if not elevated; `ps-getperfcounters.ps1` exits if not Administrator.

**Why:** Forensic/read-only system inspection on the host under investigation.

**Mitigation:** Run only on hosts you own; use `-Mode Quick` or `-Mode Standard` in production; reserve `-Mode Deep` for maintenance windows.

---

## AWS Support API (`-CreateSupportCase`)

**Design:** When `-CreateSupportCase` is set and AWS CLI is configured, the script calls `support:CreateCase` and attaches the report.

**Why:** Optional operator workflow; IAM policy in README is **customer-side** least-privilege example (`support:CreateCase`, attachments, communications only).

**Not in repo:** No embedded credentials. Uses ambient AWS CLI config on the host.

---

## Deep mode disk writes

**Design:** `-Mode Deep` and `-Mode DiskOnly` create multi-GB test files (default 1 GB; `-DiskTestSize` up to 100 GB).

**Why:** Explicit deep/disk modes; documented performance impact in README.

---

## Legacy helper scripts

**Design:** `ps-getperfcounters.ps1` and `Measure-DiskPerformance.ps1` predate the unified `Invoke-WindowsForensics.ps1` monolith. They write local output and may run disk I/O tests when invoked directly.

**Why:** Kept for operators who still use the slimmer scripts; README documents the unified script only.

---

## Hardening already in tree (not exceptions)

| Concern | Current behavior |
|---------|------------------|
| Predictable report filename | **Fixed** — random suffix via `GetRandomFileName()` in `Initialize-OutputFile` |
| Report file permissions | **Fixed** — ACL restricted to current user + SYSTEM on Windows |
| Dynamic command execution | **Fixed** — database probes use call operator (`& sqlcmd`, `& mysql`, etc.) instead of `Invoke-Expression` |

Re-run internal snapshot scan to confirm closure.

---

## Example IAM in README

README includes a **template** IAM policy JSON for AWS Support. It is documentation, not a deployed role in this repo.
