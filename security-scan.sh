#!/usr/bin/env bash
# CSE / internal security scan for windows-forensics (local Docker tools + optional PSScriptAnalyzer).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")" && pwd)"
OUT="${SECURITY_SCAN_OUT:-/tmp/windows-forensics-security-scan}"
DOCKER_HOST="${DOCKER_HOST:-unix://${HOME}/.colima/default/docker.sock}"
export DOCKER_HOST
export DOCKER_CONFIG="${DOCKER_CONFIG:-/tmp/docker-nocreds}"
mkdir -p "$OUT" "$DOCKER_CONFIG"
[[ -f "${DOCKER_CONFIG}/config.json" ]] || printf '%s\n' '{"auths":{}}' > "${DOCKER_CONFIG}/config.json"

if ! docker info >/dev/null 2>&1; then
  echo "ERROR: Docker unavailable (start Colima: colima start)" >&2
  exit 1
fi

echo "=== Gitleaks (git history) ===" | tee "$OUT/latest-gitleaks.txt"
docker run --rm -v "${ROOT}:/repo:ro" -w /repo zricethezav/gitleaks:v8.30.1 \
  detect --redact --source /repo 2>&1 | tee -a "$OUT/latest-gitleaks.txt" || true

echo "=== Trivy (repo secrets) ===" | tee "$OUT/latest-trivy-script.txt"
docker run --rm -v "${ROOT}:/repo:ro" -w /repo aquasec/trivy:0.71.2 fs \
  --scanners secret \
  --severity HIGH,CRITICAL,MEDIUM \
  . 2>&1 | tee -a "$OUT/latest-trivy-script.txt" || true

if command -v pwsh >/dev/null 2>&1 && pwsh -NoProfile -Command 'Get-Module -ListAvailable PSScriptAnalyzer' >/dev/null 2>&1; then
  echo "=== PSScriptAnalyzer (Invoke-WindowsForensics.ps1) ===" | tee "$OUT/latest-psscriptanalyzer.txt"
  pwsh -NoProfile -Command "
    Invoke-ScriptAnalyzer -Path '${ROOT}/Invoke-WindowsForensics.ps1' -Severity Warning,Error \
      -ExcludeRule PSAvoidUsingWriteHost \
      2>&1 | Format-List
  " 2>&1 | tee -a "$OUT/latest-psscriptanalyzer.txt" || true
else
  echo "SKIP PSScriptAnalyzer (pwsh + Install-Module PSScriptAnalyzer -Scope CurrentUser)" | tee "$OUT/latest-psscriptanalyzer.txt"
fi

echo ""
echo "Reports in ${OUT}"
echo "Documented exceptions: SECURITY-EXCEPTIONS.md"
echo "Amazon Git Security Scanner config: .security-scan/config.yaml (after cse init)"
