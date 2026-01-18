# Security Checker - AI Coding Agent Instructions

## Project Overview

**Security Checker** is a Windows security configuration audit tool based on KISA (Korean Internet & Security Agency) vulnerability assessment guidelines. It performs read-only security checks without modifying system settings, providing results via JSON output and an interactive web dashboard.

**Core Purpose**: Automated security compliance verification for Windows systems with zero-touch auditing and visualization.

## Architecture Overview

### Three-Layer Component Design

1. **Data Layer** (`check_definitions.json`)
   - Single JSON file containing 20+ security check definitions
   - Each check has metadata, PowerShell commands, severity, and compliance criteria
   - Enables decoupled check logic from execution logic
   - **Pattern**: Add new checks by extending JSON array (no code modification needed)

2. **Execution Layer** (`Invoke-SecurityCheck.ps1` or `SecurityChecker-AllInOne.ps1`)
   - Loads check definitions and executes via PowerShell functions (Test-W01, Test-W02, etc.)
   - Named convention: `Test-[CHECK_CODE]` (e.g., `Test-W04` for password complexity)
   - Returns standardized result objects with: item_code, status, current_state, expected_state
   - Distinguishes three check result types:
     - **Registry/Policy checks**: Return "양호" (good) or "관리 필요" (needs management)
     - **Manual review checks**: Return "수동 확인 필요" (manual review needed)
     - **Error checks**: Return "점검 불가" (check failed)

3. **Presentation Layer** (`dashboard.html/css/js`, `start_dashboard.py`)
   - Single-page web app that visualizes JSON scan results
   - Features: status filtering, category filtering, severity filtering, CSV export
   - Dashboard server runs on port 8080 (configurable)
   - Consumption pattern: Upload JSON file → displays charts and drill-down details

### Data Flow Example

```
Invoke-SecurityCheck.ps1
  ↓ (loads)
check_definitions.json
  ↓ (executes Test-W* functions)
PowerShell commands (e.g., net accounts, Get-LocalUser, Get-Service)
  ↓ (collects)
JSON result file
  ↓ (loads)
dashboard.html
  ↓ (visualizes)
User browser
```

## Critical Developer Workflows

### Running Security Checks

```powershell
# All checks to screen output
.\Invoke-SecurityCheck.ps1

# All checks to JSON file
.\Invoke-SecurityCheck.ps1 -OutputPath "result.json"

# Specific checks only
.\Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02","W-13"

# All-in-one: check + save + dashboard (single file)
.\SecurityChecker-AllInOne.ps1
```

### Building Standalone EXE

```powershell
# Automatic build with dependency resolution
.\Build-Executable.ps1

# Manual build (if PS2EXE module available)
Invoke-PS2EXE -InputFile "SecurityChecker-AllInOne.ps1" `
  -OutputFile "dist\SecurityChecker.exe"
```

### Web Dashboard Operation

```powershell
# Terminal 1: Run security check
.\Invoke-SecurityCheck.ps1 -OutputPath "my_scan.json"

# Terminal 2: Start dashboard (auto-opens browser)
.\Start-Dashboard.ps1 -Port 8080

# Browser: Upload JSON file via file picker
```

### Testing Execution Policy Issues

```powershell
# Immediate bypass (session only)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# Persistent bypass (not recommended for production)
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser
```

## Project-Specific Conventions

### Check Code Naming Scheme

- **Format**: `W-##` (Windows, two-digit number)
- **Categories**:
  - W-01 to W-03: Account management (계정 관리)
  - W-04 to W-09: Password policy (암호 정책)
  - W-10 to W-14: Services & sharing (서비스 및 공유)
  - W-15 to W-20: Firewall & defense (방화벽 및 방어)

### Result Status Values

Three discrete status categories used throughout:
- `양호` (Good) - compliant
- `관리 필요` (Needs Management) - non-compliant
- `수동 확인 필요` (Manual Review) - requires human assessment
- `부분 양호` (Partial Good) - mixed compliance
- `점검 불가` (Check Failed) - unable to verify
- `수동 검토 필요` (Manual Review) - alternative wording in some contexts

### JSON Output Schema

Every check result includes:
```json
{
  "item_code": "W-XX",
  "check_title": "Title in Korean",
  "status": "양호|관리 필요|수동 확인 필요",
  "current_state": "Actual system value",
  "expected_state": "Desired compliance state",
  "operational_meaning": "Why this matters for security",
  "severity": "상|중|하"
}
```

### Language Requirement

**Korean language throughout**:
- UI messages in Korean
- Check descriptions in Korean
- Status values in Korean (not English)
- Documentation in Korean
- Compliance is bidirectional (Korean ↔ English checks in registry/policy output)

## Integration Points & External Interfaces

### PowerShell Command Integration

- **Registry access**: Parses Windows registry via `net accounts`, `Get-ItemProperty`
- **Account info**: Uses `Get-LocalUser`, `Get-LocalGroup`
- **Service status**: Uses `Get-Service`, `Get-WmiObject`
- **Audit policy**: Parses `auditpol /get /category:*` output
- **Firewall**: Checks `NetSecurity` module functions

### Web Dashboard Dependencies

- **Python**: `http.server`, `socketserver` (no external deps)
- **JavaScript**: Vanilla JS + Chart.js (charting library)
- **Static files**: Must include dashboard.html, dashboard.css, dashboard.js alongside JSON output
- **Port requirement**: Dashboard listens on configurable TCP port (default 8080)

### Distribution Formats

1. **Source form**: Raw PowerShell + JSON files
2. **EXE form**: Packaged via PS2EXE module (requires WinRM setup)
3. **AllInOne form**: Single PS1 file with embedded check definitions

## Adding New Security Checks

### Step 1: Define in `check_definitions.json`

```json
{
  "item_code": "W-21",
  "category": "New Category",
  "check_title": "한글 제목",
  "check_type": "registry|account|policy",
  "severity": "상|중|하",
  "check_method": {
    "type": "powershell",
    "command": "Get-ItemProperty ..."
  },
  "expected_state": "권장 상태 설명",
  "operational_meaning": "보안상 의미 설명"
}
```

### Step 2: Implement in `Invoke-SecurityCheck.ps1`

```powershell
function Test-W21 {
    param($checkDef)
    try {
        # Execute check logic
        $result = Get-ItemProperty ...
        $status = if ($result -eq $expected) { "양호" } else { "관리 필요" }
        
        return @{
            item_code = "W-21"
            check_title = $checkDef.check_title
            status = $status
            current_state = "Current value: $result"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
    catch {
        return @{
            item_code = "W-21"
            status = "점검 불가"
            current_state = "오류: $_"
        }
    }
}
```

### Step 3: Register in Main Execution Loop

Add function call in `Invoke-SecurityCheck` or `SecurityChecker-AllInOne`:
```powershell
$result = Test-W21 $checkDefinition
$results += $result
```

## Key Files Reference

| File | Purpose | Modification Frequency |
|------|---------|----------------------|
| [check_definitions.json](check_definitions.json) | Check definitions | High (for new checks) |
| [Invoke-SecurityCheck.ps1](Invoke-SecurityCheck.ps1) | Modular check runner | High (new check functions) |
| [SecurityChecker-AllInOne.ps1](SecurityChecker-AllInOne.ps1) | Standalone executable | Low (feature freeze) |
| [dashboard.html/css/js](dashboard.html) | Web visualization | Medium (UI improvements) |
| [Build-Executable.ps1](Build-Executable.ps1) | EXE packaging | Low (maintenance only) |

## Common Tasks & Patterns

### Task: Add a new password policy check

1. Get policy value: `net accounts | Select-String "정책명"`
2. Parse regex: Extract number with `[int]$Matches[1]`
3. Compare to threshold: `if ($value -ge $threshold) { "양호" } else { "관리 필요" }`
4. Add Test-W## function and JSON entry

### Task: Fix a check that fails on some Windows versions

- Wrap PowerShell command in try-catch
- Add fallback registry query if `net accounts` fails
- Return "점검 불가" with error message if all methods fail
- Test on Windows 10, Windows 11, Windows Server 2016+

### Task: Add filtering to dashboard

- Modify `dashboard.js` filterResults() function
- Filter by status, category, severity, or custom property
- Update UI to show filter controls in dashboard.html
- Test with example_output.json sample data

---

**Last Updated**: 2026-01-17  
**Primary Language**: Korean (한국어)  
**Platform**: Windows 10, 11, Server 2016+  
**Runtime**: PowerShell 5.1+
