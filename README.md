# Security Checker

Windows 보안 구성 상태를 읽기 전용으로 점검하는 PowerShell 기반 프로젝트다. 현재 배포 기준은 `v1.0`이며 64개 항목 구현을 사용한다.

## 포함 파일

- `scripts/Invoke-SecurityCheck.ps1`: 기본 점검 스크립트
- `scripts/SecurityChecker-AllInOne.ps1`: 올인원 배포 스크립트
- `config/check_definitions.json`: 64개 항목 정의
- `dashboard/`: 대시보드 정적 파일
- `tools/Start-Dashboard.ps1`: 로컬 대시보드 실행기
- `build/Build-Executable.ps1`: EXE 패키징 스크립트

## 실행

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\results.json"
.\tools\Start-Dashboard.ps1 -Port 8080
```

대시보드 주소:
- `http://localhost:8080/dashboard/dashboard.html`
