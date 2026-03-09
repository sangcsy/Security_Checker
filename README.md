# Security Checker

Windows 보안 구성 상태를 읽기 전용으로 점검하는 PowerShell 기반 프로젝트다. 현재 배포 기준은 `v1.0`이며 64개 항목 구현을 사용한다.

## 포함 파일

- `scripts/SecurityChecker-AllInOne.ps1`: 기본 실행 스크립트
- `scripts/Invoke-SecurityCheck.ps1`: 수동 점검 스크립트
- `config/check_definitions.json`: 64개 항목 정의
- `dashboard/`: 대시보드 정적 파일
- `tools/Start-Dashboard.ps1`: 수동 대시보드 실행기
- `build/Build-Executable.ps1`: EXE 패키징 스크립트

## 기본 실행

검사 완료 후 결과를 자동 저장하고, 대시보드를 바로 띄우는 기본 흐름이다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\SecurityChecker-AllInOne.ps1
```

특징:
- 검사 완료 후 결과 JSON 자동 저장
- 내장 웹서버 자동 실행
- 브라우저에서 결과 자동 로드
- `8080` 사용 중이면 다음 빈 포트로 자동 변경

## 수동 실행

필요할 때만 점검과 대시보드를 분리해서 사용할 수 있다.

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\results.json"
.\tools\Start-Dashboard.ps1 -Port 8080
```
