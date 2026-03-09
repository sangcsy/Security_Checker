# 대시보드 빠른 실행

## 가장 간단한 방법

```powershell
.\tools\Start-Dashboard.ps1 -Port 8080
```

브라우저에서 다음 주소를 연다.

- `http://localhost:8080/dashboard/dashboard.html`

## 점검 결과 파일 만들기

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\my-scan.json"
```

그 다음 대시보드 화면에서 `my-scan.json` 을 업로드하면 된다.

## 필요한 파일

- `dashboard/dashboard.html`
- `dashboard/dashboard.css`
- `dashboard/dashboard.js`
- `config/check_definitions.json`

## 권장 방식

이 프로젝트는 Windows PowerShell 기반이므로 Python 서버 대신 `tools/Start-Dashboard.ps1` 사용을 권장한다.
