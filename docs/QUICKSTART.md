# Quickstart

## 1. 실행 정책 허용

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

## 2. 기본 점검 실행

```powershell
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\scan-result.json"
```

## 3. 현재 배포 기준 v1.0 실행

```powershell
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\scan-result.json"
```

## 4. 대시보드 실행

```powershell
.\tools\Start-Dashboard.ps1 -Port 8080
```

## 5. 결과 확인

- 주소: `http://localhost:8080/dashboard/dashboard.html`
- 생성한 JSON 파일을 업로드해 결과를 확인한다.
