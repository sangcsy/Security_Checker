# 대시보드 가이드

## 목적

대시보드는 점검 결과 JSON을 업로드해 상태 요약, 필터링, 상세 확인을 할 수 있는 정적 웹 화면이다.

## 실행 순서

### 1. 점검 결과 생성

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\scan-result.json"
```

### 2. 대시보드 서버 실행

```powershell
.\tools\Start-Dashboard.ps1 -Port 8080
```

### 3. 브라우저에서 접속

- 주소: `http://localhost:8080/dashboard/dashboard.html`
- 화면에서 결과 JSON 파일을 업로드하면 된다.

## 주요 기능

- 상태별 결과 요약
- 카테고리, 상태 기준 필터링
- 점검 항목 상세 보기
- CSV 내보내기

## 관련 파일

- 대시보드 화면: `dashboard/dashboard.html`
- 스크립트: `dashboard/dashboard.js`
- 스타일: `dashboard/dashboard.css`
- 점검 정의: `config/check_definitions.json`
- 실행기: `tools/Start-Dashboard.ps1`

## 확인 포인트

- JSON 스키마가 예제와 크게 다르지 않은지 확인
- 필터링과 상세 보기 동작 확인
- CSV 내보내기 동작 확인
