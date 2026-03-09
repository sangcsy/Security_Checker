# Architecture

## 개요

이 프로젝트는 `정의`, `실행`, `표시`, `배포`를 분리한 구조다. 점검 항목 정의는 JSON에 두고, 실제 검사 로직은 PowerShell 스크립트에 두며, 결과 해석은 웹 대시보드가 맡는다.

## 계층별 책임

### 1. Definition Layer
- 위치: `config/`
- 파일: `check_definitions.json`
- 역할: 현재 배포 기준인 64개 항목 메타데이터를 보관한다.

### 2. Execution Layer
- 위치: `scripts/`
- 파일: `Invoke-SecurityCheck.ps1`
- 역할: Windows 계정, 정책, 레지스트리, 서비스 상태를 읽어서 표준 결과 객체로 변환한다.
- 특징: `Test-W##` 함수 단위로 점검이 분리돼 있다.

### 3. Presentation Layer
- 위치: `dashboard/`
- 파일: `dashboard.html`, `dashboard.css`, `dashboard.js`
- 역할: JSON 결과를 업로드받아 요약, 필터링, 상세 확인 기능을 제공한다.
- 참고: 점검 정의는 `../config/check_definitions.json` 에서 읽는다.

### 4. Tooling Layer
- 위치: `tools/`, `build/`
- 역할: 대시보드 로컬 서버 실행, EXE 패키징 같은 보조 작업을 담당한다.

### 5. Archive Layer
- 위치: `archive/test-v0/`
- 역할: 20개 항목 테스트판 스크립트와 구 정의 파일을 기록용으로 보관한다.

## 데이터 흐름

```text
config/check_definitions*.json
        ↓
scripts/Invoke-SecurityCheck*.ps1
        ↓
scan-result.json
        ↓
dashboard/dashboard.html
        ↓
사용자 브라우저
```

## 설계 원칙
- 읽기 전용 감사 유지
- 점검 정의와 실행 로직 분리
- 배포 스크립트와 운영 스크립트 분리
- 루트 최소화로 탐색 비용 감소

