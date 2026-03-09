# Repository Guidelines

## 프로젝트 목적
- Windows 보안 구성 점검을 자동화하는 읽기 전용 감사 도구다.
- 시스템 설정을 수정하는 remediation 로직은 추가하지 않는다.
- 결과는 콘솔, JSON, 웹 대시보드로 제공한다.

## 폴더 구조
- `scripts/`: 점검 실행 스크립트와 올인원 배포 스크립트.
- `config/`: 현재 배포 기준 점검 정의 데이터.
- `archive/test-v0/`: 20개 항목 테스트판과 예전 정의 파일 보관.
- `dashboard/`: `dashboard.html`, `dashboard.css`, `dashboard.js`.
- `tools/`: 대시보드 로컬 서버 실행기.
- `build/`: EXE 패키징 스크립트.
- `docs/`: 빠른 시작, 배포, 아키텍처 문서.
- `examples/`: 샘플 JSON 출력.

## 작업 규칙
- PowerShell 함수 이름은 `Verb-Noun` 규칙을 유지한다.
- 점검 함수는 `Test-W##` 형식을 사용한다.
- 점검 ID `W-##` 와 JSON 정의를 항상 동기화한다.
- 결과 객체는 `item_code`, `status`, `current_state`, `expected_state` 를 일관되게 포함한다.
- 한국어 사용자 문구를 우선한다.

## 기본 명령
- 전체 점검: `./scripts/Invoke-SecurityCheck.ps1`
- 선택 점검: `./scripts/Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02"`
- 현재 배포용 v1.0 점검: `./scripts/Invoke-SecurityCheck.ps1`
- 대시보드 실행: `./tools/Start-Dashboard.ps1 -Port 8080`
- EXE 빌드: `./build/Build-Executable.ps1`

## 정리 기준
- `dist/`, 실제 점검 결과 JSON, `*.backup` 파일은 저장소에 남기지 않는다.
- 루트에는 프로젝트 진입 문서와 상위 폴더만 유지한다.
- 새 파일 추가 시 먼저 기존 폴더 책임에 맞는 위치를 선택한다.
