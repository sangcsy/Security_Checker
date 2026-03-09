# 배포 가이드

## 배포 대상

이 프로젝트의 배포 대상은 올인원 스크립트 또는 EXE 패키지다. 로컬 개발용 도구는 배포 핵심 경로에 포함되지 않는다.

## EXE 빌드

```powershell
.\build\Build-Executable.ps1
```

빌드가 끝나면 `dist/` 아래에 EXE와 배포 폴더가 생성된다.

## 배포 구성

```text
dist/
└── SecurityChecker_v1.0/
    ├── SecurityChecker.exe
    ├── dashboard/
    │   ├── dashboard.html
    │   ├── dashboard.css
    │   └── dashboard.js
    ├── config/
    │   └── check_definitions.json
    └── README.txt
```

## 사용자 실행 흐름

1. `SecurityChecker.exe` 실행
2. 시스템 점검 수행
3. 결과 JSON 저장
4. 내장 웹서버로 대시보드 표시

## 참고 사항

- EXE는 `scripts/SecurityChecker-AllInOne.ps1` 기반이다.
- 대시보드 서버는 올인원 스크립트 내부 로직으로 실행된다.
- `tools/Start-Dashboard.ps1` 는 로컬 개발 확인용이다.

## 배포 전 체크리스트

- `config/check_definitions.json` 최신 여부 확인
- 대시보드 정적 파일 변경 반영 여부 확인
- 올인원 스크립트 버전 표기 확인
- 관리자 권한 필요 여부 문구 확인
