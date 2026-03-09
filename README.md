# Security Checker

Windows 보안 구성 상태를 읽기 전용으로 점검하는 PowerShell 기반 프로젝트다. KISA 가이드를 기준으로 점검 결과를 JSON으로 저장하고, 웹 대시보드로 시각화한다.

현재 배포 기준은 `v1.0`이며, 실제 내용은 64개 항목 구현이다. 초기에 테스트용으로 사용한 20개 항목 버전은 `archive/test-v0/`로 분리해 기록만 남겼다.

## 폴더 구조

```text
Security_Checker/
├── config/      # 점검 정의 JSON
├── dashboard/   # 웹 대시보드 정적 자산
├── docs/        # 사용 가이드 및 아키텍처 문서
├── examples/    # 예제 결과 파일
├── scripts/     # 점검 및 올인원 실행 스크립트
├── tools/       # 대시보드 실행 도구
├── build/       # 패키징 스크립트
├── README.md
└── AGENTS.md
```

## 핵심 실행 경로

```powershell
# 현재 배포 기준 v1.0 (64개 항목) 점검
.\scripts\Invoke-SecurityCheck.ps1 -OutputPath ".\results.json"

# 대시보드 서버 실행
.\tools\Start-Dashboard.ps1 -Port 8080

# EXE 패키징
.\build\Build-Executable.ps1
```

## 아키텍처 요약

- `config/`: 점검 항목 메타데이터와 기대 상태를 정의한다.
- `scripts/`: 실제 Windows 보안 점검 로직과 결과 생성 책임을 가진다.
- `dashboard/`: 생성된 JSON 결과를 브라우저에서 분석할 수 있게 보여준다.
- `tools/`: 로컬 서버 실행처럼 개발 보조 기능을 제공한다.
- `build/`: 올인원 스크립트를 실행 파일 형태로 묶는다.
- `archive/test-v0/`: 20개 항목 테스트판을 기록용으로 보관한다.

자세한 설명은 [docs/ARCHITECTURE.md](./docs/ARCHITECTURE.md) 를 참고하면 된다.
