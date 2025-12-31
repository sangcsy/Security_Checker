# Windows 보안 구성 검사 도구

## 개요

이 도구는 **KISA(한국인터넷진흥원) 기술적 취약점 분석·평가 방법 상세가이드**를 기반으로 Windows 시스템의 보안 구성 상태를 검사하는 도구입니다.

### 주요 특징

- ✅ **읽기 전용 검사**: 시스템 설정을 변경하지 않고 현재 상태만 확인
- ✅ **KISA 가이드 기반**: 국내 보안 표준에 부합하는 검사 항목
- ✅ **데이터 기반 아키텍처**: 검사 로직과 정의가 분리되어 확장 용이
- ✅ **JSON 출력**: 결과를 표준 JSON 형식으로 제공
- ✅ **한글 지원**: 운영 담당자가 이해하기 쉬운 설명 제공

### 이 도구가 하는 일

- 계정 관리 정책 확인 (Administrator, Guest 계정 등)
- 암호 정책 검사 (복잡도, 길이, 사용 기간 등)
- 계정 잠금 정책 확인
- 감사 정책 검사
- 서비스 및 공유 설정 확인
- 보안 옵션 검증 (UAC, 원격 데스크톱 등)
- 방화벽 및 Windows Defender 상태 확인
- 업데이트 설정 확인

### 이 도구가 하지 않는 일

- ❌ 공격 또는 침투 테스트
- ❌ 취약점 악용 (exploitation)
- ❌ 무차별 대입 공격 (brute force)
- ❌ 권한 상승 시도
- ❌ 시스템 설정 변경

## 시스템 요구사항

- **운영체제**: Windows 10 / Windows 11 / Windows Server 2016 이상
- **PowerShell**: 5.1 이상
- **권한**: 일부 검사 항목은 관리자 권한 필요 (권장)

## 설치 방법

설치가 필요 없습니다. 필요한 파일만 다운로드하면 됩니다:

1. `check_definitions.json` - 검사 항목 정의
2. `Invoke-SecurityCheck.ps1` - 검사 실행 스크립트

## 사용 방법

### 기본 사용법

```powershell
# 모든 검사 항목 실행 (화면 출력)
.\Invoke-SecurityCheck.ps1

# 결과를 파일로 저장
.\Invoke-SecurityCheck.ps1 -OutputPath "result.json"

# 특정 검사 항목만 실행
.\Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02","W-13"
```

### 웹 대시보드 사용법 🌐

검사 결과를 시각화된 웹 대시보드에서 확인할 수 있습니다:

```powershell
# 1. 먼저 보안 검사 실행
.\Invoke-SecurityCheck.ps1 -OutputPath "scan_result.json"

# 2. 대시보드 서버 시작
.\Start-Dashboard.ps1

# 브라우저가 자동으로 열리면 JSON 파일을 업로드하세요
```

**대시보드 기능:**
- 📊 검사 결과 시각화 (차트, 그래프)
- 🔍 필터링 및 검색 기능
- 📋 상세 정보 보기
- 📥 CSV 내보내기

### 관리자 권한으로 실행

더 정확한 결과를 위해 관리자 권한으로 실행을 권장합니다:

```powershell
# PowerShell을 관리자 권한으로 실행 후
.\Invoke-SecurityCheck.ps1 -OutputPath "result.json"
```

### 실행 정책 설정

처음 실행 시 PowerShell 실행 정책 오류가 발생할 수 있습니다:

```powershell
# 현재 세션에만 적용 (권장)
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 또는 스크립트 서명 우회
PowerShell -ExecutionPolicy Bypass -File .\Invoke-SecurityCheck.ps1
```

## 출력 형식

### 콘솔 출력

검사 진행 상황과 결과 요약이 색상과 함께 표시됩니다:

- 🟢 **양호**: 보안 설정이 권장 사항을 충족
- 🔴 **관리 필요**: 보안 설정 개선 필요
- 🟡 **수동 확인 필요**: 추가 검토 필요
- 🟡 **부분 양호**: 일부만 충족
- ⚪ **점검 불가**: 검사 수행 불가 (권한 부족 등)

### JSON 출력

```json
{
  "metadata": {
    "scan_time": "2025-12-26 14:30:00",
    "computer_name": "DESKTOP-PC",
    "os_version": "Microsoft Windows NT 10.0.22631.0",
    "total_checks": 20,
    "based_on": "KISA 기술적 취약점 분석·평가 방법 상세가이드"
  },
  "summary": {
    "good": 12,
    "needs_management": 5,
    "manual_check": 2,
    "partial_good": 1,
    "check_failed": 0
  },
  "results": [
    {
      "item_code": "W-01",
      "check_title": "Administrator 계정 이름 변경",
      "status": "양호",
      "current_state": "현재 Administrator SID(-500) 계정 이름: SysAdmin",
      "expected_state": "Administrator가 아닌 다른 이름으로 변경됨",
      "operational_meaning": "기본 관리자 계정 이름을 변경하면 자동화된 공격 도구로부터 계정을 보호할 수 있습니다."
    }
  ]
}
```

## 검사 항목 목록

| 코드 | 카테고리 | 검사 항목 | 심각도 |
|------|----------|-----------|--------|
| W-01 | 계정 관리 | Administrator 계정 이름 변경 | 상 |
| W-02 | 계정 관리 | Guest 계정 비활성화 | 상 |
| W-03 | 계정 관리 | 불필요한 계정 존재 여부 | 중 |
| W-04 | 암호 정책 | 암호 복잡성 설정 | 상 |
| W-05 | 암호 정책 | 암호 최소 길이 설정 (8자 이상) | 상 |
| W-06 | 암호 정책 | 암호 최대 사용 기간 설정 (60일 이하) | 중 |
| W-07 | 암호 정책 | 암호 최소 사용 기간 설정 (1일 이상) | 하 |
| W-08 | 계정 관리 | 계정 잠금 임계값 설정 (5회 이하) | 상 |
| W-09 | 감사 정책 | 계정 로그온 이벤트 감사 | 중 |
| W-10 | 서비스 관리 | 불필요한 서비스 실행 여부 | 중 |
| W-11 | 공유 및 권한 | 공유 폴더 및 드라이브 존재 여부 | 상 |
| W-12 | 보안 옵션 | 원격 데스크톱 서비스 설정 | 상 |
| W-13 | 보안 옵션 | UAC (사용자 계정 컨트롤) 설정 | 상 |
| W-14 | 업데이트 및 패치 | Windows 업데이트 설정 | 상 |
| W-15 | 방화벽 | Windows 방화벽 설정 | 상 |
| W-16 | 보안 옵션 | 화면 보호기 설정 | 하 |
| W-17 | 보안 옵션 | 로그온 법적 고지 설정 | 하 |
| W-18 | 계정 관리 | 관리자 그룹 구성원 확인 | 상 |
| W-19 | 보안 옵션 | 이동식 미디어 자동 실행 비활성화 | 중 |
| W-20 | 보안 옵션 | Windows Defender 실시간 보호 | 상 |

## 아키텍처

### 파일 구조

```
Check vulnerability/
├── check_definitions.json      # 검사 항목 정의 (데이터)
├── Invoke-SecurityCheck.ps1    # 검사 실행 스크립트 (로직)
├── dashboard.html              # 웹 대시보드 (HTML)
├── dashboard.css               # 대시보드 스타일
├── dashboard.js                # 대시보드 로직
├── Start-Dashboard.ps1         # 대시보드 서버 시작 스크립트
├── QUICKSTART.md               # 빠른 시작 가이드
└── README.md                   # 문서
```

### 설계 원칙

1. **관심사의 분리 (Separation of Concerns)**
   - 검사 정의(`check_definitions.json`)와 검사 로직(`Invoke-SecurityCheck.ps1`)을 분리
   - 새로운 검사 항목 추가가 용이

2. **데이터 기반 (Data-Driven)**
   - JSON 파일로 검사 항목을 정의
   - 검사 로직 변경 없이 검사 항목 추가/수정 가능

3. **확장 가능성 (Extensibility)**
   - 각 검사 항목은 독립적인 함수로 구현
   - 새로운 검사 함수 추가 시 `$checkFunctions` 해시테이블에만 등록

4. **재사용성 (Reusability)**
   - 검사 로직을 함수로 모듈화
   - 다른 스크립트에서도 재사용 가능

## 검사 항목 추가 방법

### 1. 검사 정의 추가 (`check_definitions.json`)

```json
{
  "item_code": "W-21",
  "category": "새로운 카테고리",
  "check_title": "새로운 검사 항목",
  "description": "검사 항목 설명",
  "check_type": "registry",
  "severity": "상",
  "check_method": {
    "type": "powershell",
    "command": "검사 명령어"
  },
  "expected_state": "기대 상태",
  "compliance_criteria": {
    "good": "양호 조건",
    "bad": "취약 조건"
  },
  "operational_meaning": "운영 의미 설명"
}
```

### 2. 검사 함수 구현 (`Invoke-SecurityCheck.ps1`)

```powershell
function Test-W21 {
    param($checkDef)
    
    try {
        # 검사 로직 구현
        # ...
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "양호" # 또는 "관리 필요", "수동 확인 필요" 등
            current_state = "현재 상태 설명"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
    catch {
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "점검 불가"
            current_state = "오류: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}
```

### 3. 함수 매핑 등록

```powershell
$checkFunctions = @{
    # ... 기존 항목들 ...
    'W-21' = 'Test-W21'
}
```

## 보안 가이드 참고

이 도구는 다음 보안 가이드를 참고하여 개발되었습니다:

- **KISA 기술적 취약점 분석·평가 방법 상세가이드**
- CIS (Center for Internet Security) Benchmarks for Windows
- Microsoft Security Baseline
- NIST (National Institute of Standards and Technology) Guidelines

## 문제 해결

### 실행 정책 오류

```
이 시스템에서 스크립트를 실행할 수 없으므로...
```

**해결 방법:**
```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 관리자 권한 필요

일부 검사 항목은 관리자 권한이 필요합니다:

```powershell
# PowerShell을 마우스 우클릭 > "관리자 권한으로 실행"
```

### 검사 결과가 "점검 불가"

- 관리자 권한으로 실행했는지 확인
- Windows 버전이 지원되는지 확인
- 해당 기능이 시스템에 존재하는지 확인

## 주의사항

1. **읽기 전용**: 이 도구는 시스템 설정을 변경하지 않습니다
2. **보안 도구**: 공격 도구가 아닌 보안 검사 도구입니다
3. **정기 점검**: 주기적으로 실행하여 보안 상태를 모니터링하세요
4. **수동 검토**: 일부 항목은 자동 판단이 어려워 수동 검토가 필요합니다
5. **환경 고려**: 조직의 보안 정책에 맞게 결과를 해석하세요

## 라이선스

이 도구는 교육 및 보안 감사 목적으로만 사용되어야 합니다.

## 작성자

Security Operations Team

## 버전 정보

- **버전**: 1.0
- **최종 수정일**: 2025-12-26
- **기반**: KISA 기술적 취약점 분석·평가 방법 상세가이드

## 지원

문제가 발생하거나 개선 제안이 있으시면 이슈를 등록해주세요.
