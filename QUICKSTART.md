# 빠른 시작 가이드

## 1분 안에 시작하기

### 1단계: 파일 확인

다음 파일들이 있는지 확인하세요:
- ✅ `check_definitions.json`
- ✅ `Invoke-SecurityCheck.ps1`

### 2단계: PowerShell 열기

**방법 1: 일반 사용자**
```
시작 메뉴 > "PowerShell" 검색 > Windows PowerShell 실행
```

**방법 2: 관리자 (권장)**
```
시작 메뉴 > "PowerShell" 검색 > 마우스 우클릭 > "관리자 권한으로 실행"
```

### 3단계: 폴더 이동

```powershell
cd "C:\Users\User\Desktop\Side Project\Check vulnerability"
```

### 4단계: 실행 정책 설정 (처음 한 번만)

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### 5단계: 검사 실행

```powershell
# 기본 실행 (화면에 결과 출력)
.\Invoke-SecurityCheck.ps1

# 결과를 파일로 저장
.\Invoke-SecurityCheck.ps1 -OutputPath "security_report.json"
```

## 자주 사용하는 명령어

### 모든 검사 실행 후 결과 저장
```powershell
.\Invoke-SecurityCheck.ps1 -OutputPath "report_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
```

### 특정 검사만 실행
```powershell
# 계정 관련 검사만
.\Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02","W-03","W-08","W-18"

# 암호 정책 검사만
.\Invoke-SecurityCheck.ps1 -CheckCodes "W-04","W-05","W-06","W-07"

# 주요 보안 설정만 (UAC, 방화벽, Defender)
.\Invoke-SecurityCheck.ps1 -CheckCodes "W-13","W-15","W-20"
```

### 결과를 보기 쉽게 정리해서 보기
```powershell
# JSON 파일을 읽어서 보기 좋게 출력
$result = Get-Content "security_report.json" | ConvertFrom-Json
$result.results | Format-Table item_code, check_title, status -AutoSize
```

## 실행 예시

```powershell
PS C:\Users\User\Desktop\Side Project\Check vulnerability> .\Invoke-SecurityCheck.ps1

================================================================================
Windows 보안 구성 검사 도구
KISA 기술적 취약점 분석·평가 방법 상세가이드 기반
================================================================================

검사 정의 파일 로딩 중...
✓ 20 개의 검사 항목 로드 완료

[W-01] Administrator 계정 이름 변경 검사 중... [양호]
[W-02] Guest 계정 비활성화 검사 중... [양호]
[W-03] 불필요한 계정 존재 여부 검사 중... [수동 확인 필요]
[W-04] 암호 복잡성 설정 검사 중... [양호]
[W-05] 암호 최소 길이 설정 검사 중... [양호]
...

================================================================================
검사 결과 요약
================================================================================
양호: 12 건
관리 필요: 5 건
수동 확인 필요: 2 건
부분 양호: 1 건

✓ 결과가 저장되었습니다: security_report.json
```

## 결과 해석

### 양호 🟢
보안 설정이 권장 사항을 충족합니다. 추가 조치 불필요.

### 관리 필요 🔴
보안 설정이 권장 사항을 충족하지 않습니다. **즉시 조치 필요**.

예시:
- Guest 계정이 활성화됨 → 비활성화 필요
- 암호 복잡성이 비활성화됨 → 활성화 필요
- UAC가 비활성화됨 → 활성화 필요

### 수동 확인 필요 🟡
자동으로 판단하기 어려운 항목입니다. **담당자가 직접 검토** 필요.

예시:
- 활성화된 계정 목록 → 각 계정이 필요한지 검토
- 실행 중인 서비스 목록 → 각 서비스가 필요한지 검토
- 관리자 그룹 구성원 → 각 구성원이 적절한지 검토

### 부분 양호 🟡
일부만 권장 사항을 충족합니다. **개선 권장**.

예시:
- 원격 데스크톱이 활성화되어 있지만 NLA 사용 중 → 가능하면 비활성화

### 점검 불가 ⚪
검사를 수행할 수 없습니다.

원인:
- 관리자 권한 부족
- 해당 기능이 시스템에 없음
- Windows 버전 불일치

## 일반적인 오류 해결

### "이 시스템에서 스크립트를 실행할 수 없으므로"

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
```

### "액세스가 거부되었습니다"

PowerShell을 **관리자 권한으로 실행**하세요.

### "JSON 파일을 찾을 수 없습니다"

스크립트와 같은 폴더에 `check_definitions.json` 파일이 있는지 확인하세요.

### "Get-LocalUser를 인식할 수 없습니다"

Windows PowerShell 5.1 이상이 필요합니다:
```powershell
$PSVersionTable.PSVersion
```

## 정기 검사 스케줄링

### Windows 작업 스케줄러 사용

매주 월요일 오전 9시에 자동 검사:

```powershell
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-ExecutionPolicy Bypass -File `"C:\Users\User\Desktop\Side Project\Check vulnerability\Invoke-SecurityCheck.ps1`" -OutputPath `"C:\SecurityReports\report_$(Get-Date -Format 'yyyyMMdd').json`""

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am

$principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest

Register-ScheduledTask -TaskName "WeeklySecurityCheck" -Action $action -Trigger $trigger -Principal $principal -Description "주간 보안 구성 검사"
```

## 다음 단계

1. **결과 검토**: 생성된 JSON 파일을 검토하세요
2. **조치 계획**: "관리 필요" 항목에 대한 조치 계획을 수립하세요
3. **정기 점검**: 주기적으로 검사를 실행하여 보안 상태를 모니터링하세요
4. **문서화**: 검사 결과와 조치 내역을 문서화하세요

## 도움말

더 자세한 정보는 `README.md` 파일을 참조하세요.
