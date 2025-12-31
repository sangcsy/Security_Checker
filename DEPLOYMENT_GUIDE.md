# SecurityChecker 배포 가이드

## 📋 목차
- [빠른 시작](#빠른-시작)
- [EXE 파일 빌드](#exe-파일-빌드)
- [사용 방법](#사용-방법)
- [폴더 구조](#폴더-구조)
- [문제 해결](#문제-해결)
- [고급 설정](#고급-설정)

---

## 🚀 빠른 시작

### 사용자용 (EXE 실행)

1. **SecurityChecker.exe 더블클릭**
2. 보안 검사가 자동으로 시작됩니다
3. 완료 후 브라우저가 자동으로 열려 결과를 표시합니다

> **💡 팁**: 관리자 권한으로 실행하면 더 정확한 결과를 얻을 수 있습니다.

---

## 🔨 EXE 파일 빌드

### 사전 요구사항

- Windows 10 이상
- PowerShell 5.1 이상
- 인터넷 연결 (PS2EXE 모듈 설치 시)

### 빌드 방법

#### 방법 1: 자동 빌드 (권장)

```powershell
.\Build-Executable.ps1
```

빌드 스크립트가 자동으로:
1. PS2EXE 모듈 설치 여부 확인
2. 필요시 모듈 자동 설치
3. 필수 파일 확인
4. EXE 파일 생성
5. 배포 패키지 생성

#### 방법 2: 수동 빌드

```powershell
# 1. PS2EXE 모듈 설치
Install-Module -Name PS2EXE -Scope CurrentUser -Force

# 2. 모듈 가져오기
Import-Module PS2EXE

# 3. EXE 생성
Invoke-PS2EXE `
    -InputFile "SecurityChecker-AllInOne.ps1" `
    -OutputFile "dist\SecurityChecker.exe" `
    -NoConsole $false `
    -Title "Windows 보안 구성 검사 도구" `
    -Description "KISA 기술적 취약점 분석·평가 방법 상세가이드 기반" `
    -Version "2.0.0.0"
```

### 빌드 출력

빌드가 완료되면 다음 구조로 배포 패키지가 생성됩니다:

```
dist\
└── SecurityChecker_v2.0\
    ├── SecurityChecker.exe         # 실행 파일
    ├── dashboard\                  # 대시보드 리소스
    │   ├── dashboard.html
    │   ├── dashboard.css
    │   ├── dashboard.js
    │   └── check_definitions.json
    └── README.txt                  # 사용 안내
```

선택적으로 ZIP 파일도 생성됩니다:
```
dist\SecurityChecker_v2.0.zip
```

---

## 📘 사용 방법

### 기본 실행

```powershell
# EXE 실행
.\SecurityChecker.exe

# 또는 PowerShell 스크립트 실행
.\SecurityChecker-AllInOne.ps1
```

### 고급 옵션

```powershell
# 브라우저 자동 실행 건너뛰기
.\SecurityChecker-AllInOne.ps1 -SkipBrowser

# 관리자 권한 확인 강제
.\SecurityChecker-AllInOne.ps1 -AdminCheck
```

### 실행 흐름

```
1️⃣ [환경 초기화]
   ├─ 관리자 권한 확인
   └─ 결과 폴더 생성 (%APPDATA%\SecurityChecker\Results)

2️⃣ [보안 검사 수행]
   ├─ 20개 항목 검사 (W-01 ~ W-20)
   ├─ 실시간 진행률 표시
   └─ 각 항목별 결과 저장

3️⃣ [결과 저장]
   └─ JSON 파일 생성 (scan_20250130_143052.json)

4️⃣ [웹 서버 시작]
   ├─ 포트 8080-8089 중 사용 가능한 포트 선택
   └─ 로컬 HTTP 서버 시작

5️⃣ [대시보드 표시]
   ├─ 기본 브라우저 자동 실행
   ├─ 결과 파일 자동 로드
   └─ 시각화된 대시보드 표시
```

---

## 📂 폴더 구조

### 결과 파일 저장 위치

```
%APPDATA%\SecurityChecker\Results\
└── scan_YYYYMMDD_HHmmss.json
```

실제 경로 예시:
```
C:\Users\YourName\AppData\Roaming\SecurityChecker\Results\
```

### 결과 파일 형식

```json
{
  "metadata": {
    "scan_date": "2025-01-30 14:30:52",
    "hostname": "DESKTOP-ABC123",
    "os_version": "Windows 10 Pro 22H2",
    "script_version": "2.0"
  },
  "summary": {
    "total_checks": 20,
    "good": 12,
    "needs_management": 6,
    "manual_check": 2,
    "check_failed": 0
  },
  "results": [...]
}
```

---

## 🛠️ 문제 해결

### 문제 1: "PS2EXE 모듈을 찾을 수 없습니다"

**원인**: PS2EXE 모듈이 설치되지 않음

**해결**:
```powershell
Install-Module -Name PS2EXE -Scope CurrentUser -Force
```

### 문제 2: "스크립트 실행이 차단되었습니다"

**원인**: PowerShell 실행 정책

**해결**:
```powershell
# 현재 세션에서만 허용
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 또는 현재 사용자에 대해 영구 허용
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

### 문제 3: "포트 8080이 이미 사용 중입니다"

**원인**: 다른 프로그램이 해당 포트 사용 중

**해결**: 스크립트가 자동으로 8081-8089 포트로 시도합니다. 별도 조치 불필요.

수동으로 포트를 정리하려면:
```powershell
# 포트 사용 프로세스 확인
netstat -ano | findstr :8080

# 프로세스 종료 (PID 확인 후)
Stop-Process -Id <PID> -Force
```

### 문제 4: "관리자 권한이 필요합니다"

**원인**: 일부 검사는 관리자 권한 필요

**해결**:
1. 프로그램 우클릭
2. "관리자 권한으로 실행" 선택

### 문제 5: 브라우저가 자동으로 열리지 않습니다

**원인**: 기본 브라우저 설정 문제

**해결**:
1. 수동으로 브라우저 열기
2. 주소창에 입력: `http://localhost:8080/dashboard/dashboard.html`
3. 저장된 결과 파일 수동 업로드

---

## ⚙️ 고급 설정

### 사용자 지정 포트 설정

스크립트를 수정하여 포트 범위 변경:

```powershell
# SecurityChecker-AllInOne.ps1의 Start-EmbeddedWebServer 함수에서
$portRange = 8080..8089  # 원하는 범위로 변경
```

### 검사 항목 추가/수정

#### 1. 검사 정의 추가

`Get-CheckDefinitions` 함수에 새 항목 추가:

```powershell
@{
    item_code = "W-21"
    category = "새 카테고리"
    check_title = "새 검사 제목"
    severity = "상"
    expected_state = "예상되는 상태"
    operational_meaning = "운영상 의미"
}
```

#### 2. 검사 로직 구현

`Test-SecurityCheck` 함수에 새 케이스 추가:

```powershell
"W-21" {
    # 검사 로직 구현
    $result = # ... 검사 수행
    
    return @{
        item_code = $ItemCode
        check_title = $CheckDef.check_title
        status = "양호" # 또는 "관리 필요", "수동 점검", "점검 실패"
        current_state = "현재 상태"
        expected_state = $CheckDef.expected_state
        operational_meaning = $CheckDef.operational_meaning
    }
}
```

### 대시보드 커스터마이징

#### 색상 테마 변경

`dashboard\dashboard.css` 파일에서:

```css
:root {
    --primary-color: #4A90E2;      /* 기본 파란색 */
    --success-color: #27AE60;      /* 성공 녹색 */
    --warning-color: #F39C12;      /* 경고 주황색 */
    --danger-color: #E74C3C;       /* 위험 빨간색 */
    --background-color: #F5F7FA;   /* 배경색 */
}
```

#### 차트 설정 변경

`dashboard\dashboard.js` 파일에서:

```javascript
// 도넛 차트 옵션
statusChart = new Chart(statusCtx, {
    type: 'doughnut',
    options: {
        // 옵션 수정
    }
});
```

---

## 📦 배포 체크리스트

배포 전 확인 사항:

- [ ] 모든 필수 파일 존재 확인
  - [ ] SecurityChecker-AllInOne.ps1
  - [ ] dashboard.html
  - [ ] dashboard.css
  - [ ] dashboard.js
  - [ ] check_definitions.json
  
- [ ] 빌드 테스트
  - [ ] EXE 파일 정상 생성
  - [ ] 파일 크기 확인 (예상: 2-5MB)
  
- [ ] 기능 테스트
  - [ ] 보안 검사 실행
  - [ ] 결과 파일 생성 확인
  - [ ] 대시보드 표시 확인
  - [ ] 브라우저 자동 실행 확인
  
- [ ] 문서 준비
  - [ ] README.txt 포함
  - [ ] 사용자 가이드 준비
  
- [ ] 배포 패키지 생성
  - [ ] 폴더 압축 (ZIP)
  - [ ] 버전 정보 확인

---

## 🔄 업데이트 관리

### 버전 관리

버전 변경 시 수정할 파일:

1. **SecurityChecker-AllInOne.ps1**
   ```powershell
   $Global:ScriptVersion = "2.1"  # 버전 업데이트
   ```

2. **Build-Executable.ps1**
   ```powershell
   Version = "2.1.0.0"  # 버전 업데이트
   ```

3. **check_definitions.json**
   ```json
   "metadata": {
       "version": "2.1"
   }
   ```

### 변경 이력

| 버전 | 날짜 | 변경 내용 |
|------|------|-----------|
| 2.0 | 2025-12-30 | 올인원 실행 파일 구조로 전환 |
| 1.0 | 2025-12-26 | 초기 버전 (20개 검사 항목) |

---

## 📞 지원

### 문제 보고

문제 발생 시 다음 정보를 포함하여 보고:

1. Windows 버전
2. PowerShell 버전 (`$PSVersionTable` 결과)
3. 오류 메시지
4. 실행 로그
5. 결과 JSON 파일 (가능한 경우)

### 추가 리소스

- KISA 취약점 가이드: [KISA 공식 웹사이트]
- PowerShell 문서: https://docs.microsoft.com/powershell
- Chart.js 문서: https://www.chartjs.org/docs/

---

**© 2025 Security Operations Team**
