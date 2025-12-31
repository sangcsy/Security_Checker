# 웹 대시보드 사용 가이드

## 🎯 대시보드 시작하기

### 1단계: 보안 검사 실행

먼저 PowerShell에서 보안 검사를 실행합니다:

```powershell
# 폴더로 이동
cd "C:\Users\User\Desktop\Side Project\Check vulnerability"

# 보안 검사 실행 및 결과 저장
.\Invoke-SecurityCheck.ps1 -OutputPath "my_scan_result.json"
```

### 2단계: 대시보드 서버 시작

```powershell
# 대시보드 서버 시작 (기본 포트: 8080)
.\Start-Dashboard.ps1

# 다른 포트를 사용하려면
.\Start-Dashboard.ps1 -Port 3000
```

서버가 시작되면 브라우저가 자동으로 열립니다!

### 3단계: JSON 파일 업로드

1. **"검사 결과 파일 선택"** 버튼 클릭
2. 생성된 JSON 파일 선택 (`my_scan_result.json`)
3. 대시보드에 결과가 자동으로 표시됩니다!

## 📊 대시보드 기능

### 1. 검사 결과 요약

상단에 한눈에 보이는 요약 카드:
- ✅ **양호**: 보안 설정이 권장 사항 충족
- ❌ **관리 필요**: 즉시 조치 필요
- ⚠️ **수동 확인 필요**: 담당자 검토 필요
- 🟡 **부분 양호**: 일부만 충족
- ⚪ **점검 불가**: 검사 불가

### 2. 시각화 차트

#### 상태별 분포 (도넛 차트)
- 각 상태별 비율을 한눈에 확인
- 마우스를 올리면 상세 정보 표시

#### 카테고리별 분포 (막대 차트)
- 계정 관리, 암호 정책, 보안 옵션 등
- 카테고리별 검사 항목 수 확인

### 3. 필터링 및 검색

검사 결과를 쉽게 찾을 수 있습니다:

- **상태 필터**: 특정 상태만 보기 (예: "관리 필요"만 표시)
- **카테고리 필터**: 특정 카테고리만 보기 (예: "암호 정책"만 표시)
- **심각도 필터**: 심각도별 필터링 (상/중/하)
- **검색**: 키워드로 검사 항목 검색

### 4. 상세 정보 보기

각 검사 항목의 **"상세보기"** 버튼을 클릭하면:
- 검사 코드 및 제목
- 현재 상태 vs 권장 상태
- 운영 의미 (왜 중요한가?)
- 상세 설명

### 5. CSV 내보내기

**"CSV 내보내기"** 버튼으로:
- 현재 필터링된 결과를 CSV로 저장
- Excel에서 열어서 분석 가능
- 보고서 작성에 활용

## 💡 사용 팁

### 팁 1: 관리가 필요한 항목만 보기

```
1. 상태 필터에서 "관리 필요" 선택
2. 심각도 필터에서 "상" 선택
3. 우선순위가 높은 항목만 표시됨
```

### 팁 2: 특정 카테고리 집중 검토

```
1. 카테고리 필터에서 "암호 정책" 선택
2. 암호 관련 설정만 집중 검토
```

### 팁 3: 빠른 검색

```
검색창에 키워드 입력:
- "Administrator" → 관리자 계정 관련 항목
- "암호" → 암호 관련 모든 항목
- "방화벽" → 방화벽 설정 항목
```

### 팁 4: 정기 검사 비교

여러 날짜에 검사를 실행하여 개선 사항 추적:

```powershell
# 매주 검사 실행
.\Invoke-SecurityCheck.ps1 -OutputPath "scan_2025-12-26.json"
.\Invoke-SecurityCheck.ps1 -OutputPath "scan_2026-01-02.json"

# 대시보드에서 각각 열어서 비교
```

## 🎨 대시보드 화면 구성

### 상단
- 제목 및 설명
- 파일 업로드 영역

### 메타데이터 섹션
- 검사 일시
- 컴퓨터 이름
- OS 버전
- 전체 검사 항목 수

### 요약 섹션
- 5개 상태별 카드
- 도넛 차트 (상태별 분포)
- 막대 차트 (카테고리별 분포)

### 필터 섹션
- 상태 / 카테고리 / 심각도 드롭다운
- 검색 입력창

### 상세 결과 테이블
- 검사 코드, 제목, 상태 등
- 각 행마다 "상세보기" 버튼
- CSV 내보내기 버튼

## 🔧 문제 해결

### 브라우저가 자동으로 열리지 않아요

수동으로 브라우저를 열고 주소창에 입력:
```
http://localhost:8080
```

### "포트가 이미 사용 중" 오류

다른 포트 번호를 사용하세요:
```powershell
.\Start-Dashboard.ps1 -Port 3000
```

### 서버를 종료하고 싶어요

PowerShell 창에서 **Ctrl + C** 키를 누르세요.

### JSON 파일이 로드되지 않아요

1. JSON 파일이 유효한지 확인
2. 파일이 `Invoke-SecurityCheck.ps1`로 생성되었는지 확인
3. 브라우저 콘솔(F12)에서 오류 확인

### 차트가 표시되지 않아요

인터넷 연결을 확인하세요 (Chart.js 라이브러리가 CDN에서 로드됨).

오프라인에서 사용하려면:
1. Chart.js를 다운로드
2. `dashboard.html`에서 CDN 링크를 로컬 파일로 변경

## 🚀 고급 사용법

### 여러 PC 검사 결과 비교

1. 여러 PC에서 검사 실행:
```powershell
# PC-A에서
.\Invoke-SecurityCheck.ps1 -OutputPath "scan_PC-A.json"

# PC-B에서
.\Invoke-SecurityCheck.ps1 -OutputPath "scan_PC-B.json"
```

2. 한 PC에 파일을 모아서 대시보드로 비교 분석

### 자동화된 정기 검사

Windows 작업 스케줄러로 자동 검사:
```powershell
# 매주 월요일 오전 9시 자동 검사
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" `
    -Argument "-File `"C:\...\Invoke-SecurityCheck.ps1`" -OutputPath `"C:\Reports\scan_$(Get-Date -Format 'yyyyMMdd').json`""

$trigger = New-ScheduledTaskTrigger -Weekly -DaysOfWeek Monday -At 9am

Register-ScheduledTask -TaskName "WeeklySecurity" -Action $action -Trigger $trigger
```

### 네트워크 공유로 결과 관리

```powershell
# 공유 폴더에 결과 저장
.\Invoke-SecurityCheck.ps1 -OutputPath "\\FileServer\SecurityReports\$env:COMPUTERNAME.json"
```

## 📱 브라우저 호환성

권장 브라우저:
- ✅ Google Chrome (최신 버전)
- ✅ Microsoft Edge (최신 버전)
- ✅ Firefox (최신 버전)
- ⚠️ Internet Explorer (지원 안 됨)

## 🎓 다음 단계

1. **정기 검사 설정**: 주기적으로 보안 상태 모니터링
2. **결과 분석**: "관리 필요" 항목부터 개선
3. **문서화**: 검사 결과 및 조치 내역 기록
4. **팀 공유**: 대시보드 URL을 팀원과 공유

## 📞 도움이 필요하신가요?

- 메인 문서: `README.md`
- 빠른 시작: `QUICKSTART.md`
- 검사 스크립트 도움말: `Get-Help .\Invoke-SecurityCheck.ps1 -Full`
