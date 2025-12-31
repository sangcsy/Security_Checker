# 대시보드 시작하는 가장 쉬운 방법

## 방법 1: 브라우저에서 직접 열기 (가장 쉬움!) ⭐

1. **dashboard.html** 파일을 더블클릭하거나
2. 파일을 마우스 우클릭 → "연결 프로그램" → Chrome 또는 Edge 선택

**주의**: 일부 브라우저에서는 로컬 파일 보안 정책으로 인해 `check_definitions.json`을 로드하지 못할 수 있습니다.

## 방법 2: Python 간단 서버 (권장)

Python이 설치되어 있다면:

```powershell
# PowerShell에서
cd "C:\Users\User\Desktop\Side Project\Check vulnerability"
python -m http.server 8080

# 브라우저에서 열기
# http://localhost:8080/dashboard.html
```

Python이 없다면: https://www.python.org/downloads/ 에서 다운로드

## 방법 3: VS Code Live Server 사용

VS Code가 설치되어 있다면:

1. VS Code에서 폴더 열기
2. "Live Server" 확장 설치
3. dashboard.html 파일에서 우클릭 → "Open with Live Server"

## 방법 4: Node.js http-server 사용

Node.js가 설치되어 있다면:

```powershell
# 전역 설치 (한 번만)
npm install -g http-server

# 서버 시작
cd "C:\Users\User\Desktop\Side Project\Check vulnerability"
http-server -p 8080

# 브라우저에서 열기
# http://localhost:8080/dashboard.html
```

## 빠른 테스트

먼저 예제 데이터로 테스트해보세요:

1. 대시보드를 엽니다 (위 방법 중 하나 사용)
2. **example_output.json** 파일을 업로드합니다
3. 대시보드 기능을 확인합니다!

## 실제 검사 실행

```powershell
# 실행 정책 설정
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass

# 보안 검사 실행
.\Invoke-SecurityCheck.ps1 -OutputPath "my_scan.json"

# 대시보드에서 my_scan.json 파일을 업로드
```

## 문제 해결

### Chrome에서 CORS 오류가 발생하는 경우

Chrome을 CORS 비활성화 모드로 실행:

```cmd
chrome.exe --allow-file-access-from-files
```

또는 로컬 서버를 사용하세요 (방법 2, 3, 4).

### 파일이 로드되지 않는 경우

모든 파일이 같은 폴더에 있는지 확인:
- dashboard.html
- dashboard.css
- dashboard.js
- check_definitions.json

## 다음 단계

1. ✅ 대시보드가 열리면 예제 파일(example_output.json) 업로드
2. ✅ 모든 기능 확인 (차트, 필터, 검색, CSV 내보내기)
3. ✅ 실제 검사 실행 후 결과 확인
4. ✅ 정기적으로 검사 실행하여 보안 상태 모니터링

즐거운 보안 검사 되세요! 🛡️
