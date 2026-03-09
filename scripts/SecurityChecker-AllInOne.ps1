<#
.SYNOPSIS
    Windows 보안 구성 검사 올인원 도구 (전체 64개 검사)

.DESCRIPTION
    KISA 기술적 취약점 분석·평가 방법 상세가이드 기반
    검사 수행 → 결과 저장 → 웹 대시보드 자동 실행
    
    단일 파일로 모든 기능 제공 (서버/네트워크 불필요)

.EXAMPLE
    .\SecurityChecker-AllInOne-Full.ps1
    
.NOTES
    버전: 1.0
    작성자: Security Checker (Lee SeungWon)
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipBrowser,
    
    [Parameter(Mandatory=$false)]
    [switch]$AdminCheck
)

$ErrorActionPreference = "Stop"
$Global:ScriptVersion = "1.0"
$Global:ResultsFolder = "$env:APPDATA\SecurityChecker\Results"
$Global:CurrentResultFile = ""

# ========================================
# 유틸리티 함수
# ========================================

function Write-Banner {
    $banner = @"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          Windows 보안 구성 검사 도구 v$Global:ScriptVersion      ║
║                                                                  ║
║          KISA 기술적 취약점 분석·평가 방법 상세가이드 기반       ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Initialize-Environment {
    Write-Host "[1/5] 환경 초기화 중..." -ForegroundColor Yellow
    
    # 결과 폴더 생성
    if (-not (Test-Path $Global:ResultsFolder)) {
        New-Item -ItemType Directory -Path $Global:ResultsFolder -Force | Out-Null
    }
    
    # 관리자 권한 확인
    if (-not (Test-Administrator)) {
        Write-Warning "⚠️  관리자 권한으로 실행하지 않았습니다."
        Write-Host "   일부 검사가 정확하지 않을 수 있습니다." -ForegroundColor Yellow
        
        if ($AdminCheck) {
            Write-Host ""
            $response = Read-Host "관리자 권한으로 다시 시작하시겠습니까? (Y/N)"
            if ($response -eq 'Y' -or $response -eq 'y') {
                Start-Process powershell -Verb RunAs -ArgumentList "-File `"$PSCommandPath`""
                exit
            }
        }
    }
    else {
        Write-Host "✓ 관리자 권한으로 실행 중" -ForegroundColor Green
    }
    
    Write-Host "✓ 환경 초기화 완료" -ForegroundColor Green
    Write-Host ""
}

# ========================================
# 검사 정의 (내장)
# ========================================

function Get-CheckDefinitions {
    return @{
        metadata = @{
            version = "1.0"
            based_on = "KISA 기술적 취약점 분석·평가 방법 상세가이드 (64개 항목)"
            target_os = "Windows"
            total_checks = 64
        }
        checks = @(
            @{ item_code = "W-01"; category = "계정 관리"; check_title = "Administrator 계정 이름 변경 등 보안성 강화"; severity = "상"; expected_state = "Administrator가 아닌 다른 이름으로 변경됨"; operational_meaning = "기본 관리자 계정 이름을 변경하면 자동화된 공격 도구로부터 계정을 보호할 수 있습니다." },
            @{ item_code = "W-02"; category = "계정 관리"; check_title = "Guest 계정 비활성화"; severity = "상"; expected_state = "Guest 계정이 비활성화되어 있음"; operational_meaning = "Guest 계정을 비활성화하여 인증되지 않은 사용자의 시스템 접근을 차단합니다." },
            @{ item_code = "W-03"; category = "계정 관리"; check_title = "불필요한 계정 제거"; severity = "상"; expected_state = "불필요한 계정이 존재하지 않음"; operational_meaning = "사용하지 않는 계정을 제거하여 공격 표면을 줄입니다." },
            @{ item_code = "W-04"; category = "계정 관리"; check_title = "계정 잠금 임계값 설정"; severity = "상"; expected_state = "계정 잠금 임계값이 5회 이하로 설정됨"; operational_meaning = "반복적인 로그인 시도를 제한하여 무차별 대입 공격을 차단합니다." },
            @{ item_code = "W-05"; category = "계정 관리"; check_title = "해독 가능한 암호화를 사용하여 암호 저장 해제"; severity = "상"; expected_state = "해독 가능한 암호화 사용 안 함"; operational_meaning = "암호를 명문으로 저장하지 않아 암호 도용을 방지합니다." },
            @{ item_code = "W-06"; category = "계정 관리"; check_title = "관리자 그룹에 최소한의 사용자 포함"; severity = "상"; expected_state = "관리자 그룹이 필요한 사용자만 포함"; operational_meaning = "관리자 권한을 최소화하여 악의적 사용을 방지합니다." },
            @{ item_code = "W-07"; category = "계정 관리"; check_title = "Everyone 사용 권한을 익명 사용자에게 적용"; severity = "중"; expected_state = "Everyone 권한이 익명 사용자에게 적용되지 않음"; operational_meaning = "과도한 권한 할당을 방지하여 보안을 강화합니다." },
            @{ item_code = "W-08"; category = "계정 관리"; check_title = "계정 잠금 기간 설정"; severity = "중"; expected_state = "계정 잠금 기간이 15분 이상으로 설정됨"; operational_meaning = "계정 잠금 기간을 설정하여 무차별 대입 공격에 대한 방어를 강화합니다." },
            @{ item_code = "W-09"; category = "계정 관리"; check_title = "비밀번호 관리정책 설정"; severity = "상"; expected_state = "암호 정책이 KISA 기준에 부합함"; operational_meaning = "강력한 암호 정책을 통해 암호 기반 공격을 방지합니다." },
            @{ item_code = "W-10"; category = "계정 관리"; check_title = "마지막 사용자 이름 표시 안 함"; severity = "중"; expected_state = "마지막 사용자 이름이 표시되지 않음"; operational_meaning = "로그인 화면에서 사용자 이름을 숨겨 계정 열거를 방지합니다." },
            @{ item_code = "W-11"; category = "계정 관리"; check_title = "로컬 로그온 허용"; severity = "중"; expected_state = "로컬 로그온이 적절히 통제됨"; operational_meaning = "로컬 로그온 권한을 제한하여 무단 접근을 방지합니다." },
            @{ item_code = "W-12"; category = "계정 관리"; check_title = "익명 SID/이름 변환 허용 해제"; severity = "중"; expected_state = "익명 SID/이름 변환이 비활성화됨"; operational_meaning = "익명 사용자의 계정 정보 접근을 차단합니다." },
            @{ item_code = "W-13"; category = "계정 관리"; check_title = "콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한"; severity = "중"; expected_state = "빈 암호 사용이 제한됨"; operational_meaning = "빈 암호 계정의 로컬 로그온을 방지합니다." },
            @{ item_code = "W-14"; category = "계정 관리"; check_title = "원격터미널 접속 가능한 사용자 그룹 제한"; severity = "중"; expected_state = "RDP 접근이 필요한 사용자만 허용"; operational_meaning = "원격 데스크톱 접근을 최소화하여 무단 접근을 차단합니다." },
            @{ item_code = "W-15"; category = "서비스 관리"; check_title = "사용자 개인키 사용 시 암호 입력"; severity = "상"; expected_state = "개인키 사용 시 암호 입력 필요"; operational_meaning = "개인키를 암호로 보호하여 키 도용을 방지합니다." },
            @{ item_code = "W-16"; category = "서비스 관리"; check_title = "공유 권한 및 사용자 그룹 설정"; severity = "상"; expected_state = "공유 권한이 최소 권한 원칙에 따라 설정됨"; operational_meaning = "공유 폴더 권한을 적절히 설정하여 무단 접근을 방지합니다." },
            @{ item_code = "W-17"; category = "서비스 관리"; check_title = "하드디스크 기본 공유 제거"; severity = "상"; expected_state = "C$, D$ 등 기본 공유가 제거됨"; operational_meaning = "기본 공유를 제거하여 네트워크 공격 표면을 줄입니다." },
            @{ item_code = "W-18"; category = "서비스 관리"; check_title = "불필요한 서비스 제거"; severity = "상"; expected_state = "업무상 필요한 서비스만 실행됨"; operational_meaning = "불필요한 서비스를 종료하여 공격 가능성을 줄입니다." },
            @{ item_code = "W-19"; category = "서비스 관리"; check_title = "불필요한 IIS 서비스 구동 점검"; severity = "상"; expected_state = "IIS가 필요한 경우에만 활성화됨"; operational_meaning = "IIS 웹 서비스를 최소화하여 웹 기반 공격을 줄입니다." },
            @{ item_code = "W-20"; category = "서비스 관리"; check_title = "NetBIOS 바인딩 서비스 구동 점검"; severity = "상"; expected_state = "NetBIOS가 필요한 경우에만 활성화됨"; operational_meaning = "NetBIOS 서비스를 비활성화하여 레거시 공격을 줄입니다." },
            @{ item_code = "W-21"; category = "서비스 관리"; check_title = "암호화되지 않는 FTP 서비스 비활성화"; severity = "상"; expected_state = "FTP 서비스가 비활성화되어 있음"; operational_meaning = "암호화되지 않은 FTP 대신 SFTP/FTPS 사용을 강제합니다." },
            @{ item_code = "W-22"; category = "서비스 관리"; check_title = "FTP 디렉토리 접근권한 설정"; severity = "상"; expected_state = "FTP 디렉토리 권한이 적절히 설정됨"; operational_meaning = "FTP 디렉토리 권한을 제한하여 데이터 유출을 방지합니다." },
            @{ item_code = "W-23"; category = "서비스 관리"; check_title = "공유 서비스에 대한 익명 접근 제한 설정"; severity = "상"; expected_state = "익명 접근이 제한됨"; operational_meaning = "익명 사용자의 공유 서비스 접근을 차단합니다." },
            @{ item_code = "W-24"; category = "서비스 관리"; check_title = "FTP 접근 제어 설정"; severity = "상"; expected_state = "FTP 접근 제어가 설정됨"; operational_meaning = "FTP 접근을 허용된 사용자로만 제한합니다." },
            @{ item_code = "W-25"; category = "서비스 관리"; check_title = "DNS Zone Transfer 설정"; severity = "상"; expected_state = "DNS Zone Transfer가 인증된 호스트만 가능"; operational_meaning = "DNS Zone Transfer를 제한하여 DNS 정보 유출을 방지합니다." },
            @{ item_code = "W-26"; category = "서비스 관리"; check_title = "RDS(Remote Data Services) 제거"; severity = "상"; expected_state = "RDS가 필요한 경우에만 활성화됨"; operational_meaning = "불필요한 RDS를 제거하여 원격 공격을 방지합니다." },
            @{ item_code = "W-27"; category = "서비스 관리"; check_title = "최신 Windows OS Build 버전 적용"; severity = "상"; expected_state = "최신 보안 패치가 적용됨"; operational_meaning = "최신 OS 버전으로 업데이트하여 알려진 취약점을 해결합니다." },
            @{ item_code = "W-28"; category = "서비스 관리"; check_title = "터미널 서비스 암호화 수준 설정"; severity = "중"; expected_state = "터미널 서비스 암호화가 활성화됨"; operational_meaning = "RDP 통신을 암호화하여 세션 스니핑을 방지합니다." },
            @{ item_code = "W-29"; category = "서비스 관리"; check_title = "불필요한 SNMP 서비스 구동 점검"; severity = "중"; expected_state = "SNMP가 필요한 경우에만 활성화됨"; operational_meaning = "SNMP 서비스를 최소화하여 네트워크 관리 공격을 줄입니다." },
            @{ item_code = "W-30"; category = "서비스 관리"; check_title = "SNMP Community String 복잡성 설정"; severity = "중"; expected_state = "SNMP Community String이 강력하게 설정됨"; operational_meaning = "SNMP 커뮤니티 문자열을 보호하여 정보 유출을 방지합니다." },
            @{ item_code = "W-31"; category = "서비스 관리"; check_title = "SNMP Access control 설정"; severity = "중"; expected_state = "SNMP 접근이 제한됨"; operational_meaning = "SNMP 접근을 허용된 호스트로만 제한합니다." },
            @{ item_code = "W-32"; category = "서비스 관리"; check_title = "DNS 서비스 구동 점검"; severity = "중"; expected_state = "DNS가 필요한 경우에만 활성화됨"; operational_meaning = "DNS 서비스를 관리하여 DNS 기반 공격을 방지합니다." },
            @{ item_code = "W-33"; category = "서비스 관리"; check_title = "HTTP/FTP/SMTP 배너 차단"; severity = "하"; expected_state = "서비스 배너가 숨겨짐"; operational_meaning = "서버 정보 공개를 최소화하여 정찰 공격을 어렵게 합니다." },
            @{ item_code = "W-34"; category = "서비스 관리"; check_title = "Telnet 서비스 비활성화"; severity = "중"; expected_state = "Telnet 서비스가 비활성화됨"; operational_meaning = "암호화되지 않은 Telnet을 제거하여 통신 보안을 강화합니다." },
            @{ item_code = "W-35"; category = "서비스 관리"; check_title = "불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거"; severity = "중"; expected_state = "불필요한 ODBC/OLE-DB가 제거됨"; operational_meaning = "불필요한 데이터베이스 드라이버를 제거하여 공격 표면을 줄입니다." },
            @{ item_code = "W-36"; category = "서비스 관리"; check_title = "원격터미널 접속 타임아웃 설정"; severity = "중"; expected_state = "RDP 세션 타임아웃이 설정됨"; operational_meaning = "유휴 RDP 세션을 자동 종료하여 미인가 접근을 방지합니다." },
            @{ item_code = "W-37"; category = "서비스 관리"; check_title = "예약된 작업에 의심스러운 명령이 등록되어 있는지 점검"; severity = "중"; expected_state = "예약된 작업이 안전함"; operational_meaning = "악성 스케줄 작업의 실행을 방지합니다." },
            @{ item_code = "W-38"; category = "패치 관리"; check_title = "주기적 보안 패치 및 벤더 권고사항 적용"; severity = "상"; expected_state = "보안 패치가 최신 상태임"; operational_meaning = "정기적 패치 적용으로 알려진 취약점을 해결합니다." },
            @{ item_code = "W-39"; category = "패치 관리"; check_title = "백신 프로그램 업데이트"; severity = "상"; expected_state = "백신 정의가 최신 상태임"; operational_meaning = "최신 악성코드 정의로 맬웨어 감염을 방지합니다." },
            @{ item_code = "W-40"; category = "로그 관리"; check_title = "정책에 따른 시스템 로깅 설정"; severity = "중"; expected_state = "시스템 로깅이 정책에 따라 설정됨"; operational_meaning = "시스템 이벤트 로깅으로 보안 사건을 추적합니다." },
            @{ item_code = "W-41"; category = "로그 관리"; check_title = "NTP 및 시각 동기화 설정"; severity = "중"; expected_state = "시스템 시각이 NTP로 동기화됨"; operational_meaning = "정확한 시간 기록으로 로그 분석의 신뢰성을 보장합니다." },
            @{ item_code = "W-42"; category = "로그 관리"; check_title = "이벤트 로그 관리 설정"; severity = "하"; expected_state = "이벤트 로그 크기 및 보관 정책이 설정됨"; operational_meaning = "로그 관리 정책으로 로그 무결성을 보장합니다." },
            @{ item_code = "W-43"; category = "로그 관리"; check_title = "이벤트 로그 파일 접근 통제 설정"; severity = "중"; expected_state = "이벤트 로그 접근이 통제됨"; operational_meaning = "로그 파일 보호로 로그 위변조를 방지합니다." },
            @{ item_code = "W-44"; category = "보안 관리"; check_title = "원격으로 액세스할 수 있는 레지스트리 경로"; severity = "상"; expected_state = "레지스트리 원격 접근이 제한됨"; operational_meaning = "레지스트리 원격 접근을 제한하여 원격 공격을 방지합니다." },
            @{ item_code = "W-45"; category = "보안 관리"; check_title = "백신 프로그램 설치"; severity = "상"; expected_state = "백신 프로그램이 설치되고 활성화됨"; operational_meaning = "백신 프로그램으로 악성코드 감염을 방지합니다." },
            @{ item_code = "W-46"; category = "보안 관리"; check_title = "SAM 파일 접근 통제 설정"; severity = "상"; expected_state = "SAM 파일이 적절히 보호됨"; operational_meaning = "SAM 파일 보호로 비밀번호 도용을 방지합니다." },
            @{ item_code = "W-47"; category = "보안 관리"; check_title = "화면보호기 설정"; severity = "상"; expected_state = "화면보호기가 암호로 보호됨"; operational_meaning = "화면보호기 암호 설정으로 물리적 접근을 방지합니다." },
            @{ item_code = "W-48"; category = "보안 관리"; check_title = "로그온하지 않고 시스템 종료 허용"; severity = "상"; expected_state = "비로그인 사용자의 시스템 종료가 제한됨"; operational_meaning = "시스템 종료 권한을 제한하여 서비스 거부 공격을 방지합니다." },
            @{ item_code = "W-49"; category = "보안 관리"; check_title = "원격 시스템에서 강제로 시스템 종료"; severity = "상"; expected_state = "원격 강제 종료가 제한됨"; operational_meaning = "원격 종료 권한을 제한하여 가용성을 보장합니다." },
            @{ item_code = "W-50"; category = "보안 관리"; check_title = "보안 감사를 로그할 수 없는 경우 즉시 시스템 종료"; severity = "상"; expected_state = "감사 실패 시 시스템 종료 정책이 설정됨"; operational_meaning = "감사 로그 실패 시 시스템을 종료하여 감사 무효화를 방지합니다." },
            @{ item_code = "W-51"; category = "보안 관리"; check_title = "SAM 계정과 공유의 익명 열거 허용 안 함"; severity = "상"; expected_state = "익명 계정 열거가 비활성화됨"; operational_meaning = "익명 사용자의 계정 정보 열거를 차단합니다." },
            @{ item_code = "W-52"; category = "보안 관리"; check_title = "Autologon 기능 제어"; severity = "상"; expected_state = "자동 로그온이 비활성화됨"; operational_meaning = "자동 로그온 기능을 제거하여 무단 접근을 방지합니다." },
            @{ item_code = "W-53"; category = "보안 관리"; check_title = "이동식 미디어 포맷 및 꺼내기 허용"; severity = "상"; expected_state = "이동식 미디어 접근이 통제됨"; operational_meaning = "USB 등 이동식 미디어 접근을 제한하여 데이터 유출을 방지합니다." },
            @{ item_code = "W-54"; category = "보안 관리"; check_title = "DoS 공격 방어 레지스트리 설정"; severity = "중"; expected_state = "DoS 방어 레지스트리가 설정됨"; operational_meaning = "네트워크 기반 DoS 공격에 대한 방어를 강화합니다." },
            @{ item_code = "W-55"; category = "보안 관리"; check_title = "사용자가 프린터 드라이버를 설치할 수 없게 함"; severity = "중"; expected_state = "프린터 드라이버 설치가 제한됨"; operational_meaning = "악성 드라이버 설치로부터 시스템을 보호합니다." },
            @{ item_code = "W-56"; category = "보안 관리"; check_title = "SMB 세션 중단 관리 설정"; severity = "중"; expected_state = "SMB 세션 타임아웃이 설정됨"; operational_meaning = "유휴 SMB 세션을 자동 종료하여 접근 권한 악용을 방지합니다." },
            @{ item_code = "W-57"; category = "보안 관리"; check_title = "로그온 시 경고 메시지 설정"; severity = "하"; expected_state = "법적 고지 메시지가 표시됨"; operational_meaning = "로그온 경고로 무단 접근 시도자를 인식하게 합니다." },
            @{ item_code = "W-58"; category = "보안 관리"; check_title = "사용자별 홈 디렉터리 권한 설정"; severity = "중"; expected_state = "홈 디렉토리가 사용자만 접근 가능"; operational_meaning = "개인 홈 디렉토리를 보호하여 프라이버시를 보장합니다." },
            @{ item_code = "W-59"; category = "보안 관리"; check_title = "LAN Manager 인증 수준"; severity = "중"; expected_state = "LAN Manager가 비활성화되고 NTLMv2만 사용"; operational_meaning = "레거시 인증을 제거하여 인증 공격을 방지합니다." },
            @{ item_code = "W-60"; category = "보안 관리"; check_title = "보안 채널 데이터 디지털 암호화 또는 서명"; severity = "중"; expected_state = "보안 채널이 암호화 또는 서명으로 보호됨"; operational_meaning = "도메인 통신을 보호하여 중간자 공격을 방지합니다." },
            @{ item_code = "W-61"; category = "보안 관리"; check_title = "파일 및 디렉토리 보호"; severity = "중"; expected_state = "중요 파일이 ACL로 보호됨"; operational_meaning = "파일 권한 설정으로 무단 접근을 방지합니다." },
            @{ item_code = "W-62"; category = "보안 관리"; check_title = "시작프로그램 목록 분석"; severity = "중"; expected_state = "시작 프로그램이 필요한 것만 포함"; operational_meaning = "불필요한 시작 프로그램을 제거하여 성능과 보안을 강화합니다." },
            @{ item_code = "W-63"; category = "보안 관리"; check_title = "도메인 컨트롤러-사용자의 시간 동기화"; severity = "중"; expected_state = "시간이 도메인 컨트롤러와 동기화됨"; operational_meaning = "시간 동기화로 로그 무결성과 인증 신뢰성을 보장합니다." },
            @{ item_code = "W-64"; category = "보안 관리"; check_title = "윈도우 방화벽 설정"; severity = "중"; expected_state = "윈도우 방화벽이 활성화되고 규칙이 설정됨"; operational_meaning = "방화벽으로 비인가 네트워크 접근을 차단합니다." }
        )
    }
}

# ========================================
# 보안 검사 함수
# ========================================

function Test-SecurityCheck {
    param(
        [string]$ItemCode,
        [hashtable]$CheckDef
    )
    
    try {
        switch ($ItemCode) {
            "W-01" {
                ### Administrator 계정 이름 변경 등 보안성 강화
                # Administrator 계정 검색 (SID 끝 번호 -500)
                $adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}
                $adminName = $adminAccount.Name
                $status = if ($adminName -ne "Administrator") { "양호" } else { "관리 필요" }
                $currentState = "현재 Administrator SID(-500) 계정 이름: $adminName"
            }
            
            "W-02" {
                ### Guest 계정 비활성화
                # Guest 계정 존재 여부 파악 (이름으로 검색)
                $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
                if ($null -eq $guest) {
                    $status = "양호"
                    $currentState = "Guest 계정이 존재하지 않음"
                }
                # Guest 계정이 존재할 경우, Enabled 여부를 파악
                elseif ($guest.Enabled -eq $false) {
                    $status = "양호"
                    $currentState = "Guest 계정 비활성화"
                }
                else {
                    $status = "취약"
                    $currentState = "Guest 계정 활성화"
                }
            }
            
            "W-03" {
                ### 불필요한 계정 제거
                # 계정 목록 확인
                $enabledAccounts = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
                $userList = ($enabledAccounts | ForEach-Object { $_.Name }) -join ', '
                $status = "수동 확인 필요"
                $currentState = "활성화된 계정 ($($enabledAccounts.Count)개): $userList"
            }
            
            "W-04" {
                ### 계정 잠금 임계값 설정
                # 계정 잠금 임계값 확인
                $lockoutLine = net accounts | Select-String -Pattern "잠금 임계값"
                $lockoutThreshold = $lockoutLine.ToString().Split(':')[1].Trim()
                if ($lockoutThreshold -eq "아님") {
                    $status = "관리 필요"
                    $currentState = "계정 잠금 임계값이 설정되지 않음"
                }
                elseif ([int]$lockoutThreshold -le 5) {
                    $status = "양호"
                    $currentState = "계정 잠금 임계값: $lockoutThreshold"
                }
                else {
                    $status = "관리 필요"
                    $currentState = "계정 잠금 임계값: $lockoutThreshold"
                }
            }
            
            "W-05" {
                ### 해독 가능한 암호화를 사용하여 암호 저장 해제
                # '해독 가능한 암호화를 사용하여 암호 저장'(ClearTextPassword) 정책 확인
                $tempFile = "$env:temp\policy_$([System.Guid]::NewGuid()).inf"
                try {
                    secedit /export /cfg $tempFile 2>$null | Out-Null
                    if (Test-Path $tempFile) {
                        $textPassLine = Select-String -Path $tempFile -Pattern "ClearTextPassword" -ErrorAction SilentlyContinue
                        if ($null -ne $textPassLine) {
                            $clearTextPass = [int]($textPassLine.ToString().Split('=')[1].Trim())
                        }
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                    if ([int]$clearTextPass -eq 0) {
                        $status = "양호"
                        $currentState = "해독 가능한 암호화를 사용하여 암호 저장 정책: 사용 안 함 (0)"
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "해독 가능한 암호화를 사용하여 암호 저장 정책: 사용 (1)"
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "보안 정책 추출 실패 또는 권한 부족: $($_.Exception.Message)"
                }
            }
            
            "W-06" {
                ### 관리자 그룹에 최소한의 사용자 포함
                # 관리자 그룹 확인
                $adminLine = Get-LocalGroupMember Administrators
                $adminCount = 
                $adminName = ($adminLine | ForEach-Object {$_.Name.ToString().split('\')[1]}) -join ', '
                if ($adminLine.Count -eq 1) {
                    $status = "양호"
                }
                else {
                    $status = "수동 확인 필요"
                }
                $currentState = "현재 관리자 그룹 계정 ($($adminLine.Count)개): $adminName"
            }
            
            "W-07" {
                ### Everyone 사용 권한을 익명 사용자에게 적용
                # EveryoneIncludesAnonymous 레지스트리 값 확인
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                $valueName = "EveryoneIncludesAnonymous"
                if (Test-Path $registryPath) {
                    $everyIncAnonymous = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $everyIncAnonymous) {
                        $result = $everyIncAnonymous.$valueName
                        if ($result -eq 0) {
                            $status = "양호"
                            $currentState = "EveryoneIncludesAnonymous 설정: 사용 안 함 (0)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "EveryoneIncludesAnonymous 설정: 사용 (1)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "EveryoneIncludesAnonymous를 찾을 수 없음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "EveryoneIncludesAnonymous 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-08" {
                ### 계정 잠금 기간 설정
                # 계정 잠금 기간 확인
                $lockoutLine = net accounts | Select-String -Pattern "잠금 기간"
                $lockoutTime = $lockoutLine.ToString().Split(':')[1].Trim()
                if ([int]$lockoutTime -ge 60) {
                    $status = "양호"
                    $currentState = "잠금 기간(분): $lockoutTime"
                }
                else {
                    $status = "관리 필요"
                    $currentState = "잠금 기간(분): $lockoutTime"
                }
            }
            
            "W-09" {
                ### 비밀번호 관리정책 설정
                # 최소·최대 암호 사용 기간, 최소 암호 길이, 암호 기록 개수 확인
                    # 최소 암호 사용 기간: 1일 이상 (최근 암호 기억 기능 우회 방지 목적)
                    # 최대 암호 사용 기간: 90일 이하
                    # 최소 암호 길이: 8자 이상
                    # 암호 기록 개수: 4개 이상
                    # 비밀번호 복잡성: 1(사용) 
                $passwordMinAgeLine = net accounts | Select-String -Pattern "최소 암호 사용 기간" 
                $passwordMaxAgeLine = net accounts | Select-String -Pattern "최대 암호 사용 기간" 
                $passwordLengthLine = net accounts | Select-String -Pattern "최소 암호 길이"
                $passwordCountLine = net accounts | Select-String -Pattern "암호 기록 개수"
                
                $passwordMinAge = $passwordMinAgeLine.ToString().Split(':')[1].Trim()
                $passwordMaxAge = $passwordMaxAgeLine.ToString().Split(':')[1].Trim()
                $passwordLength = $passwordLengthLine.ToString().Split(':')[1].Trim()
                if ($passwordCountLine.ToString().Split(':')[1].Trim() -eq "없음") {
                    $passwordCount = 0
                }
                else {
                    $passwordCount = $passwordCountLine.ToString().Split(':')[1].Trim()
                }
                # 암호 복잡성 확인하기 위한 파일 생성 -> 변수 값 입력 -> 파일 삭제 과정
                $tempFile = "$env:temp\policy_$([System.Guid]::NewGuid()).inf"
                try {
                    secedit /export /cfg $tempFile 2>$null | Out-Null
                    if (Test-Path $tempFile) {
                        $complexityLine = Select-String -Path $tempFile -Pattern "PasswordComplexity" -ErrorAction SilentlyContinue
                        if ($null -ne $complexityLine) {
                            # PasswordComplexity=1 형식에서 숫자만 추출
                            $passwordComplexity = [int]($complexityLine.ToString().Split('=')[1].Trim())
                        }
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                    if ([int]$passwordMinAge -ge 1 -and [int]$passwordMaxAge -le 90 -and [int]$passwordLength -ge 8 `
                    -and [int]$passwordCount -ge 4 -and [int]$passwordComplexity -eq 1) {
                        $status = "양호"
                    }
                    else {
                        $status = "관리 필요"
                    }
                    $currentState = "최소 기간: ${passwordMinAge}일 / 최대 기간: ${passwordMaxAge}일 / 최소 길이: ${passwordLength}자 / 기록 개수: ${passwordCount}개 / 복잡성: $passwordComplexity"
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "보안 정책 추출 실패 또는 권한 부족: $($_.Exception.Message)"
                }
            }
            
            "W-10" {
                ### 마지막 사용자 이름 표시 안 함
                # DontDisplayLastUserName 레지스트리 값 확인
                $registryPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
                $valueName = "DontDisplayLastUserName"
                if (Test-Path $registryPath) {
                    $lastUserName = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $lastUserName) {
                        $result = $lastUserName.$valueName
                        if ($result -eq 1) {
                            $status = "양호"
                            $currentState = "DontDisplayLastUserName 설정: 사용 (1)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "DontDisplayLastUserName 설정: 사용 안 함 (0)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "DontDisplayLastUserName를 찾을 수 없음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "DontDisplayLastUserName 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-11" {
                ### 로컬 로그온 허용
                # SeInteractiveLogonRight 값 확인
                    # Administrators SID = S-1-5-32-544
                $tempFile = "$env:temp\policy_$([System.Guid]::NewGuid()).inf"
                try {
                    secedit /export /cfg $tempFile 2>$null | Out-Null
                    if (Test-Path $tempFile) {
                        $logonLine = Select-String -Path $tempFile -Pattern "SeInteractiveLogonRight" -ErrorAction SilentlyContinue
                        if ($null -ne $logonLine) {
                            # 값 분리 (예: __vmware__,Guest,*S-1-5-32-544,*S-1-5-32-545,*S-1-5-32-551...)
                            $sids = $logonLine.ToString().Split('=')[1].Split(',')
                            $accountList = foreach ($sid in $sids) {
                                try {
                                    (New-Object System.Security.Principal.SecurityIdentifier($sid.Trim('*'))).
                                    Translate([System.Security.Principal.NTAccount]).Value
                                }
                                catch {
                                    $sid
                                }
                            }
                        }
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                    $allowed = @("Administrators", "IUSR")
                    $notAllowed = $accountList | Where-Object {$_ -notmatch $allowed}
                    if ($notAllowed.Count -eq 0) {
                        $status = "양호"
                    }
                    else {
                        $status = "관리 필요"
                    }
                    $displayAccount = $accountList -join ', '
                    $currentState = "로컬 로그인 허용 계정 ($($accountList.Count)개): $displayAccount"
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "보안 정책 추출 실패 또는 권한 부족: $($_.Exception.Message)"
                }
                
            }
            
            "W-12" {
                ### 익명 SID/이름 변환 허용 해제
                # LSAAnonymousNameLookup 값 확인
                $tempFile = "$env:temp\policy_$([System.Guid]::NewGuid()).inf"
                try {
                    secedit /export /cfg $tempFile 2>$null | Out-Null
                    if (Test-Path $tempFile) {
                        $nameLookupLine = Select-String -Path $tempFile -Pattern "LSAAnonymousNameLookup" -ErrorAction SilentlyContinue
                        if ($null -ne $nameLookupLine) {
                            $nameLookup = [int]($nameLookupLine.ToString().Split('=')[1].Trim())
                        }
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                    if ([int]$nameLookup -eq 0) {
                        $status = "양호"
                        $currentState = "익명 SID/이름 변환 정책: 사용 안 함 (0)"
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "익명 SID/이름 변환 정책: 사용 (1)"
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "보안 정책 추출 실패 또는 권한 부족: $($_.Exception.Message)"
                }
                
                
            }
            
            "W-13" {
                ### 콘솔 로그온 시 로컬 계정에서 빈 암호 사용 제한
                # LimitBlankPasswordUse 레지스트리 값 확인
                $registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
                $valueName = "LimitBlankPasswordUse"
                if (Test-Path $registryPath) {
                    $limitBlankPasswordUse = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $limitBlankPasswordUse) {
                        $result = $limitBlankPasswordUse.$valueName
                        if ($result -eq 1) {
                            $status = "양호"
                            $currentState = "LimitBlankPasswordUse 설정: 사용 (1)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "LimitBlankPasswordUse 설정: 사용 안 함 (0)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "LimitBlankPasswordUse를 찾을 수 없음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "LimitBlankPasswordUse 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-14" {
                ### 원격터미널 접속 가능한 사용자 그룹 제한
                # Remote Desktop Users 그룹 멤버 확인
                $rdpUsersLine = Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue
                $rdpUser = ($rdpUsersLine | ForEach-Object {$_.Name.ToString().split('\')[1]}) -join ', '
                if ($rdpUsersLine.Count -eq 0) {
                    $status = "양호"
                }
                else {
                    $status = "수동 확인 필요"
                }
                $currentState = "현재 원격 데스크톱 사용자 ($($rdpUsersLine.Count)개): $rdpUser"
            }
            
            "W-15" {
                ### 사용자 개인키 사용 시 암호 입력
                # 개인 키 사용 시 암호 입력 (ForceKeyProtection) 레지스트리 값 확인
                $registryPath = "HKLM:\SOFTWARE\Microsoft\Cryptography\Protect\Providers\Microsoft Smart Card Key Storage Provider"
                $valueName = "ForceKeyProtection"
                if (Test-Path $registryPath) {
                    $forceKeyProtection = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $forceKeyProtection) {
                        $result = $forceKeyProtection.$valueName
                        if ($result -eq 1) {
                            $status = "양호"
                            $currentState = "ForceKeyProtection 설정: 사용 (1)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "ForceKeyProtection 설정: 사용 안 함 (0)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "ForceKeyProtection를 찾을 수 없음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "ForceKeyProtection 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-16" {
                ### 공유 권한 및 사용자 그룹 설정
                # 공유 디렉터리 내 Everyone 권한 존재 여부 점검
                $allowed = @("C$", "D$", "Admin$", "IPC$")
                $sharedDirectory = Get-SmbShare | Select-Object -ExpandProperty Name
                $normalShares = $sharedDirectory | Where-Object {$_ -notin $allowed}
                if ($normalShares.Count -eq 0) {
                    $status = "양호"
                    $currentState = "일반 공유 디렉터리 없음"
                }
                else {
                    $vulnerableShares = @()
                    foreach ($share in $normalShares) {
                        $accessList = @(Get-SmbShareAccess -Name $share | Where-Object {$_.AccountName -eq "Everyone"})
                        if ($accessList.Count -gt 0) {
                            $vulnerableShares += $share
                        }
                    }
                    if ($vulnerableShares.Count -eq 0) {
                        $status = "양호"
                        $currentState = "일반 공유 디렉터리 존재하나 Everyone 권한 없음"
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "Everyone 권한이 설정된 공유 디렉터리: $($vulnerableShares -join ', ')"
                    }
                }
            }
            
            "W-17" {
                ### 하드디스크 기본 공유 제거
                # AutoShareServer 레지스트리 값 확인
                $registryPath = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                $valueName = "AutoShareServer"
                if (Test-Path $registryPath) {
                    $autoShareServer = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $autoShareServer) {
                        $result = $autoShareServer.$valueName
                        if ($result -eq 0) {
                            $status = "양호"
                            $currentState = "AutoShareServer 설정: 사용 안 함 (0)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "AutoShareServer 설정: 사용 (1)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "AutoShareServer를 찾을 수 없음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "AutoShareServer 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-18" {
                ### 불필요한 서비스 제거
                # 불필요한 서비스 목록
                $unnecessaryServices = @(
                    "Alerter",        # 알림 서비스 (서비스명: Alerter)
                    "wuauserv", # 자동 업데이트 서비스 (서비스명: Automatic Updates)
                    "ClipSrv",       # 클립북 서비스 (서비스명: Clipbook)
                    "Browser", # 컴퓨터 브라우저 서비스 (서비스명: Computer Browser)
                    "CryptSvc", # 암호화 서비스 (서비스명: Cryptographic Services)
                    "Dhcp",   # DHCP 클라이언트 서비스 (서비스명: DHCP Client)
                    "TrkWks", # 분산 링크 추적 클라이언트 (서비스명: Distributed Link Tracking Client)
                    "TrkSvr", # 분산 링크 추적 서버 (서비스명: Distributed Link Tracking Server)
                    "Dnscache",    # DNS 클라이언트 서비스 (서비스명: DNS Client)
                    "WerSvc", # 오류 보고 서비스 (서비스명: Error reporting Service)
                    "HidServ", # HID 접근 서비스 (서비스명: Human Interface Device Access)
                    "ImapiService", # IMAPI CD 굽기 서비스 (서비스명: IMAPI CD-Burning COM Service)
                    "Irmon", # 적외선 모니터 서비스 (서비스명: Infrared Monitor)
                    "Messenger",      # 메신저 서비스 (서비스명: Messenger)
                    "Mnmsrvc", # NetMeeting 원격 데스크톱 공유 (서비스명: NetMeeting Remote Desktop Sharing)
                    "WPDBusEnum", # 휴대용 미디어 일련 번호 서비스 (서비스명: Portable Media Serial Number)
                    "Spooler",  # 프린트 스풀러 서비스 (서비스명: Print Spooler)
                    "RemoteRegistry", # 원격 레지스트리 서비스 (서비스명: Remote Registry)
                    "SimpTcp", # 단순 TCP/IP 서비스 (서비스명: Simple TCP/IP Services)
                    "upnphost", # UPnP 장치 호스트 서비스 (서비스명: Universal Plug and Play Device Host)
                    "WlanSvc" # 무선 제로 구성 서비스 (서비스명: Wireless Zero Configuration)
                )
                $runningUnnecessaryServices = @()
                foreach ($serviceName in $unnecessaryServices) {
                    $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
                    if ($null -ne $service -and $service.Status -eq 'Running') {
                        $runningUnnecessaryServices += $service.DisplayName
                    }
                }
                if ($runningUnnecessaryServices.Count -eq 0) {
                    $status = "양호"
                    $currentState = "불필요한 서비스가 실행되지 않음"
                }
                else {
                    $status = "수동 확인 필요"
                    $currentState = "실행 중인 불필요한 서비스: $($runningUnnecessaryServices -join ', ')"
                }
            }
            
            "W-19" {
                ### 불필요한 IIS 서비스 구동 점검
                # IIS 서비스 상태 확인
                $IIS = Get-Service W3SVC -ErrorAction SilentlyContinue
                if ($null -ne $IIS) {
                    if ($IIS.Status -eq 'Running') {
                        $status = "수동 확인 필요"
                        $currentState = "IIS 서비스가 실행 중 (IIS 서비스가 불필요한 경우 IIS 서비스 중지 권고)"
                    }
                    else {
                        $status = "양호"
                        $currentState = "IIS 서비스가 중지됨"
                    }
                }
                else {
                    $status = "양호"
                    $currentState = "IIS 서비스가 설치되지 않음"
                }
            }
            
            "W-20" {
                ### NetBIOS 바인딩 서비스 구동 점검
                # NetBIOS 바인딩 서비스 상태 확인
                $netbiosService = Get-Service "NetBT" -ErrorAction SilentlyContinue
                if ($null -ne $netbiosService) {
                    if ($netbiosService.Status -eq 'Running') {
                        # NetbiosOptions 값: 0 (기본값/DHCP), 1 (활성화), 2 (비활성화)
                        $adaptersWithNetbios = Get-WmiObject -Class Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
                        $vulnerableAdapters = $adaptersWithNetbios | Where-Object { $_.NetbiosOptions -eq 1 }
                        $vulnerableAdaptersList = $vulnerableAdapters | ForEach-Object { $_.ServiceName }
                        if ($vulnerableAdapters.Count -gt 0) {
                            $status = "수동 확인 필요"
                            $currentState = "NetBIOS 바인딩 서비스가 실행 중: $($vulnerableAdaptersList -join ', ') (NetBIOS 서비스가 불필요한 경우 NetBIOS 서비스 중지 권고)"
                        }
                        else {
                            $status = "양호"
                            $currentState = "NetBIOS 바인딩 서비스가 실행 중이나 NetBIOS 옵션이 비활성화됨"
                        }
                    }
                    else {
                        $status = "양호"
                        $currentState = "NetBIOS 바인딩 서비스가 중지됨"
                    }
                }
                else {
                    $status = "양호"
                    $currentState = "NetBIOS 바인딩 서비스가 설치되지 않음"
                }
            }
            
            "W-21" {
                ### 암호화되지 않는 FTP 서비스 비활성화
                # FTP 서비스 상태 확인 및 Secure FTP 상태 확인
                $ftpService = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue
                if ($null -ne $ftpService) {
                    if ($ftpService.Status -eq 'Running') {
                        $status = "관리 필요"
                        $currentState = "FTP 서비스가 실행 중 (Secure FTP 사용 권고)"
                    }
                    else {
                        $status = "양호"
                        $currentState = "FTP 서비스가 중지됨"
                    }
                }
                else {
                    $status = "양호"
                    $currentState = "FTP 서비스가 설치되지 않음"
                }
            }
            
            "W-22" {
                ### FTP 디렉토리 접근권한 설정
                # FTP 홈 디렉토리 Everyone 권한 존재 여부 점검
                $ftpService = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

                if ($null -eq $ftpService -or $ftpService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "FTP 서비스 미사용 (점검 대상 아님)"
                }
                else {
                    # FTP 사이트 정보 확인
                    $ftpConfigPath = "C:\Windows\System32\inetsrv\config\applicationHost.config"
                    if (-not (Test-Path $ftpConfigPath)) {
                        $status = "수동 확인 필요"
                        $currentState = "FTP 서비스 실행 중이나 IIS 구성 파일을 찾을 수 없음"
                    }
                    else {
                        [xml]$ftpConfig = Get-Content $ftpConfigPath
                        $ftpSites = $ftpConfig.configuration.'system.applicationHost'.sites.site |
                        Where-Object { $_.bindings.binding.protocol -eq "ftp" }

                        if ($null -eq $ftpSites) {
                            $status = "수동 확인 필요"
                            $currentState = "FTP 서비스 실행 중이나 FTP 사이트 정보를 확인할 수 없음"
                        }
                        else {
                            $vulnerable = $false
                            foreach ($site in $ftpSites) {
                                foreach ($vdir in $site.application.virtualDirectory) {
                                    $path = $vdir.physicalPath
                                    if (Test-Path $path) {
                                        $acl = Get-Acl $path
                                        # Everyone SID = S-1-1-0
                                        if ($acl.Access | Where-Object {
                                            $_.IdentityReference.Value -match "S-1-1-0"
                                        }) {
                                            $vulnerable = $true
                                        }
                                    }
                                }
                            }

                            if ($vulnerable) {
                                $status = "관리 필요"
                                $currentState = "FTP 홈 디렉터리에 Everyone 권한 존재"
                            }
                            else {
                                $status = "양호"
                                $currentState = "FTP 홈 디렉터리에 Everyone 권한 없음"
                            }
                        }
                    }
                }
            }
            
            "W-23" {
                ### 공유 서비스에 대한 익명 접근 제한 설정
                # RestrictAnonymous 레지스트리 값 확인
                $registryPath = "HKLM:\System\CurrentControlSet\Control\Lsa"
                $valueName = "RestrictAnonymous"
                if (Test-Path $registryPath) {
                    $restrictAnonymous = Get-ItemProperty -Path $registryPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $restrictAnonymous) {
                        $result = $restrictAnonymous.$valueName
                        if ($result -eq 0) {
                            $status = "양호"
                            $currentState = "익명 인증: 사용 안 함 (0)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "익명 인증: 사용 (1)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "RestrictAnonymous를 찾을 수 없음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "RestrictAnonymous 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-24" {
                ### FTP 접근 제어 설정
                # FTP 접근 제어(IP 제한) 설정 점검
                $ftpService = Get-Service -Name "FTPSVC" -ErrorAction SilentlyContinue

                if ($null -eq $ftpService -or $ftpService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "FTP 서비스 미사용 (점검 대상 아님)"
                }
                else {
                    try {
                        Import-Module WebAdministration -ErrorAction Stop

                        # FTP IP 접근 제어 설정 조회
                        $ipSecurity = Get-WebConfiguration `
                            -Filter "/system.ftpServer/security/ipSecurity" `
                            -PSPath "IIS:\"

                        if ($null -eq $ipSecurity) {
                            $status = "관리 필요"
                            $currentState = "FTP IP 접근 제어 설정이 존재하지 않음"
                        }
                        else {
                            if ($ipSecurity.allowUnlisted -eq $false) {
                                $status = "양호"
                                $currentState = "FTP 접근 제어 설정 적용됨 (특정 IP만 허용)"
                            }
                            else {
                                $status = "관리 필요"
                                $currentState = "FTP 접근 제어 설정 미적용 (모든 IP 허용)"
                            }
                        }
                    }
                    catch {
                        $status = "수동 확인 필요"
                        $currentState = "FTP 접근 제어 설정 확인 중 오류 발생 (수동 점검 필요)"
                    }
                }
            }
            
            "W-25" {
                ### DNS Zone Transfer 설정
                # DNS Zone Transfer 차단 설정 점검
                $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue

                if ($null -eq $dnsService -or $dnsService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "DNS 서비스 미사용"
                }
                else {
                    try {
                        $zones = Get-DnsServerZone -ErrorAction Stop |
                                Where-Object { $_.ZoneType -eq "Primary" }

                        if ($zones.Count -eq 0) {
                            $status = "양호"
                            $currentState = "Primary DNS Zone 없음"
                        }
                        else {
                            $vulnerableZones = @()

                            foreach ($zone in $zones) {
                                if ($zone.SecureSecondaries -eq "TransferToAnyServer") {
                                    $vulnerableZones += $zone.ZoneName
                                }
                            }

                            if ($vulnerableZones.Count -gt 0) {
                                $status = "관리 필요"
                                $currentState = "다음 DNS Zone에서 영역 전송이 전체 허용됨: " +
                                                ($vulnerableZones -join ", ")
                            }
                            else {
                                $status = "양호"
                                $currentState = "모든 DNS Zone에서 영역 전송이 제한됨 또는 비활성화됨"
                            }
                        }
                    }
                    catch {
                        $status = "수동 확인 필요"
                        $currentState = "DNS Zone Transfer 설정 확인 중 오류 발생"
                    }
                }
            }
            
            "W-26" {
                ### RDS(Remote Data Services) 제거
                # 1. OS 버전 확인
                $os = Get-CimInstance Win32_OperatingSystem
                $osVersion = [version]$os.Version

                # Windows 2008 이상 (6.0 이상)
                if ($osVersion.Major -ge 6) {
                    $status = "양호"
                    $currentState = "Windows 2008 이상 버전 사용 (RDS 점검 대상 아님)"
                }
                # 2. IIS 사용 여부 확인
                elseif ({
                    $iisService = Get-Service -Name "W3SVC" -ErrorAction SilentlyContinue
                    $null -eq $iisService -or $iisService.Status -ne "Running"
                }.Invoke()) {
                    $status = "양호"
                    $currentState = "IIS 서비스 미사용"
                }
                # 3. MSADC 가상 디렉터리 존재 여부 확인
                else {
                    $msadcPath1 = "C:\Inetpub\wwwroot\MSADC"
                    $msadcPath2 = "C:\Windows\System32\inetsrv\MSADC"

                    $msadcExists = (Test-Path $msadcPath1) -or (Test-Path $msadcPath2)

                    if (-not $msadcExists) {
                        $status = "양호"
                        $currentState = "MSADC 가상 디렉터리 존재하지 않음"
                    }
                    # 4. RDS 레지스트리 키 존재 여부 확인
                    else {
                        $rdsRegPath = "HKLM:\SOFTWARE\Microsoft\DataAccess\RDS"
                        if (-not (Test-Path $rdsRegPath)) {
                            $status = "양호"
                            $currentState = "RDS 관련 레지스트리 키 존재하지 않음"
                        }
                        # 위 모든 양호 조건에 해당하지 않는 경우
                        else {
                            $status = "취약"
                            $currentState = "IIS 사용 중이며 MSADC 가상 디렉터리 및 RDS 레지스트리 키가 존재함 (RDS 취약)"
                        }
                    }
                }
            }
            
            "W-27" {
                ### 최신 Windows OS Build 버전 적용
                # 현재 Windows OS Build 버전 확인 (마지막 보안 패치 날짜 기준으로 90일 경과 시 '관리 필요', 이내면 '수동 확인 필요')
                $osInfo = Get-ComputerInfo -Property "WindowsVersion", "WindowsBuildLabEx", "WindowsProductName"
                $currentBuild = [int](Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion").CurrentBuild
                $installDate = (Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1).InstalledOn
            
                 if ($installDate -lt (Get-Date).AddDays(-90)) {
                    $status = "관리 필요"
                    $currentState = "현재 빌드 버전: $currentBuild ($($osInfo.WindowsProductName)) / 마지막 보안 패치 설치 후 90일 경과 ($($installDate.ToString('yyyy-MM-dd')))"
                }
                else {
                    $status = "수동 확인 필요"
                    $currentState = "현재 빌드 버전: $currentBuild ($($osInfo.WindowsProductName)) / 마지막 보안 패치 설치 날짜: $($installDate.ToString('yyyy-MM-dd'))"
                }
            }
            
            "W-28" {
                ### 터미널 서비스 암호화 수준 설정
                # 원격 데스크톱 서비스 상태 확인
                $RDPStatus = Get-Service -Name TermService -ErrorAction SilentlyContinue
                if ($RDPStatus.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "원격 데스크톱 서비스 미사용"
                } 
                else {
                    # 2. 레지스트리 경로 설정
                    $RegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                    $ValueName = "MinEncryptionLevel"
                    # 3. 레지스트리 값 확인
                    if (Test-Path $RegPath) {
                        $EncryptionLevel = Get-ItemProperty -Path $RegPath -Name $ValueName -ErrorAction SilentlyContinue
                        if ($null -eq $EncryptionLevel) {
                            # 값이 없으면 기본 설정(보통 중간 이상)이므로 양호 처리
                            $status = "양호"
                            $currentState = "MinEncryptionLevel 값이 설정되지 않음 - 기본 보안 적용 중"
                        }
                        elseif ($EncryptionLevel.$ValueName -ge 2) {
                            # 2: 중간, 3: 높음, 4: FIPS 준수
                            $status = "양호"
                            $currentState = "MinEncryptionLevel 설정: $($EncryptionLevel.$ValueName) (중간 이상)"
                        }
                        else {
                            # 1: 낮음
                            $status = "관리 필요"
                            $currentState = "MinEncryptionLevel 설정: $($EncryptionLevel.$ValueName) (낮음)"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "RDP-Tcp 레지스트리 경로를 찾을 수 없음"
                    }
                }
            }
            
            "W-29" {
                ### 불필요한 SNMP 서비스 구동 점검
                # SNMP 서비스 존재 및 실행 여부 확인
                $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

                if ($null -eq $snmpService -or $snmpService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "SNMP 서비스가 설치되지 않았거나 중지된 상태입니다."
                }
                else {
                    $status = "수동 확인 필요"
                    $currentState = "SNMP 서비스가 실행 중입니다. (불필요한 경우 서비스 비활성화 권고)"
                }
            }
            
            "W-30" {
                ### SNMP Community String 복잡성 설정
                # 1. SNMP 서비스 존재 및 실행 여부 확인
                $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

                if ($null -eq $snmpService -or $snmpService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "SNMP 서비스가 설치되지 않았거나 중지된 상태입니다."
                }
                else {
                    # 2. SNMP 서비스를 사용 중인 경우, Community String 설정 확인 (레지스트리 쿼리)
                    $snmpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\ValidCommunities"
                    
                    if (Test-Path $snmpPath) {
                        $communities = Get-ItemProperty -Path $snmpPath
                        # 기본값인 'public' 또는 'private'이 포함되어 있는지 확인
                        $vulnerableStrings = @("public", "private")
                        $currentCommunities = $communities.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" }

                        $isVulnerable = $false
                        foreach ($str in $currentCommunities) {
                            if ($vulnerableStrings -contains $str.ToLower()) {
                                $isVulnerable = $true
                                break
                            }
                        }

                        if ($isVulnerable) {
                            $status = "관리 필요"
                            $currentState = "SNMP 사용 중이나, 기본 커뮤니티 이름(public/private)이 설정되어 있습니다."
                        }
                        else {
                            $status = "양호"
                            $currentState = "SNMP 사용 중이며, 기본값이 아닌 커뮤니티 이름을 사용하고 있습니다."
                        }
                    }
                    else {
                        # 서비스는 도는데 커뮤니티 설정이 없는 경우 (비정상 상황 혹은 취약)
                        $status = "관리 필요"
                        $currentState = "SNMP 서비스가 실행 중이나 보안 설정(Community String)을 확인할 수 없습니다."
                    }
                }
            }
            
            "W-31" {
                # SNMP Access control 설정
                # 허용 IP 설정 점검
                $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
                if ($null -eq $snmpService -or $snmpService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "SNMP 서비스가 설치되지 않았거나 중지된 상태입니다."
                }
                else {
                    # SNMP 접근 제어 설정 확인 (레지스트리 쿼리)
                    $snmpPath = "HKLM:\SYSTEM\CurrentControlSet\Services\SNMP\Parameters\PermittedManagers"
                    if (Test-Path $snmpPath) {
                        $permittedManagers = Get-ItemProperty -Path $snmpPath
                        $managers = $permittedManagers.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" }
                        if ($managers.Count -eq 0) {
                            $status = "관리 필요"
                            $currentState = "SNMP 사용 중이나, 허용된 매니저(관리자) IP가 설정되어 있지 않습니다."
                        }
                        else {
                            $status = "양호"
                            $currentState = "SNMP 사용 중이며, 허용된 매니저(관리자) IP가 설정되어 있습니다: $($managers -join ', ')"
                        }
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "SNMP 서비스가 실행 중이나 접근 제어 설정을 확인할 수 없습니다."
                    }
                }
            }
            
            "W-32" {
                ### DNS 서비스 구동 점검
                # 양호 : DNS 서비스를 사용하지 않거나 동적 업데이트 “없음(아니오)”으로 설정된 경우
                # 관리 필요 : 서비스를 사용하며 동적 업데이트가 설정된 경우
                # DNS 서비스 상태 확인
                $dnsService = Get-Service -Name "DNS" -ErrorAction SilentlyContinue
                if ($null -eq $dnsService -or $dnsService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "DNS 서비스 미사용"
                }
                else {
                    try {
                        $zones = Get-DnsServerZone -ErrorAction Stop

                        if ($zones.Count -eq 0) {
                            $status = "양호"
                            $currentState = "DNS Zone 없음"
                        }
                        else {
                            $vulnerableZones = @()

                            foreach ($zone in $zones) {
                                if ($zone.DynamicUpdate -ne "None") {
                                    $vulnerableZones += $zone.ZoneName
                                }
                            }

                            if ($vulnerableZones.Count -gt 0) {
                                $status = "관리 필요"
                                $currentState = "다음 DNS Zone에서 동적 업데이트가 설정됨: " +
                                                ($vulnerableZones -join ", ")
                            }
                            else {
                                $status = "양호"
                                $currentState = "모든 DNS Zone에서 동적 업데이트가 '없음(아니오)'으로 설정됨"
                            }
                        }
                    }
                    catch {
                        $status = "수동 확인 필요"
                        $currentState = "DNS 서비스 설정 확인 중 오류 발생"
                    }
                }
            }
            
            "W-33" {
                ### HTTP/FTP/SMTP 배너 차단
                $results = @()
                Import-Module WebAdministration -ErrorAction SilentlyContinue

                # 1. HTTP (IIS) 서버 헤더 및 X-Powered-By 확인
                if (Get-Service W3SVC -ErrorAction SilentlyContinue) {
                    $sites = Get-Website
                    foreach ($site in $sites) {
                        $config = Get-WebConfigurationProperty -Filter "system.webServer/httpProtocol/customHeaders" -PSPath "IIS:\Sites\$($site.Name)" -Name "Collection"
                        $hasXPoweredBy = $config | Where-Object { $_.Name -eq "X-Powered-By" }
                        
                        # URL 재작성 규칙(Server 헤더 제거) 확인
                        $urlRewrite = Get-WebConfigurationProperty -Filter "system.webServer/rewrite/outboundRules" -PSPath "IIS:\Sites\$($site.Name)" -Name "Collection"
                        $hasServerRemove = $urlRewrite | Where-Object { $_.Name -eq "Remove Server" }

                        if ($hasXPoweredBy -or -not $hasServerRemove) {
                            $results += "HTTP($($site.Name)): 배너 노출 차단 미설정"
                        }
                    }
                }

                # 2. FTP 기본 배너 숨기기 확인
                if (Get-Service FTPSVC -ErrorAction SilentlyContinue) {
                    $ftpBanner = Get-WebConfigurationProperty -Filter "system.applicationHost/sites/siteDefaults/ftpServer/messages" -Name "suppressDefaultBanner"
                    if ($ftpBanner.Value -eq $false) {
                        $results += "FTP: 기본 배너 숨기기(suppressDefaultBanner) 미설정"
                    }
                }

                # 3. SMTP 배너 설정 확인 (IIS 6.0 Metabase 기반)
                if (Get-Service SMTPSVC -ErrorAction SilentlyContinue) {
                    # adsutil.vbs 대신 레지스트리나 IIS 메타베이스 쿼리 사용 (예시 로직)
                    # 보통 ConnectResponse 값이 비어있지 않고 특정 문구로 대체되었는지 확인
                    $smtpPath = "IIS://localhost/smtpsvc/1"
                    try {
                        $smtp = [ADSI]$smtpPath
                        if ([string]::IsNullOrEmpty($smtp.ConnectResponse)) {
                            $results += "SMTP: 접속 배너가 기본값으로 노출됨"
                        }
                    } catch {
                        $results += "SMTP: 설정 확인 불가(관리도구 미설치)"
                    }
                }

                # 최종 결과 판단
                if ($results.Count -eq 0) {
                    $status = "양호"
                    $currentState = "모든 웹/FTP/SMTP 서비스에서 배너 차단 설정이 적용되었습니다."
                } else {
                    $status = "관리 필요"
                    $currentState = $results -join ", "
                }
            }
            
            "W-34" {
                ### Telnet 서비스 비활성화
                # 양호 : Telnet 서비스가 구동되어 있지 않거나 인증 방법이 NTLM인 경우
                # 취약 : Telnet 서비스가 구동되어 있으며 인증 방법이 NTLM이 아닌 경우
                $telnetService = Get-Service -Name "TlntSvr" -ErrorAction SilentlyContinue
                if ($null -eq $telnetService -or $telnetService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "Telnet 서비스 미사용"
                }
                else {
                    # Telnet 인증 방법 확인 (레지스트리 쿼리)
                    $telnetRegPath = "HKLM:\SYSTEM\CurrentControlSet\Services\TlntSvr\Parameters"
                    $valueName = "AuthenticationMethods"
                    if (Test-Path $telnetRegPath) {
                        $authMethods = Get-ItemProperty -Path $telnetRegPath -Name $valueName -ErrorAction SilentlyContinue
                        if ($null -ne $authMethods) {
                            if ($authMethods.$valueName -eq 1) {
                                $status = "양호"
                                $currentState = "Telnet 인증 방법: NTLM 사용"
                            }
                            else {
                                $status = "관리 필요"
                                $currentState = "Telnet 인증 방법: NTLM 이외의 방법 사용 (취약)"
                            }
                        }
                        else {
                            $status = "점검 불가"
                            $currentState = "Telnet 인증 방법을 찾을 수 없음"
                        }
                    }
                    else {
                        $status = "점검 불가"
                        $currentState = "Telnet 레지스트리 경로를 찾을 수 없음"
                    }
                }
            }
            
            "W-35" {
                ### 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거
                # 양호 : 시스템 DSN 부분의 데이터 소스를 현재 사용하고 있는 경우
                # 취약 : 시스템 DSN 부분의 데이터 소스를 현재 사용하고 있지 않은 경우
                $odbcRegPath = "HKLM:\SOFTWARE\ODBC\ODBC.INI\ODBC Data Sources"
                if (Test-Path $odbcRegPath) {
                    $dataSources = Get-ItemProperty -Path $odbcRegPath
                    $dataSourceNames = $dataSources.PSObject.Properties.Name | Where-Object { $_ -ne "PSPath" -and $_ -ne "PSParentPath" -and $_ -ne "PSChildName" -and $_ -ne "PSDrive" -and $_ -ne "PSProvider" }
                    
                    if ($dataSourceNames.Count -eq 0) {
                        $status = "양호"
                        $currentState = "시스템 DSN에 데이터 소스가 존재하지 않음"
                    }
                    else {
                        # 현재 사용 중인 데이터 소스 확인 (수동 확인 필요)
                        $status = "수동 확인 필요"
                        $currentState = "시스템 DSN에 다음 데이터 소스가 존재함: $($dataSourceNames -join ', ') (현재 사용 여부 수동 확인 필요)"
                    }
                }
                else {
                    $status = "양호"
                    $currentState = "시스템 DSN에 데이터 소스가 존재하지 않음"
                }
            }
            
            "W-36" {
                ### 원격터미널 접속 타임아웃 설정
                # 양호 : 원격 제어 시 Timeout 제어 설정을 30분 이하로 설정한 경우
                # 취약 : 원격 제어 시 Timeout 제어 설정을 적용하지 않거나 30분 초과로 설정한 경우
                $rdpRegPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server"
                $valueName = "IdleWinStationTimeout"
                if (Test-Path $rdpRegPath) {
                    $timeoutValue = Get-ItemProperty -Path $rdpRegPath -Name $valueName -ErrorAction SilentlyContinue
                    if ($null -ne $timeoutValue) {
                        # 값은 밀리초 단위이므로 30분(1800000ms)과 비교
                        if ($timeoutValue.$valueName -le 1800000) {
                            $status = "양호"
                            $currentState = "원격 터미널 접속 타임아웃 설정: $($timeoutValue.$valueName) ms (30분 이하)"
                        }
                        else {
                            $status = "관리 필요"
                            $currentState = "원격 터미널 접속 타임아웃 설정: $($timeoutValue.$valueName) ms (30분 초과)"
                        }
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "원격 터미널 접속 타임아웃 설정이 적용되지 않음"
                    }
                }
                else {
                    $status = "점검 불가"
                    $currentState = "원격 터미널 레지스트리 경로를 찾을 수 없음"
                }
            }
            
            "W-37" {
                ### 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검
                # 양호 : 불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하고 제거한 경우
                # 취약 : 불필요한 명령어나 파일 등 주기적인 예약 작업의 존재 여부를 주기적으로 점검하지 않거나, 불필요한 작업을 제거하지 않은 경우
                $scheduledTasks = Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' -or $_.State -eq 'Running' }
                $suspiciousTasks = @()
                foreach ($task in $scheduledTasks) {
                    $actions = $task.Actions
                    foreach ($action in $actions) {
                        # 실행 파일과 인수를 하나로 합침
                        $fullCommandLine = "$($action.Execute) $($action.Arguments)"
                        
                        $suspiciousPatterns = @("cmd.exe /c", "powershell.exe -enc", "powershell.exe -Command", "temp\", "http://", "https://", "wget", "curl", "Invoke-WebRequest", "Invoke-Expression")
                        
                        foreach ($pattern in $suspiciousPatterns) {
                            # 합쳐진 전체 명령어 라인에서 패턴 검색
                            if ($fullCommandLine -like "*$pattern*") {
                                $suspiciousTasks += $task.TaskName
                                break
                            }
                        }
                    }
                }
                if ($suspiciousTasks.Count -eq 0) {
                    $status = "양호"
                    $currentState = "의심스러운 예약 작업 없음"
                }
                else {
                    $status = "수동 확인 필요"
                    $currentState = "의심스러운 예약 작업 발견: $($suspiciousTasks -join ', ')"
                }
            }
            
            "W-38" {
                ### 주기적 보안 패치 및 벤더 권고사항 적용
                # 양호 : 패치 절차를 수립하여 주기적으로 패치를 확인 및 설치하는 경우
                # 취약 : 패치 절차가 수립되어 있지 않거나 주기적으로 패치를 설치하지 않는 경우
                $lastPatch = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 1
                if ($null -eq $lastPatch) {
                    $status = "취약"
                    $currentState = "시스템에서 설치된 패치 기록을 찾을 수 없습니다."
                }
                else {
                    $lastDate = $lastPatch.InstalledOn
                    $daysSincePatch = ((Get-Date) - $lastDate).Days

                    # 2. 판단 로직: 마지막 패치 이후 90일이 경과했는지 체크
                    if ($daysSincePatch -le 90) {
                        $status = "양호"
                        $currentState = "최근 보안 패치 설치 기록 있음: $($lastDate.ToString('yyyy-MM-dd')) ($($daysSincePatch)일 경과)"
                    }
                    else {
                        $status = "취약"
                        $currentState = "마지막 보안 패치 설치 후 90일 이상 경과되었습니다: $($lastDate.ToString('yyyy-MM-dd'))"
                    }
                }

                # 3. 자동 업데이트 설정 확인
                $auPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
                $isAutoUpdate = $false

                if (Test-Path $auPath) {
                    $auOption = Get-ItemProperty -Path $auPath -Name "AUOptions" -ErrorAction SilentlyContinue
                    if ($null -ne $auOption -and $auOption.AUOptions -eq 4) {
                        $isAutoUpdate = $true
                    }
                }# 레지스트리에 없더라도 서비스 상태로 보완 확인
                $auService = Get-Service -Name "wuauserv" -ErrorAction SilentlyContinue
                $isServiceRunning = ($null -ne $auService -and $auService.StartType -ne "Disabled")

                if ($isAutoUpdate) {
                    $currentState += " (자동 업데이트 정책 활성화됨)"
                } elseif ($isServiceRunning) {
                    $currentState += " (Windows Update 서비스가 활성화 상태임)"
                } else {
                    $status = "관리 필요"
                    $currentState += " (자동 업데이트 설정 확인 불가 또는 비활성화)"
                }
            }
            
            "W-39" {
                ### 백신 프로그램 업데이트
                # 양호 : 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립된 경우
                # 취약 : 바이러스 백신 프로그램의 최신 엔진 업데이트가 설치되어 있지 않거나, 망 격리 환경의 경우 백신 업데이트를 위한 절차 및 적용 방법이 수립되지 않은 경우
                # 1. Windows Defender 상태 확인
                $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
                $defenderOk = $false
                if ($null -ne $defender) {
                    # 최근 7일 이내 업데이트 되었고, 실시간 감시가 켜져 있는지 확인
                    if ($defender.AntivirusSignatureLastUpdated -gt (Get-Date).AddDays(-7) -and $defender.RealTimeProtectionEnabled) {
                        $defenderOk = $true
                        $lastUpdateDate = $defender.AntivirusSignatureLastUpdated
                    }
                }

                # 2. 타사 백신 상태 확인
                $antivirusProducts = Get-CimInstance -Namespace "root\SecurityCenter2" -ClassName "AntiVirusProduct" -ErrorAction SilentlyContinue
                $thirdPartyOk = $false
                $thirdPartyNames = @()

                if ($null -ne $antivirusProducts) {
                    foreach ($product in $antivirusProducts) {
                        # 0x0010 비트가 꺼져 있으면(최신), 0x1000 비트가 켜져 있으면(활성화)
                        $state = $product.productState
                        $isUpToDate = !($state -band 0x0010)
                        $isActive = ($state -band 0x1000)

                        if ($isUpToDate -and $isActive) {
                            $thirdPartyOk = $true
                            $thirdPartyNames += $product.displayName
                        }
                    }
                }

                # 3. 최종 판단 (둘 중 하나만 정상이어도 양호)
                if ($defenderOk -or $thirdPartyOk) {
                    $status = "양호"
                    $usedAntivirus = if ($thirdPartyOk) { $thirdPartyNames -join ", " } else { "Windows Defender" }
                    $currentState = "백신 프로그램($usedAntivirus)이 활성화되어 있으며 최신 상태입니다."
                }
                else {
                    $status = "관리 필요"
                    $currentState = "활성화된 백신이 없거나 업데이트가 오래되었습니다. (Defender 및 설치된 백신 확인 필요)"
                }
            }
            
            "W-40" {
                # 1. DC 여부 판단
                $isDomainController = (Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4

                # 2. auditpol 결과 수집 (환경 호환 방식)
                $auditStats = auditpol /get /category:* /r | ConvertFrom-Csv

                # 3. 권고 기준 정의 (하위 범주 기준)
                $checkItems = @(
                    @{
                        Name = "계정 관리"
                        SubCategories = @("사용자 계정 관리", "보안 그룹 관리")
                        Required = "실패"
                    },
                    @{
                        Name = "계정 로그온 이벤트"
                        SubCategories = @("계정 로그온")
                        Required = "성공 및 실패"
                    },
                    @{
                        Name = "로그온 이벤트"
                        SubCategories = @("로그온")
                        Required = "성공 및 실패"
                    },
                    @{
                        Name = "권한 사용"
                        SubCategories = @("중요한 권한 사용")
                        Required = "성공 및 실패"
                    },
                    @{
                        Name = "정책 변경"
                        SubCategories = @("감사 정책 변경", "인증 정책 변경")
                        Required = "성공 및 실패"
                    }
                )

                # DC인 경우만 DS Access 추가
                if ($isDomainController) {
                    $checkItems += @{
                        Name = "DS 액세스"
                        SubCategories = @("디렉터리 서비스 액세스")
                        Required = "실패"
                    }
                }

                $goodItems = @()
                $badItems  = @()

                # 4. 점검 로직
                foreach ($item in $checkItems) {
                    $isCompliant = $true
                    $currentStates = @()

                    foreach ($sub in $item.SubCategories) {
                        $entry = $auditStats | Where-Object { $_."하위 범주" -eq $sub }

                        if ($null -eq $entry -or [string]::IsNullOrWhiteSpace($entry."포함 설정")) {
                            $isCompliant = $false
                            $currentStates += "$($sub): 미설정"
                            continue
                        }

                        $setting = $entry."포함 설정"
                        $currentStates += "$($sub): $setting"

                        switch ($item.Required) {
                            "성공 및 실패" {
                                if ($setting -notmatch "성공" -or $setting -notmatch "실패") {
                                    $isCompliant = $false
                                }
                            }
                            "실패" {
                                if ($setting -notmatch "실패") {
                                    $isCompliant = $false
                                }
                            }
                            "성공" {
                                if ($setting -notmatch "성공") {
                                    $isCompliant = $false
                                }
                            }
                        }
                    }

                    if ($isCompliant) {
                        $goodItems += "$($item.Name) (기준: $($item.Required))"
                    } else {
                        $badItems += "$($item.Name) (현재: $($currentStates -join ', ') / 기준: $($item.Required))"
                    }
                }

                # 5. 최종 결과 출력
                if ($badItems.Count -eq 0) {
                    $status = "양호"
                    $currentState = "점검 결과: 모든 감사 정책이 권고 기준에 따라 적절히 설정되어 있습니다."
                } else {
                    $status = "관리 필요"
                    $currentState = @"
                점검 결과 미흡한 항목이 발견되었습니다.
                [미흡 항목]:
                - $(($badItems -join "`n- "))
                [양호 항목]:
                - $(($goodItems -join "`n- "))
"@
                }
            }
            
            "W-41" {
                ### NTP 및 시각 동기화 설정
                # 양호 : NTP 및 시각 동기화를 설정한 경우
                # 취약 : NTP 및 시각 동기화를 설정하지 않은 경우
                try {
                    $ntpParams = w32tm /dumpreg /subkey:parameters 2>$null

                    if (-not $ntpParams) {
                        throw "w32tm 출력 없음"
                    }

                    $typeMatch      = $ntpParams | Select-String "Type"
                    $ntpServerMatch = $ntpParams | Select-String "NtpServer"
                    $peerListMatch  = $ntpParams | Select-String "ManualPeerList"

                    $type      = if ($typeMatch) { $typeMatch.Line } else { "" }
                    $ntpServer = if ($ntpServerMatch) { $ntpServerMatch.Line } else { "" }
                    $peerList  = if ($peerListMatch) { $peerListMatch.Line } else { "" }

                    $isDC = (Get-WmiObject Win32_ComputerSystem).DomainRole -ge 4

                    if ($type -match "NoSync") {
                        $status = "관리 필요"
                        $currentState = "시간 동기화가 비활성화됨 (NoSync)"
                    }
                    elseif ($isDC -and $type -match "NT5DS|All") {
                        $status = "양호"
                        $currentState = "도메인 기반 시간 동기화(NT5DS) 설정됨"
                    }
                    elseif (-not $isDC -and $type -match "NTP|All" -and ($ntpServer -or $peerList)) {
                        $status = "양호"
                        $currentState = "NTP 서버 기반 시간 동기화 설정됨"
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "시간 동기화 설정이 불완전함 (Type 또는 서버 설정 누락)"
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "오류: $($_.Exception.Message)"
                }
            }
            
            "W-42" {
                ### 이벤트 로그 관리 설정
                # 양호 : 최대 로그 크기 “10,240KB 이상”으로 설정, “90일 이후 이벤트 덮어씀”을 설정한 경우
                # 취약 : 최대 로그 크기 “10,240KB 미만”으로 설정, 이벤트 덮어씀 기간이 “90일 이하로 설정된 경우
                try {
                    $targetLogs = @("Application", "System", "Security")
                    $issues = @()

                    foreach ($logName in $targetLogs) {
                        try {
                            $logInfo = Get-WinEvent -ListLog $logName -ErrorAction Stop
                            $logConfig = wevtutil gl $logName

                            # 최대 크기 체크
                            if ($logInfo.MaximumSizeInBytes -lt 10MB) {
                                $issues += "$logName (크기 미흡)"
                            }

                            # 덮어쓰기 / 백업 정책 체크
                            if ($logConfig -match "retention:\s*true") {
                                $issues += "$logName (덮어쓰기 비활성화)"
                            }
                        }
                        catch {
                            $issues += "$logName (로그 정보 접근 불가)"
                        }
                    }

                    if ($issues.Count -eq 0) {
                        $status = "양호"
                        $currentState = "Application, System, Security 이벤트 로그가 권고 크기 이상이며 덮어쓰기 또는 백업 정책이 설정됨"
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "다음 항목에서 설정 미흡: $($issues -join ', ')"
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "오류: $($_.Exception.Message)"
                }
            }
            
            "W-43" {
                ### 이벤트 로그 파일 접근 통제 설정
                # 양호 : 로그 디렉터리의 접근 권한에 Everyone 권한이 없는 경우
                # 취약 : 로그 디렉터리의 접근 권한에 Everyone 권한이 있는 경우
                $logPath = "$env:SystemRoot\System32\Winevt\Logs"
                try {
                    $acl = Get-Acl -Path $logPath
                    $hasEveryone = $false

                    foreach ($access in $acl.Access) {
                        if ($access.IdentityReference -eq "Everyone") {
                            $hasEveryone = $true
                            break
                        }
                    }

                    if ($hasEveryone) {
                        $status = "관리 필요"
                        $currentState = "이벤트 로그 디렉터리에 'Everyone' 권한이 설정되어 있습니다."
                    }
                    else {
                        $status = "양호"
                        $currentState = "이벤트 로그 디렉터리에 'Everyone' 권한이 없습니다."
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "오류: $($_.Exception.Message)"
                }
            }
            
            "W-44" {
                ### 원격으로 액세스할 수 있는 레지스트리 경로
                # 양호 : Remote Registry Service가 중지된 경우
                # 취약 : Remote Registry Service가 사용 중인 경우
                $remoteRegService = Get-Service "RemoteRegistry" -ErrorAction SilentlyContinue
                if ($null -ne $remoteRegService) {
                    if ($remoteRegService.Status -eq 'Running') {
                        $status = "관리 필요"
                        $currentState = "원격 레지스트리 서비스가 실행 중"
                    }
                    else {
                        $status = "양호"
                        $currentState = "원격 레지스트리 서비스가 중지됨"
                    }
                }
                else {
                    $status = "양호"
                    $currentState = "원격 레지스트리 서비스가 설치되지 않음"
                }
            }
            
            "W-45" {
                ### 백신 프로그램 설치
                # 양호 : 백신 프로그램이 설치된 경우
                # 취약 : 백신 프로그램이 설치되지 않은 경우
                $installedSoftware = Get-WmiObject -Class Win32_Product | Where-Object { $_.Name -like "*virus*" -or $_.Name -like "*antivirus*" }
                if ($installedSoftware) {
                    $status = "양호"
                    $currentState = "백신 프로그램이 설치됨"
                }
                else {
                    $status = "관리 필요"
                    $currentState = "백신 프로그램이 설치되지 않음"
                }
                # 대안 방법: Security Center2 네임스페이스에서 AntivirusProduct 클래스 사용
                $AntivirusProduct = Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntivirusProduct

                if ($AntivirusProduct) {
                    $status = "양호"
                    $currentState = "설치된 백신: " + ($AntivirusProduct.displayName -join ", ")
                } else {
                    $status = "관리 필요"
                    $currentState = "보안 센터에 등록된 백신 프로그램이 없음"
                }
            }
            
            "W-46" {
                ### SAM 파일 접근 통제 설정
                $samPath = "$env:SystemRoot\System32\config\SAM"
                $allowedAccounts = @(
                    "NT AUTHORITY\SYSTEM",
                    "BUILTIN\Administrators",
                    "NT SERVICE\TrustedInstaller"
                )

                try {
                    $acl = Get-Acl -Path $samPath

                    $unauthorizedAccess = $acl.Access | Where-Object {
                        $allowedAccounts -notcontains $_.IdentityReference.Value
                    }

                    if ($unauthorizedAccess.Count -eq 0) {
                        $status = "양호"
                        $currentState = "SAM 파일 접근 권한이 적절히 설정됨 (허용된 시스템 계정만 존재)"
                    }
                    else {
                        $status = "관리 필요"
                        $details = $unauthorizedAccess | ForEach-Object {
                            "[$($_.IdentityReference.Value)] 권한: $($_.FileSystemRights)"
                        }
                        $currentState = "비인가 권한 발견: " + ($details -join ", ")
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "SAM 파일 접근 권한 확인 실패: $($_.Exception.Message)"
                }
            }
            
            "W-47" {
                ### 화면보호기 설정
                # 양호 : 화면 보호기를 설정하고 대기 시간이 10분 이하의 값으로 설정되어 있으며, 화면 보호기 해제를 위한 암호를 사용하는 경우
                # 취약 : 화면 보호기가 설정되지 않았거나 암호를 사용하지 않거나, 화면 보호기 대기 시간이 10분을 초과한 값으로 설정된 경우
                $screenSaverRegPath = "HKCU:\Control Panel\Desktop"
                try {
                    $screenSaverActive = Get-ItemProperty -Path $screenSaverRegPath -Name "ScreenSaveActive" -ErrorAction SilentlyContinue
                    $screenSaverTimeout = Get-ItemProperty -Path $screenSaverRegPath -Name "ScreenSaveTimeOut" -ErrorAction SilentlyContinue
                    $screenSaverSecure = Get-ItemProperty -Path $screenSaverRegPath -Name "ScreenSaverIsSecure" -ErrorAction SilentlyContinue

                    if ($null -ne $screenSaverActive -and $screenSaverActive.ScreenSaveActive -eq "1" `
                        -and $null -ne $screenSaverTimeout -and [int]$screenSaverTimeout.ScreenSaveTimeOut -le 600 `
                        -and $null -ne $screenSaverSecure -and $screenSaverSecure.ScreenSaverIsSecure -eq "1") {
                        $status = "양호"
                        $currentState = "화면 보호기 설정이 적절히 구성됨"
                    }
                    else {
                        $status = "관리 필요"
                        $currentState = "화면 보호기 설정이 미흡함 (활성화: $($screenSaverActive.ScreenSaveActive), 대기 시간: $($screenSaverTimeout.ScreenSaveTimeOut), 암호 사용: $($screenSaverSecure.ScreenSaverIsSecure))"
                    }
                }
                catch {
                    $status = "점검 불가"
                    $currentState = "화면 보호기 설정 확인 실패: $($_.Exception.Message)"
                }
            }
            
            "W-48" {
                # 로그온하지 않고 시스템 종료 허용
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-49" {
                # 원격 시스템에서 강제로 시스템 종료
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-50" {
                # 보안 감사를 로그할 수 없는 경우 즉시 시스템 종료
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-51" {
                # SAM 계정과 공유의 익명 열거 허용 안 함
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-52" {
                # Autologon 기능 제어
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-53" {
                # 이동식 미디어 포맷 및 꺼내기 허용
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-54" {
                # DoS 공격 방어 레지스트리 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-55" {
                # 사용자가 프린터 드라이버를 설치할 수 없게 함
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-56" {
                # SMB 세션 중단 관리 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-57" {
                # 로그온 시 경고 메시지 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-58" {
                # 사용자별 홈 디렉터리 권한 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-59" {
                # LAN Manager 인증 수준
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-60" {
                # 보안 채널 데이터 디지털 암호화 또는 서명
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-61" {
                # 파일 및 디렉토리 보호
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-62" {
                # 시작프로그램 목록 분석
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-63" {
                # 도메인 컨트롤러-사용자의 시간 동기화
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-64" {
                # 윈도우 방화벽 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            default {
                $status = "점검 불가"
                $currentState = "등록되지 않은 검사 코드"
            }
        }
        
        return @{
            item_code = $ItemCode
            check_title = $CheckDef.check_title
            status = $status
            current_state = $currentState
            expected_state = $CheckDef.expected_state
            operational_meaning = $CheckDef.operational_meaning
        }
    }
    catch {
        return @{
            item_code = $ItemCode
            check_title = $CheckDef.check_title
            status = "점검 불가"
            current_state = "오류: $_"
            expected_state = $CheckDef.expected_state
            operational_meaning = $CheckDef.operational_meaning
        }
    }
}

# ========================================
# 보안 검사 실행
# ========================================

function Invoke-SecurityScan {
    Write-Host "[2/5] 보안 검사 실행 중..." -ForegroundColor Yellow
    Write-Host ""
    
    $definitions = Get-CheckDefinitions
    $results = @()
    
    $total = $definitions.checks.Count
    $current = 0
    
    foreach ($check in $definitions.checks) {
        $current++
        $percent = [math]::Round(($current / $total) * 100)
        
        Write-Host "[$current/$total] $($check.check_title) 검사 중..." -NoNewline
        
        $result = Test-SecurityCheck -ItemCode $check.item_code -CheckDef $check
        $results += $result
        
        $color = switch ($result.status) {
            "양호" { "Green" }
            "관리 필요" { "Red" }
            "수동 확인 필요" { "Yellow" }
            "부분 양호" { "Yellow" }
            "점검 불가" { "Gray" }
            default { "White" }
        }
        Write-Host " [$($result.status)]" -ForegroundColor $color
    }
    
    Write-Host ""
    Write-Host "✓ 보안 검사 완료" -ForegroundColor Green
    Write-Host ""
    
    # 결과 요약
    $summary = @{
        good = ($results | Where-Object {$_.status -eq "양호"}).Count
        needs_management = ($results | Where-Object {$_.status -eq "관리 필요"}).Count
        manual_check = ($results | Where-Object {$_.status -eq "수동 확인 필요"}).Count
        partial_good = ($results | Where-Object {$_.status -eq "부분 양호"}).Count
        check_failed = ($results | Where-Object {$_.status -eq "점검 불가"}).Count
    }
    
    Write-Host "검사 결과 요약:" -ForegroundColor Cyan
    Write-Host "  양호: $($summary.good) 건" -ForegroundColor Green
    Write-Host "  관리 필요: $($summary.needs_management) 건" -ForegroundColor Red
    Write-Host "  수동 확인 필요: $($summary.manual_check) 건" -ForegroundColor Yellow
    Write-Host "  부분 양호: $($summary.partial_good) 건" -ForegroundColor Yellow
    Write-Host "  점검 불가: $($summary.check_failed) 건" -ForegroundColor Gray
    Write-Host ""
    
    return @{
        metadata = @{
            scan_time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            computer_name = $env:COMPUTERNAME
            os_version = [System.Environment]::OSVersion.VersionString
            total_checks = $results.Count
            based_on = $definitions.metadata.based_on
        }
        summary = $summary
        results = $results
    }
}

# ========================================
# 결과 저장
# ========================================

function Save-ScanResult {
    param([hashtable]$ScanData)
    
    Write-Host "[3/5] 결과 저장 중..." -ForegroundColor Yellow
    
    $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
    $filename = "scan_$timestamp.json"
    $Global:CurrentResultFile = Join-Path $Global:ResultsFolder $filename
    
    $ScanData | ConvertTo-Json -Depth 10 | Out-File -FilePath $Global:CurrentResultFile -Encoding UTF8
    
    Write-Host "✓ 결과 저장 완료: $Global:CurrentResultFile" -ForegroundColor Green
    Write-Host ""
}

# ========================================
# 내장 웹 서버
# ========================================

function Start-EmbeddedWebServer {
    Write-Host "[4/5] 웹 대시보드 준비 중..." -ForegroundColor Yellow
    
    # 포트 찾기
    $port = 8080
    $maxAttempts = 10
    for ($i = 0; $i -lt $maxAttempts; $i++) {
        $testPort = $port + $i
        $inUse = Get-NetTCPConnection -LocalPort $testPort -ErrorAction SilentlyContinue
        if (-not $inUse) {
            $port = $testPort
            break
        }
    }
    
    Write-Host "✓ 포트 $port 사용" -ForegroundColor Green
    
    # 실행 경로 결정 (EXE 또는 스크립트)
    $basePath = if ($PSScriptRoot -and (Test-Path (Join-Path $PSScriptRoot "dashboard"))) {
        $PSScriptRoot
    } elseif ($PSScriptRoot) {
        Split-Path -Parent $PSScriptRoot
    } else {
        (Get-Location).Path
    }
    
    # dashboard 폴더 확인 (EXE 배포 구조)
    $dashboardFolder = Join-Path $basePath "dashboard"
    $useDashboardFolder = Test-Path $dashboardFolder
    
    # 대시보드 파일 확인
    $dashboardFiles = @(
        (Join-Path $basePath "dashboard\dashboard.html"),
        (Join-Path $basePath "dashboard\dashboard.css"),
        (Join-Path $basePath "dashboard\dashboard.js"),
        (Join-Path $basePath "config\check_definitions.json")
    )
    $allFilesExist = $true
    
    foreach ($filePath in $dashboardFiles) {
        if (-not (Test-Path $filePath)) {
            Write-Warning "경고: 대시보드 의존 파일이 없습니다. ($filePath)"
            $allFilesExist = $false
        }
    }
    
    if (-not $allFilesExist) {
        Write-Host ""
        Write-Host "대시보드 파일이 없어 결과 파일만 저장되었습니다." -ForegroundColor Yellow
        Write-Host "결과 위치: $Global:CurrentResultFile" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Enter 키를 눌러 종료..." -ForegroundColor Gray
        Read-Host
        return
    }
    
    Write-Host "✓ 대시보드 파일 확인 완료" -ForegroundColor Green
    Write-Host ""
    
    # HTTP 서버 시작
    Write-Host "HTTP 서버 시작 중..." -ForegroundColor Yellow
    
    $serverRoot = if ($useDashboardFolder) { $basePath } else { $basePath }
    
    $serverJob = Start-Job -ScriptBlock {
        param($Port, $ServerRoot, $ResultFile, $UseDashboardFolder)
        
        $listener = New-Object System.Net.HttpListener
        $listener.Prefixes.Add("http://localhost:$Port/")
        $listener.Start()
        
        while ($listener.IsListening) {
            try {
                $context = $listener.GetContext()
                $request = $context.Request
                $response = $context.Response
                
                $path = $request.Url.LocalPath
                
                # 결과 JSON 서빙
                if ($path -eq "/api/result.json") {
                    if (Test-Path $ResultFile) {
                        $jsonContent = Get-Content $ResultFile -Raw -Encoding UTF8
                        $buffer = [System.Text.Encoding]::UTF8.GetBytes($jsonContent)
                        $response.ContentType = "application/json; charset=utf-8"
                        $response.ContentLength64 = $buffer.Length
                        $response.OutputStream.Write($buffer, 0, $buffer.Length)
                    }
                    $response.OutputStream.Close()
                    continue
                }
                
                # 정적 파일 서빙
                if ($path -eq "/" -or $path -eq "") {
                    $path = "/dashboard/dashboard.html"
                }
                
                # 경로 정규화
                $requestPath = $path.TrimStart('/').Replace('/', '\')
                $filePath = Join-Path $ServerRoot $requestPath
                
                # 파일이 없으면 dashboard 폴더에서 찾기
                if (Test-Path $filePath) {
                    $content = [System.IO.File]::ReadAllBytes($filePath)
                    
                    $extension = [System.IO.Path]::GetExtension($filePath)
                    $response.ContentType = switch ($extension) {
                        ".html" { "text/html; charset=utf-8" }
                        ".css" { "text/css; charset=utf-8" }
                        ".js" { "application/javascript; charset=utf-8" }
                        ".json" { "application/json; charset=utf-8" }
                        ".ico" { "image/x-icon" }
                        default { "text/plain; charset=utf-8" }
                    }
                    
                    $response.ContentLength64 = $content.Length
                    $response.OutputStream.Write($content, 0, $content.Length)
                }
                else {
                    $response.StatusCode = 404
                    $buffer = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found: $filePath")
                    $response.ContentLength64 = $buffer.Length
                    $response.OutputStream.Write($buffer, 0, $buffer.Length)
                }
                
                $response.OutputStream.Close()
            }
            catch {
                # 에러 무시하고 계속
            }
        }
        
        $listener.Stop()
    } -ArgumentList $port, $serverRoot, $Global:CurrentResultFile, $useDashboardFolder
    
    Start-Sleep -Milliseconds 500
    Write-Host "✓ HTTP 서버 시작 완료" -ForegroundColor Green
    Write-Host ""
    
    # 브라우저 실행
    if (-not $SkipBrowser) {
        Write-Host "[5/5] 브라우저에서 결과 표시 중..." -ForegroundColor Yellow
        
        $dashboardUrl = "http://localhost:$port/?autoload=true"
        
        Write-Host "대시보드 URL: $dashboardUrl" -ForegroundColor Cyan
        Write-Host ""
        
        try {
            Start-Process $dashboardUrl
            Write-Host "✓ 브라우저에서 대시보드 자동 실행됨" -ForegroundColor Green
            Write-Host "✓ 결과가 자동으로 로드됩니다" -ForegroundColor Green
        }
        catch {
            Write-Warning "브라우저 자동 실행 실패"
            Write-Host "수동으로 브라우저를 열고 다음 주소로 이동하세요:" -ForegroundColor Yellow
            Write-Host $dashboardUrl -ForegroundColor Cyan
        }
    }
    else {
        Write-Host "[5/5] 브라우저 실행 건너뜀" -ForegroundColor Yellow
        Write-Host "대시보드 URL: http://localhost:$port" -ForegroundColor Cyan
    }
    
    Write-Host ""
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host "보안 검사 완료!" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host ""
    Write-Host "서버가 실행 중입니다. 종료하려면 Enter 키를 누르세요..." -ForegroundColor Yellow
    Read-Host
    
    # 서버 종료
    Stop-Job $serverJob
    Remove-Job $serverJob
}

# ========================================
# 메인 실행
# ========================================

function Main {
    Clear-Host
    Write-Banner
    
    try {
        # 1. 환경 초기화
        Initialize-Environment
        
        # 2. 보안 검사 실행
        $scanData = Invoke-SecurityScan
        
        # 3. 결과 저장
        Save-ScanResult -ScanData $scanData
        
        # 4. 웹 대시보드 실행
        Start-EmbeddedWebServer
    }
    catch {
        Write-Host ""
        Write-Host "오류 발생: $_" -ForegroundColor Red
        Write-Host ""
        Write-Host "Enter 키를 눌러 종료..." -ForegroundColor Gray
        Read-Host
        exit 1
    }
}

# 스크립트 실행
Main
