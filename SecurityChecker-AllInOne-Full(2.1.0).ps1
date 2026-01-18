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
    버전: 2.1.0
    작성자: Security Checker (Lee SeungWon)
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipBrowser,
    
    [Parameter(Mandatory=$false)]
    [switch]$AdminCheck
)

$ErrorActionPreference = "Stop"
$Global:ScriptVersion = "2.1.0"
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
            version = "2.1.0"
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
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-14" {
                # 원격터미널 접속 가능한 사용자 그룹 제한
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-15" {
                # 사용자 개인키 사용 시 암호 입력
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-16" {
                # 공유 권한 및 사용자 그룹 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-17" {
                # 하드디스크 기본 공유 제거
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-18" {
                # 불필요한 서비스 제거
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-19" {
                # 불필요한 IIS 서비스 구동 점검
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-20" {
                # NetBIOS 바인딩 서비스 구동 점검
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-21" {
                # 암호화되지 않는 FTP 서비스 비활성화
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-22" {
                # FTP 디렉토리 접근권한 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-23" {
                # 공유 서비스에 대한 익명 접근 제한 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-24" {
                # FTP 접근 제어 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-25" {
                # DNS Zone Transfer 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-26" {
                # RDS(Remote Data Services) 제거
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-27" {
                # 최신 Windows OS Build 버전 적용
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-28" {
                # 터미널 서비스 암호화 수준 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-29" {
                # 불필요한 SNMP 서비스 구동 점검
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-30" {
                # SNMP Community String 복잡성 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-31" {
                # SNMP Access control 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-32" {
                # DNS 서비스 구동 점검
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-33" {
                # HTTP/FTP/SMTP 배너 차단
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-34" {
                # Telnet 서비스 비활성화
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-35" {
                # 불필요한 ODBC/OLE-DB 데이터 소스와 드라이브 제거
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-36" {
                # 원격터미널 접속 타임아웃 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-37" {
                # 예약된 작업에 의심스러운 명령이 등록되어 있는지 점검
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-38" {
                # 주기적 보안 패치 및 벤더 권고사항 적용
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-39" {
                # 백신 프로그램 업데이트
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-40" {
                # 정책에 따른 시스템 로깅 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-41" {
                # NTP 및 시각 동기화 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-42" {
                # 이벤트 로그 관리 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-43" {
                # 이벤트 로그 파일 접근 통제 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-44" {
                # 원격으로 액세스할 수 있는 레지스트리 경로
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-45" {
                # 백신 프로그램 설치
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-46" {
                # SAM 파일 접근 통제 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
            }
            
            "W-47" {
                # 화면보호기 설정
                # TODO: 검사 로직 구현
                $status = "점검 불가"
                $currentState = "구현 대기 중"
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
    $basePath = if ($PSScriptRoot) { $PSScriptRoot } else { Get-Location }
    
    # dashboard 폴더 확인 (EXE 배포 구조)
    $dashboardFolder = Join-Path $basePath "dashboard"
    $useDashboardFolder = Test-Path $dashboardFolder
    
    # 대시보드 파일 확인
    $dashboardFiles = @("dashboard.html", "dashboard.css", "dashboard.js", "check_definitions.json")
    $allFilesExist = $true
    
    foreach ($file in $dashboardFiles) {
        if ($useDashboardFolder) {
            $filePath = Join-Path $dashboardFolder $file
        } else {
            $filePath = Join-Path $basePath $file
        }
        
        if (-not (Test-Path $filePath)) {
            Write-Warning "경고: $file 파일이 없습니다. ($filePath)"
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
                    $path = if ($UseDashboardFolder) { "/dashboard/dashboard.html" } else { "/dashboard.html" }
                }
                
                # 경로 정규화
                $requestPath = $path.TrimStart('/').Replace('/', '\')
                $filePath = Join-Path $ServerRoot $requestPath
                
                # 파일이 없으면 dashboard 폴더에서 찾기
                if (-not (Test-Path $filePath) -and $UseDashboardFolder) {
                    $filePath = Join-Path $ServerRoot "dashboard\$requestPath"
                }
                
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
