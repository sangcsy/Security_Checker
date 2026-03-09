<#
.SYNOPSIS
    Windows 보안 구성 검사 올인원 도구 (전체 20개 검사)

.DESCRIPTION
    KISA 기술적 취약점 분석·평가 방법 상세가이드 기반
    검사 수행 → 결과 저장 → 웹 대시보드 자동 실행
    
    단일 파일로 모든 기능 제공 (서버/네트워크 불필요)

.EXAMPLE
    .\SecurityChecker-AllInOne-Full.ps1
    
.NOTES
    버전: 2.0
    작성자: Security Operations Team
#>

param(
    [Parameter(Mandatory=$false)]
    [switch]$SkipBrowser,
    
    [Parameter(Mandatory=$false)]
    [switch]$AdminCheck
)

$ErrorActionPreference = "Stop"
$Global:ScriptVersion = "2.0"
$Global:ResultsFolder = "$env:APPDATA\SecurityChecker\Results"
$Global:CurrentResultFile = ""

# ========================================
# 유틸리티 함수
# ========================================

function Write-Banner {
    $banner = @"
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║          Windows 보안 구성 검사 도구 v$Global:ScriptVersion         ║
║                                                                  ║
║          KISA 기술적 취약점 분석·평가 방법 상세가이드 기반             ║
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
            based_on = "KISA 기술적 취약점 분석·평가 방법 상세가이드"
            target_os = "Windows"
        }
        checks = @(
            @{ item_code = "W-01"; category = "계정 관리"; check_title = "Administrator 계정 이름 변경"; severity = "상"; expected_state = "Administrator가 아닌 다른 이름으로 변경됨"; operational_meaning = "기본 관리자 계정 이름을 변경하면 자동화된 공격 도구로부터 계정을 보호할 수 있습니다." },
            @{ item_code = "W-02"; category = "계정 관리"; check_title = "Guest 계정 비활성화"; severity = "상"; expected_state = "Guest 계정이 비활성화되어 있음"; operational_meaning = "Guest 계정을 비활성화하여 인증되지 않은 사용자의 시스템 접근을 차단합니다." },
            @{ item_code = "W-03"; category = "계정 관리"; check_title = "불필요한 계정 존재 여부"; severity = "상"; expected_state = "불필요한 계정이 존재하지 않음"; operational_meaning = "사용하지 않는 계정을 제거하여 공격 표면을 줄입니다." },
            @{ item_code = "W-04"; category = "계정 관리"; check_title = "암호 복잡성 설정"; severity = "상"; expected_state = "암호 복잡성 정책이 활성화되어 있음"; operational_meaning = "복잡한 암호 사용을 강제하여 무차별 대입 공격을 방어합니다." },
            @{ item_code = "W-05"; category = "계정 관리"; check_title = "암호 최소 길이 설정"; severity = "상"; expected_state = "암호 최소 길이가 8자 이상으로 설정됨"; operational_meaning = "긴 암호를 사용하여 암호 추측 공격에 대한 저항력을 높입니다." },
            @{ item_code = "W-06"; category = "계정 관리"; check_title = "암호 최대 사용 기간"; severity = "상"; expected_state = "암호 최대 사용 기간이 60일 이하로 설정됨"; operational_meaning = "정기적인 암호 변경으로 장기간 노출된 암호의 위험을 감소시킵니다." },
            @{ item_code = "W-07"; category = "계정 관리"; check_title = "암호 최소 사용 기간"; severity = "중"; expected_state = "암호 최소 사용 기간이 1일 이상으로 설정됨"; operational_meaning = "즉시 암호를 재변경하는 것을 방지하여 암호 정책을 우회하는 것을 막습니다." },
            @{ item_code = "W-08"; category = "계정 관리"; check_title = "계정 잠금 임계값 설정"; severity = "상"; expected_state = "계정 잠금 임계값이 5회 이하로 설정됨"; operational_meaning = "반복된 로그인 실패 시 계정을 잠가 무차별 대입 공격을 방어합니다." },
            @{ item_code = "W-09"; category = "감사 정책"; check_title = "로그온 감사 설정"; severity = "상"; expected_state = "로그온 성공 및 실패 감사가 활성화됨"; operational_meaning = "로그온 활동을 기록하여 무단 접근 시도를 탐지합니다." },
            @{ item_code = "W-10"; category = "서비스 관리"; check_title = "불필요한 서비스 중지"; severity = "상"; expected_state = "불필요한 서비스가 중지되어 있음"; operational_meaning = "불필요한 서비스를 중지하여 공격 표면을 줄이고 시스템 리소스를 절약합니다." },
            @{ item_code = "W-11"; category = "공유 폴더"; check_title = "불필요한 공유 제거"; severity = "상"; expected_state = "기본 공유 외 불필요한 공유가 없음"; operational_meaning = "불필요한 파일 공유를 제거하여 정보 유출 위험을 감소시킵니다." },
            @{ item_code = "W-12"; category = "서비스 관리"; check_title = "원격 데스크톱 서비스 보안"; severity = "상"; expected_state = "원격 데스크톱이 비활성화되어 있거나 보안 설정이 적용됨"; operational_meaning = "원격 접속을 제한하여 외부 공격자의 접근을 차단합니다." },
            @{ item_code = "W-13"; category = "보안 옵션"; check_title = "UAC 설정"; severity = "상"; expected_state = "UAC가 활성화되어 있음"; operational_meaning = "UAC를 통해 관리자 권한이 필요한 작업에 대한 승인을 요구하여 악성 소프트웨어의 무단 실행을 방지합니다." },
            @{ item_code = "W-14"; category = "패치 관리"; check_title = "Windows 업데이트 설정"; severity = "상"; expected_state = "자동 업데이트가 활성화되어 있음"; operational_meaning = "최신 보안 패치를 적용하여 알려진 취약점으로부터 시스템을 보호합니다." },
            @{ item_code = "W-15"; category = "방화벽"; check_title = "Windows 방화벽 설정"; severity = "상"; expected_state = "모든 프로필에서 방화벽이 활성화되어 있음"; operational_meaning = "방화벽을 통해 불필요한 네트워크 연결을 차단하여 외부 공격을 방어합니다." },
            @{ item_code = "W-16"; category = "보안 옵션"; check_title = "화면 보호기 설정"; severity = "중"; expected_state = "화면 보호기가 설정되고 암호로 보호됨"; operational_meaning = "무인 시스템에 대한 물리적 접근을 방지합니다." },
            @{ item_code = "W-17"; category = "보안 옵션"; check_title = "로그온 법적 고지"; severity = "하"; expected_state = "로그온 시 법적 고지가 표시됨"; operational_meaning = "무단 접속 시 법적 책임을 경고하여 내부자 위협을 감소시킵니다." },
            @{ item_code = "W-18"; category = "계정 관리"; check_title = "Administrators 그룹 관리"; severity = "상"; expected_state = "최소 권한 원칙에 따라 관리"; operational_meaning = "관리자 그룹 구성원을 최소화하여 권한 남용을 방지합니다." },
            @{ item_code = "W-19"; category = "보안 옵션"; check_title = "이동식 미디어 자동 실행 차단"; severity = "중"; expected_state = "자동 실행이 비활성화됨"; operational_meaning = "악성 코드가 포함된 이동식 미디어의 자동 실행을 차단합니다." },
            @{ item_code = "W-20"; category = "보안 옵션"; check_title = "Windows Defender 실시간 보호"; severity = "상"; expected_state = "실시간 보호가 활성화되어 있음"; operational_meaning = "실시간 악성 코드 탐지를 통해 시스템 감염을 예방합니다." }
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
                # Administrator 계정 이름 변경
                $adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}
                $adminName = $adminAccount.Name
                $status = if ($adminName -ne "Administrator") { "양호" } else { "관리 필요" }
                $currentState = "현재 Administrator SID(-500) 계정 이름: $adminName"
            }
            
            "W-02" {
                # Guest 계정 비활성화
                $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
                if ($null -eq $guest) {
                    $status = "양호"
                    $currentState = "Guest 계정이 존재하지 않음"
                } else {
                    $status = if (-not $guest.Enabled) { "양호" } else { "관리 필요" }
                    $enabled = if ($guest.Enabled) { "활성화" } else { "비활성화" }
                    $currentState = "Guest 계정 상태: $enabled"
                }
            }
            
            "W-03" {
                # 불필요한 계정 존재 여부
                $enabledUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
                $userList = ($enabledUsers | ForEach-Object { $_.Name }) -join ', '
                $status = "수동 확인 필요"
                $currentState = "활성화된 계정 ($($enabledUsers.Count)개): $userList"
            }
            
            "W-04" {
                # 암호 복잡성 설정
                $netAccounts = net accounts 2>$null
                $complexityLine = $netAccounts | Select-String "암호는 복잡성을 만족해야 함|Password must meet complexity" | Select-Object -First 1
                $complexityEnabled = $complexityLine -match "예|Yes"
                $status = if ($complexityEnabled) { "양호" } else { "관리 필요" }
                $stateText = if ($complexityEnabled) { "활성화" } else { "비활성화" }
                $currentState = "암호 복잡성: $stateText"
            }
            
            "W-05" {
                # 암호 최소 길이 설정
                $netAccounts = net accounts 2>$null
                $minPasswordLength = $netAccounts | Select-String "최소 암호 길이|Minimum password length"
                if ($minPasswordLength -and $minPasswordLength -match '(\d+)') {
                    $length = [int]$Matches[1]
                    $status = if ($length -ge 8) { "양호" } else { "관리 필요" }
                    $currentState = "암호 최소 길이: $length 자"
                } else {
                    $status = "점검 불가"
                    $currentState = "암호 최소 길이를 확인할 수 없음"
                }
            }
            
            "W-06" {
                # 암호 최대 사용 기간
                $netAccounts = net accounts 2>$null
                $maxPasswordAge = $netAccounts | Select-String "최대 암호 사용 기간|Maximum password age"
                if ($maxPasswordAge -match '(\d+)') {
                    $days = [int]$Matches[1]
                    $status = if ($days -gt 0 -and $days -le 60) { "양호" } else { "관리 필요" }
                    $currentState = "암호 최대 사용 기간: $days 일"
                } elseif ($maxPasswordAge -match "무제한|Unlimited") {
                    $status = "관리 필요"
                    $currentState = "암호 최대 사용 기간: 무제한"
                } else {
                    $status = "점검 불가"
                    $currentState = "암호 최대 사용 기간을 확인할 수 없음"
                }
            }
            
            "W-07" {
                # 암호 최소 사용 기간
                $netAccounts = net accounts 2>$null
                $minPasswordAge = $netAccounts | Select-String "최소 암호 사용 기간|Minimum password age"
                if ($minPasswordAge -match '(\d+)') {
                    $days = [int]$Matches[1]
                    $status = if ($days -ge 1) { "양호" } else { "관리 필요" }
                    $currentState = "암호 최소 사용 기간: $days 일"
                } else {
                    $status = "점검 불가"
                    $currentState = "암호 최소 사용 기간을 확인할 수 없음"
                }
            }
            
            "W-08" {
                # 계정 잠금 임계값 설정
                $netAccounts = net accounts 2>$null
                $lockoutThreshold = $netAccounts | Select-String "잠금 임계값|Lockout threshold"
                if ($lockoutThreshold -match '(\d+)') {
                    $threshold = [int]$Matches[1]
                    $status = if ($threshold -ge 1 -and $threshold -le 5) { "양호" } else { "관리 필요" }
                    $currentState = "계정 잠금 임계값: $threshold 회"
                } elseif ($lockoutThreshold -match "없음|Never") {
                    $status = "관리 필요"
                    $currentState = "계정 잠금 임계값: 설정되지 않음"
                } else {
                    $status = "점검 불가"
                    $currentState = "계정 잠금 임계값을 확인할 수 없음"
                }
            }
            
            "W-09" {
                # 로그온 감사 설정
                $auditResult = auditpol /get /category:"Logon/Logoff" 2>$null
                if ($auditResult) {
                    $hasSuccess = $auditResult -match "Success"
                    $hasFailure = $auditResult -match "Failure"
                    if ($hasSuccess -and $hasFailure) { $status = "양호" }
                    elseif ($hasSuccess -or $hasFailure) { $status = "부분 양호" }
                    else { $status = "관리 필요" }
                    $currentState = "로그온 감사 - 성공: $hasSuccess, 실패: $hasFailure"
                } else {
                    $status = "점검 불가"
                    $currentState = "감사 정책 정보를 가져올 수 없음 (관리자 권한 필요)"
                }
            }
            
            "W-10" {
                # 불필요한 서비스 중지
                $runningServices = Get-Service | Where-Object {$_.Status -eq 'Running'}
                $riskyServices = @('Telnet', 'RemoteRegistry', 'SNMP')
                $foundRiskyServices = $runningServices | Where-Object {$_.Name -in $riskyServices}
                if ($foundRiskyServices) {
                    $status = "관리 필요"
                    $currentState = "실행 중인 위험 서비스 발견: $($foundRiskyServices.Name -join ', ')"
                } else {
                    $status = "수동 확인 필요"
                    $currentState = "실행 중인 서비스: $($runningServices.Count) 개 (위험 서비스 미발견)"
                }
            }
            
            "W-11" {
                # 불필요한 공유 제거
                $shares = Get-SmbShare | Where-Object {$_.Special -eq $false}
                if ($shares) {
                    $shareList = ($shares | ForEach-Object { "$($_.Name)" }) -join ', '
                    $status = "수동 확인 필요"
                    $currentState = "공유 폴더 발견: $shareList"
                } else {
                    $status = "양호"
                    $currentState = "사용자 정의 공유 폴더 없음"
                }
            }
            
            "W-12" {
                # 원격 데스크톱 서비스 보안
                $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
                if ($null -eq $rdpSetting) {
                    $status = "점검 불가"
                    $currentState = "원격 데스크톱 설정을 확인할 수 없음"
                } else {
                    $rdpEnabled = $rdpSetting.fDenyTSConnections -eq 0
                    if (-not $rdpEnabled) {
                        $status = "양호"
                        $currentState = "원격 데스크톱: 비활성화"
                    } else {
                        $nlaSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                        $nlaEnabled = $nlaSetting.UserAuthentication -eq 1
                        $status = if ($nlaEnabled) { "부분 양호" } else { "관리 필요" }
                        $nlaText = if ($nlaEnabled) { "사용" } else { "미사용" }
                        $currentState = "원격 데스크톱: 활성화, NLA: $nlaText"
                    }
                }
            }
            
            "W-13" {
                # UAC 설정
                $uacSetting = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue
                if ($null -eq $uacSetting) {
                    $status = "점검 불가"
                    $currentState = "UAC 설정을 확인할 수 없음"
                } else {
                    $uacEnabled = $uacSetting.EnableLUA -eq 1
                    $status = if ($uacEnabled) { "양호" } else { "관리 필요" }
                    $stateText = if ($uacEnabled) { "활성화" } else { "비활성화" }
                    $currentState = "UAC: $stateText"
                }
            }
            
            "W-14" {
                # Windows 업데이트 설정
                $wuService = Get-Service -Name 'wuauserv' -ErrorAction SilentlyContinue
                if ($wuService) {
                    $serviceAuto = $wuService.StartType -in @('Automatic', 'AutomaticDelayedStart')
                    $status = if ($serviceAuto) { "양호" } else { "관리 필요" }
                    $currentState = "Windows Update 서비스 - 상태: $($wuService.Status), 시작 유형: $($wuService.StartType)"
                } else {
                    $status = "점검 불가"
                    $currentState = "Windows Update 서비스를 확인할 수 없음"
                }
            }
            
            "W-15" {
                # Windows 방화벽 설정
                $firewallProfiles = Get-NetFirewallProfile
                $allEnabled = ($firewallProfiles | Where-Object {$_.Enabled -eq $false}).Count -eq 0
                $profileStatus = $firewallProfiles | ForEach-Object {
                    $stateText = if ($_.Enabled) { "활성화" } else { "비활성화" }
                    "$($_.Name): $stateText"
                }
                $status = if ($allEnabled) { "양호" } else { "관리 필요" }
                $currentState = "방화벽 프로필 - $($profileStatus -join ', ')"
            }
            
            "W-16" {
                # 화면 보호기 설정
                $screenSaverSecure = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue
                if ($null -eq $screenSaverSecure) {
                    $status = "관리 필요"
                    $currentState = "화면 보호기 암호 설정 없음"
                } else {
                    $isSecure = $screenSaverSecure.ScreenSaverIsSecure -eq 1
                    $status = if ($isSecure) { "양호" } else { "관리 필요" }
                    $stateText = if ($isSecure) { "설정됨" } else { "미설정" }
                    $currentState = "화면 보호기 암호: $stateText"
                }
            }
            
            "W-17" {
                # 로그온 법적 고지
                $legalNotice = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -ErrorAction SilentlyContinue
                if ($null -eq $legalNotice -or [string]::IsNullOrWhiteSpace($legalNotice.LegalNoticeCaption)) {
                    $status = "관리 필요"
                    $currentState = "로그온 법적 고지 미설정"
                } else {
                    $status = "양호"
                    $currentState = "로그온 법적 고지 설정됨"
                }
            }
            
            "W-18" {
                # Administrators 그룹 관리
                $adminMembers = Get-LocalGroupMember -Group 'Administrators' -ErrorAction SilentlyContinue
                if ($adminMembers) {
                    $memberList = ($adminMembers | ForEach-Object { $_.Name }) -join ', '
                    $status = "수동 확인 필요"
                    $currentState = "Administrators 그룹 구성원 ($($adminMembers.Count)명): $memberList"
                } else {
                    $status = "점검 불가"
                    $currentState = "Administrators 그룹 정보를 확인할 수 없음"
                }
            }
            
            "W-19" {
                # 이동식 미디어 자동 실행 차단
                $autoRunSetting = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue
                if ($null -eq $autoRunSetting) {
                    $status = "관리 필요"
                    $currentState = "자동 실행 설정 없음 (기본값: 일부 활성화)"
                } else {
                    $value = $autoRunSetting.NoDriveTypeAutoRun
                    $status = if ($value -eq 255) { "양호" } else { "관리 필요" }
                    $stateText = if ($value -eq 255) { "모든 드라이브 비활성화" } else { "일부 활성화" }
                    $currentState = "자동 실행: $stateText (값: $value)"
                }
            }
            
            "W-20" {
                # Windows Defender 실시간 보호
                $defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
                if ($null -eq $defenderPrefs) {
                    $status = "점검 불가"
                    $currentState = "Windows Defender 설정을 확인할 수 없음"
                } else {
                    $realtimeEnabled = -not $defenderPrefs.DisableRealtimeMonitoring
                    $status = if ($realtimeEnabled) { "양호" } else { "관리 필요" }
                    $stateText = if ($realtimeEnabled) { "활성화" } else { "비활성화" }
                    $currentState = "실시간 보호: $stateText"
                }
            }
            
            default {
                $status = "점검 불가"
                $currentState = "검사 함수 미구현"
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
