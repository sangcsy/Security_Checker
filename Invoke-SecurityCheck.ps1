<#
.SYNOPSIS
    Windows 보안 구성 검사 도구

.DESCRIPTION
    KISA 기술적 취약점 분석·평가 방법 상세가이드를 기반으로 
    Windows 시스템의 보안 구성 상태를 검사합니다.
    
    이 도구는 읽기 전용 검사만 수행하며, 시스템 설정을 변경하지 않습니다.

.PARAMETER CheckDefinitionPath
    검사 정의 JSON 파일 경로

.PARAMETER OutputPath
    결과 JSON 파일 저장 경로

.PARAMETER CheckCodes
    특정 검사 항목만 실행 (예: "W-01","W-02")

.EXAMPLE
    .\Invoke-SecurityCheck.ps1
    모든 검사 항목을 실행하고 결과를 화면에 출력

.EXAMPLE
    .\Invoke-SecurityCheck.ps1 -OutputPath "result.json"
    모든 검사 항목을 실행하고 결과를 파일로 저장

.EXAMPLE
    .\Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02"
    특정 검사 항목만 실행
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CheckDefinitionPath = "$PSScriptRoot\check_definitions.json",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [string[]]$CheckCodes = @()
)

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Import-CheckDefinitions {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        throw "검사 정의 파일을 찾을 수 없습니다: $Path"
    }
    
    try {
        $content = Get-Content -Path $Path -Raw -Encoding UTF8
        $definitions = $content | ConvertFrom-Json
        return $definitions
    }
    catch {
        throw "검사 정의 파일을 읽는 중 오류 발생: $_"
    }
}

function Test-W01 {
    param($checkDef)
    
    try {
        $adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}
        $adminName = $adminAccount.Name
        
        $status = if ($adminName -ne "Administrator") { "양호" } else { "관리 필요" }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = "현재 Administrator SID(-500) 계정 이름: $adminName"
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

function Test-W02 {
    param($checkDef)
    
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        
        if ($null -eq $guest) {
            $status = "양호"
            $currentState = "Guest 계정이 존재하지 않음"
        }
        else {
            $status = if (-not $guest.Enabled) { "양호" } else { "관리 필요" }
            $enabled = if ($guest.Enabled) { "활성화" } else { "비활성화" }
            $currentState = "Guest 계정 상태: $enabled"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W03 {
    param($checkDef)
    
    try {
        $enabledUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
        $userList = $enabledUsers | ForEach-Object {
            "$($_.Name) (마지막 로그온: $($_.LastLogon))"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "수동 확인 필요"
            current_state = "활성화된 계정 목록: $($userList -join ', ')"
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

function Test-W04 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $complexityEnabled = $netAccounts -match "예|Yes"
        
        $status = if ($complexityEnabled) { "양호" } else { "관리 필요" }
        $stateText = if ($complexityEnabled) { "활성화" } else { "비활성화" }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = "암호 복잡성: $stateText"
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

function Test-W05 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $minPasswordLength = $netAccounts | Select-String "최소 암호 길이|Minimum password length"
        
        if ($minPasswordLength -and $minPasswordLength -match '(\d+)') {
            $length = [int]$Matches[1]
            $status = if ($length -ge 8) { "양호" } else { "관리 필요" }
            $currentState = "암호 최소 길이: $length 자"
        }
        else {
            $status = "점검 불가"
            $currentState = "암호 최소 길이를 확인할 수 없음"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W06 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $maxPasswordAge = $netAccounts | Select-String "최대 암호 사용 기간|Maximum password age"
        
        if ($maxPasswordAge -match '(\d+)') {
            $days = [int]$Matches[1]
            $status = if ($days -gt 0 -and $days -le 60) { "양호" } else { "관리 필요" }
            $currentState = "암호 최대 사용 기간: $days 일"
        }
        elseif ($maxPasswordAge -match "무제한|Unlimited") {
            $status = "관리 필요"
            $currentState = "암호 최대 사용 기간: 무제한"
        }
        else {
            $status = "점검 불가"
            $currentState = "암호 최대 사용 기간을 확인할 수 없음"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W07 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $minPasswordAge = $netAccounts | Select-String "최소 암호 사용 기간|Minimum password age"
        
        if ($minPasswordAge -match '(\d+)') {
            $days = [int]$Matches[1]
            $status = if ($days -ge 1) { "양호" } else { "관리 필요" }
            $currentState = "암호 최소 사용 기간: $days 일"
        }
        else {
            $status = "점검 불가"
            $currentState = "암호 최소 사용 기간을 확인할 수 없음"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W08 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $lockoutThreshold = $netAccounts | Select-String "잠금 임계값|Lockout threshold"
        
        if ($lockoutThreshold -match '(\d+)') {
            $threshold = [int]$Matches[1]
            $status = if ($threshold -ge 1 -and $threshold -le 5) { "양호" } else { "관리 필요" }
            $currentState = "계정 잠금 임계값: $threshold 회"
        }
        elseif ($lockoutThreshold -match "없음|Never") {
            $status = "관리 필요"
            $currentState = "계정 잠금 임계값: 설정되지 않음"
        }
        else {
            $status = "점검 불가"
            $currentState = "계정 잠금 임계값을 확인할 수 없음"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W09 {
    param($checkDef)
    
    try {
        $auditResult = auditpol /get /category:"Logon/Logoff" 2>$null
        
        if ($auditResult) {
            $logonAudit = $auditResult | Select-String "Logon"
            $hasSuccess = $logonAudit -match "Success"
            $hasFailure = $logonAudit -match "Failure"
            
            if ($hasSuccess -and $hasFailure) {
                $status = "양호"
            }
            elseif ($hasSuccess -or $hasFailure) {
                $status = "부분 양호"
            }
            else {
                $status = "관리 필요"
            }
            $currentState = "로그온 감사 - 성공: $hasSuccess, 실패: $hasFailure"
        }
        else {
            $status = "점검 불가"
            $currentState = "감사 정책 정보를 가져올 수 없음 (관리자 권한 필요)"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W10 {
    param($checkDef)
    
    try {
        $runningServices = Get-Service | Where-Object {$_.Status -eq 'Running'}
        $serviceCount = $runningServices.Count
        
        $riskyServices = @('Telnet', 'RemoteRegistry', 'SNMP')
        $foundRiskyServices = $runningServices | Where-Object {$_.Name -in $riskyServices}
        
        if ($foundRiskyServices) {
            $status = "관리 필요"
            $currentState = "실행 중인 위험 서비스 발견: $($foundRiskyServices.Name -join ', ') (전체 서비스: $serviceCount 개)"
        }
        else {
            $status = "수동 확인 필요"
            $currentState = "실행 중인 서비스: $serviceCount 개 (위험 서비스 미발견, 수동 검토 필요)"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W11 {
    param($checkDef)
    
    try {
        $shares = Get-SmbShare | Where-Object {$_.Special -eq $false}
        
        if ($shares) {
            $shareList = $shares | ForEach-Object { "$($_.Name) ($($_.Path))" }
            $status = "수동 확인 필요"
            $currentState = "공유 폴더 발견: $($shareList -join ', ')"
        }
        else {
            $status = "양호"
            $currentState = "사용자 정의 공유 폴더 없음"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W12 {
    param($checkDef)
    
    try {
        $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        
        if ($null -eq $rdpSetting) {
            $status = "점검 불가"
            $currentState = "원격 데스크톱 설정을 확인할 수 없음"
        }
        else {
            $rdpEnabled = $rdpSetting.fDenyTSConnections -eq 0
            
            if (-not $rdpEnabled) {
                $status = "양호"
                $currentState = "원격 데스크톱: 비활성화"
            }
            else {
                $nlaSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                $nlaEnabled = $nlaSetting.UserAuthentication -eq 1
                
                $status = if ($nlaEnabled) { "부분 양호" } else { "관리 필요" }
                $nlaText = if ($nlaEnabled) { "사용" } else { "미사용" }
                $currentState = "원격 데스크톱: 활성화, NLA: $nlaText"
            }
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W13 {
    param($checkDef)
    
    try {
        $uacSetting = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue
        
        if ($null -eq $uacSetting) {
            $status = "점검 불가"
            $currentState = "UAC 설정을 확인할 수 없음"
        }
        else {
            $uacEnabled = $uacSetting.EnableLUA -eq 1
            $status = if ($uacEnabled) { "양호" } else { "관리 필요" }
            $stateText = if ($uacEnabled) { "활성화" } else { "비활성화" }
            $currentState = "UAC: $stateText"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W14 {
    param($checkDef)
    
    try {
        $wuService = Get-Service -Name 'wuauserv'
        $serviceRunning = $wuService.Status -eq 'Running'
        $serviceAuto = $wuService.StartType -in @('Automatic', 'AutomaticDelayedStart')
        
        $status = if ($serviceRunning -or $serviceAuto) { "양호" } else { "관리 필요" }
        $currentState = "Windows Update 서비스 - 상태: $($wuService.Status), 시작 유형: $($wuService.StartType)"
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W15 {
    param($checkDef)
    
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $allEnabled = ($firewallProfiles | Where-Object {$_.Enabled -eq $false}).Count -eq 0
        
        $profileStatus = $firewallProfiles | ForEach-Object {
            $stateText = if ($_.Enabled) { "활성화" } else { "비활성화" }
            "$($_.Name): $stateText"
        }
        
        $status = if ($allEnabled) { "양호" } else { "관리 필요" }
        $currentState = "방화벽 프로필 - $($profileStatus -join ', ')"
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W16 {
    param($checkDef)
    
    try {
        $screenSaverSecure = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue
        
        if ($null -eq $screenSaverSecure) {
            $status = "관리 필요"
            $currentState = "화면 보호기 암호 설정 없음"
        }
        else {
            $isSecure = $screenSaverSecure.ScreenSaverIsSecure -eq 1
            $status = if ($isSecure) { "양호" } else { "관리 필요" }
            $stateText = if ($isSecure) { "설정됨" } else { "미설정" }
            $currentState = "화면 보호기 암호: $stateText"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W17 {
    param($checkDef)
    
    try {
        $legalNotice = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -ErrorAction SilentlyContinue
        
        if ($null -eq $legalNotice -or [string]::IsNullOrWhiteSpace($legalNotice.LegalNoticeCaption)) {
            $status = "관리 필요"
            $currentState = "로그온 법적 고지 미설정"
        }
        else {
            $status = "양호"
            $currentState = "로그온 법적 고지 설정됨: $($legalNotice.LegalNoticeCaption)"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W18 {
    param($checkDef)
    
    try {
        $adminMembers = Get-LocalGroupMember -Group 'Administrators'
        $memberList = $adminMembers | ForEach-Object { "$($_.Name) ($($_.ObjectClass))" }
        
        $status = "수동 확인 필요"
        $currentState = "Administrators 그룹 구성원 ($($adminMembers.Count) 명): $($memberList -join ', ')"
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W19 {
    param($checkDef)
    
    try {
        $autoRunSetting = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue
        
        if ($null -eq $autoRunSetting) {
            $status = "관리 필요"
            $currentState = "자동 실행 설정 없음 (기본값: 일부 활성화)"
        }
        else {
            $value = $autoRunSetting.NoDriveTypeAutoRun
            $status = if ($value -eq 255) { "양호" } else { "관리 필요" }
            $stateText = if ($value -eq 255) { "(모든 드라이브 비활성화)" } else { "(일부 활성화)" }
            $currentState = "자동 실행 설정 값: $value $stateText"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

function Test-W20 {
    param($checkDef)
    
    try {
        $defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        if ($null -eq $defenderPrefs) {
            $status = "점검 불가"
            $currentState = "Windows Defender 설정을 확인할 수 없음"
        }
        else {
            $realtimeEnabled = -not $defenderPrefs.DisableRealtimeMonitoring
            $status = if ($realtimeEnabled) { "양호" } else { "관리 필요" }
            $stateText = if ($realtimeEnabled) { "활성화" } else { "비활성화" }
            $currentState = "실시간 보호: $stateText"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = $currentState
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

$checkFunctions = @{
    'W-01' = 'Test-W01'; 'W-02' = 'Test-W02'; 'W-03' = 'Test-W03'; 'W-04' = 'Test-W04'
    'W-05' = 'Test-W05'; 'W-06' = 'Test-W06'; 'W-07' = 'Test-W07'; 'W-08' = 'Test-W08'
    'W-09' = 'Test-W09'; 'W-10' = 'Test-W10'; 'W-11' = 'Test-W11'; 'W-12' = 'Test-W12'
    'W-13' = 'Test-W13'; 'W-14' = 'Test-W14'; 'W-15' = 'Test-W15'; 'W-16' = 'Test-W16'
    'W-17' = 'Test-W17'; 'W-18' = 'Test-W18'; 'W-19' = 'Test-W19'; 'W-20' = 'Test-W20'
}

function Invoke-SecurityInspection {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "Windows 보안 구성 검사 도구" -ForegroundColor Cyan
    Write-Host "KISA 기술적 취약점 분석·평가 방법 상세가이드 기반" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Administrator)) {
        Write-Warning "일부 검사는 관리자 권한이 필요합니다. 관리자 권한으로 실행하시면 더 정확한 결과를 얻을 수 있습니다."
        Write-Host ""
    }
    
    Write-Host "검사 정의 파일 로딩 중..." -ForegroundColor Yellow
    $definitions = Import-CheckDefinitions -Path $CheckDefinitionPath
    Write-Host "✓ $($definitions.checks.Count) 개의 검사 항목 로드 완료" -ForegroundColor Green
    Write-Host ""
    
    $results = @()
    $checksToRun = if ($CheckCodes.Count -gt 0) {
        $definitions.checks | Where-Object {$_.item_code -in $CheckCodes}
    } else {
        $definitions.checks
    }
    
    $total = $checksToRun.Count
    $current = 0
    
    foreach ($check in $checksToRun) {
        $current++
        Write-Progress -Activity "보안 검사 진행 중" -Status "$current / $total - $($check.check_title)" -PercentComplete (($current / $total) * 100)
        
        $functionName = $checkFunctions[$check.item_code]
        
        if ($functionName -and (Get-Command $functionName -ErrorAction SilentlyContinue)) {
            Write-Host "[$($check.item_code)] $($check.check_title) 검사 중..." -NoNewline
            $result = & $functionName -checkDef $check
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
    }
    
    Write-Progress -Activity "보안 검사 진행 중" -Completed
    Write-Host ""
    
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "검사 결과 요약" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    $summary = $results | Group-Object -Property status | Select-Object Name, Count
    foreach ($item in $summary) {
        $color = switch ($item.Name) {
            "양호" { "Green" }
            "관리 필요" { "Red" }
            "수동 확인 필요" { "Yellow" }
            "부분 양호" { "Yellow" }
            "점검 불가" { "Gray" }
            default { "White" }
        }
        Write-Host "$($item.Name): $($item.Count) 건" -ForegroundColor $color
    }
    Write-Host ""
    
    $output = @{
        metadata = @{
            scan_time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            computer_name = $env:COMPUTERNAME
            os_version = [System.Environment]::OSVersion.VersionString
            total_checks = $results.Count
            based_on = $definitions.metadata.based_on
        }
        summary = @{
            good = ($results | Where-Object {$_.status -eq "양호"}).Count
            needs_management = ($results | Where-Object {$_.status -eq "관리 필요"}).Count
            manual_check = ($results | Where-Object {$_.status -eq "수동 확인 필요"}).Count
            partial_good = ($results | Where-Object {$_.status -eq "부분 양호"}).Count
            check_failed = ($results | Where-Object {$_.status -eq "점검 불가"}).Count
        }
        results = $results
    }
    
    if ($OutputPath) {
        $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "✓ 결과가 저장되었습니다: $OutputPath" -ForegroundColor Green
    }
    else {
        Write-Host "상세 결과 (JSON):" -ForegroundColor Cyan
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }
}

Invoke-SecurityInspection
