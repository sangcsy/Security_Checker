<#
.SYNOPSIS
    Windows 보안 구성 검사 도구 (64개 항목)

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
    .\Invoke-SecurityCheck(2.1.0).ps1
    모든 검사 항목을 실행하고 결과를 화면에 출력

.EXAMPLE
    .\Invoke-SecurityCheck(2.1.0).ps1 -OutputPath "result.json"
    모든 검사 항목을 실행하고 결과를 파일로 저장

.EXAMPLE
    .\Invoke-SecurityCheck(2.1.0).ps1 -CheckCodes "W-01","W-02"
    특정 검사 항목만 실행
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CheckDefinitionPath = "$PSScriptRoot\check_definitions_64items.json",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [string[]]$CheckCodes = @()
)

$ErrorActionPreference = "Stop"

# ========================================
# 관리자 권한 확인 및 재실행
# ========================================

function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 관리자 권한이 없으면 자동 재실행
if (-not (Test-Administrator)) {
    Write-Host "관리자 권한이 필요합니다. 자동으로 관리자 모드로 재실행합니다..." -ForegroundColor Yellow
    Write-Host ""
    
    # 기본 명령 구성
    $cmdString = "Set-Location -Path '$PSScriptRoot'`n& '`"$PSCommandPath`"'"
    
    # 매개변수 추가
    if ($CheckDefinitionPath -ne "$PSScriptRoot\check_definitions_64items.json") {
        $cmdString += " -CheckDefinitionPath '$CheckDefinitionPath'"
    }
    if ($OutputPath) {
        $cmdString += " -OutputPath '$OutputPath'"
    }
    if ($CheckCodes.Count -gt 0) {
        $checkCodesParam = ($CheckCodes | ForEach-Object { "'$_'" }) -join ','
        $cmdString += " -CheckCodes @($checkCodesParam)"
    }
    
    Start-Process powershell -Verb RunAs -ArgumentList "-NoExit -Command `"$cmdString`""
    exit
}

# ========================================
# 유틸리티 함수
# ========================================

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

# ========================================
# 보안 검사 함수 (W-01 ~ W-64)
# ========================================

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
                elseif ($guest.Enabled -eq $false) {
                    $status = "양호"
                    $currentState = "Guest 계정 비활성화"
                }
                else {
                    $status = "관리 필요"
                    $currentState = "Guest 계정 활성화"
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
        $enabledAccounts = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
                $userList = ($enabledAccounts | ForEach-Object { $_.Name }) -join ', '
                $status = "수동 확인 필요"
                $currentState = "활성화된 계정 ($($enabledAccounts.Count)개): $userList"
        
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

function Test-W04 {
    param($checkDef)

    try {
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

function Test-W05 {
    param($checkDef)

    try {
        $tempFile = "$env:temp\policy_$([System.Guid]::NewGuid()).inf"
                try {
                    secedit /export /cfg $tempFile 2>$null | Out-Null
                    if (Test-Path $tempFile) {
                        $textPassLine = Select-String -Path $tempFile -Pattern "ClearTextPassword" -ErrorAction SilentlyContinue
                        if ($null -ne $textPassLine) {
                            # PasswordComplexity=1 형식에서 숫자만 추출
                            $clearTextPass = [int]($textPassLine.ToString().Split('=')[1].Trim())
                        }
                        Remove-Item $tempFile -Force -ErrorAction SilentlyContinue
                    }
                }
                catch {
                    # secedit 실패 시 무시 (관리자 권한 부족)
                }
                if ([int]$clearTextPass -eq 0) {
                    $status = "양호"
                    $currentState = "해독 가능한 암호화를 사용하여 암호 저장 정책: 사용 안 함 (0)"
                }
                else {
                    $status = "관리 필요"
                    $currentState = "해독 가능한 암호화를 사용하여 암호 저장 정책: 사용 (1)"
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
                            $currentState = "EveryoneIncludesAnonymous 설정: 사용 함 (1)"
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
                }
                catch {
                    # secedit 실패 시 무시 (관리자 권한 부족)
                }
                
                if ([int]$passwordMinAge -ge 1 -and [int]$passwordMaxAge -le 90 -and [int]$passwordLength -ge 8 `
                -and [int]$passwordCount -ge 4 -and [int]$passwordComplexity -eq 1) {
                    $status = "양호"
                }
                else {
                    $status = "관리 필요"
                }
                $currentState = "최소 기간: ${passwordMinAge}일 / 최대 기간: ${passwordMaxAge}일 / 최소 길이: ${passwordLength}자 / 기록 개수: ${passwordCount}개 / 복잡성: $passwordComplexity"
        
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
                }
                catch {
                    # secedit 실패 시 무시 (관리자 권한 부족)
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
                }
                catch {
                    # secedit 실패 시 무시 (관리자 권한 부족)
                }
                if ([int]$clearTextPass -eq 0) {
                    $status = "양호"
                    $currentState = "해독 가능한 암호화를 사용하여 암호 저장 정책: 사용 안 함 (0)"
                }
                else {
                    $status = "관리 필요"
                    $currentState = "해독 가능한 암호화를 사용하여 암호 저장 정책: 사용 (1)"
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
function Test-W13 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W14 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W15 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W16 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W17 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W18 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W19 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W20 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W21 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W22 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W23 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W24 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W25 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W26 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W27 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W28 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W29 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W30 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W31 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W32 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W33 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W34 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W35 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W36 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W37 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W38 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W39 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W40 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W41 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W42 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W43 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W44 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W45 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W46 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W47 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W48 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W49 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W50 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W51 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W52 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W53 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W54 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W55 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W56 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W57 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W58 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W59 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W60 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W61 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W62 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W63 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }
function Test-W64 { param($checkDef) try { $status = "점검 불가"; $currentState = "구현 대기 중"; return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = $status; current_state = $currentState; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } catch { return @{ item_code = $checkDef.item_code; check_title = $checkDef.check_title; status = "점검 불가"; current_state = "오류: $_"; expected_state = $checkDef.expected_state; operational_meaning = $checkDef.operational_meaning } } }

# ========================================
# 검사 함수 매핑
# ========================================

$checkFunctions = @{
    'W-01' = 'Test-W01'; 'W-02' = 'Test-W02'; 'W-03' = 'Test-W03'; 'W-04' = 'Test-W04'; 'W-05' = 'Test-W05'; 'W-06' = 'Test-W06'; 'W-07' = 'Test-W07'; 'W-08' = 'Test-W08'; 'W-09' = 'Test-W09'; 'W-10' = 'Test-W10'
    'W-11' = 'Test-W11'; 'W-12' = 'Test-W12'; 'W-13' = 'Test-W13'; 'W-14' = 'Test-W14'; 'W-15' = 'Test-W15'; 'W-16' = 'Test-W16'; 'W-17' = 'Test-W17'; 'W-18' = 'Test-W18'; 'W-19' = 'Test-W19'; 'W-20' = 'Test-W20'
    'W-21' = 'Test-W21'; 'W-22' = 'Test-W22'; 'W-23' = 'Test-W23'; 'W-24' = 'Test-W24'; 'W-25' = 'Test-W25'; 'W-26' = 'Test-W26'; 'W-27' = 'Test-W27'; 'W-28' = 'Test-W28'; 'W-29' = 'Test-W29'; 'W-30' = 'Test-W30'
    'W-31' = 'Test-W31'; 'W-32' = 'Test-W32'; 'W-33' = 'Test-W33'; 'W-34' = 'Test-W34'; 'W-35' = 'Test-W35'; 'W-36' = 'Test-W36'; 'W-37' = 'Test-W37'; 'W-38' = 'Test-W38'; 'W-39' = 'Test-W39'; 'W-40' = 'Test-W40'
    'W-41' = 'Test-W41'; 'W-42' = 'Test-W42'; 'W-43' = 'Test-W43'; 'W-44' = 'Test-W44'; 'W-45' = 'Test-W45'; 'W-46' = 'Test-W46'; 'W-47' = 'Test-W47'; 'W-48' = 'Test-W48'; 'W-49' = 'Test-W49'; 'W-50' = 'Test-W50'
    'W-51' = 'Test-W51'; 'W-52' = 'Test-W52'; 'W-53' = 'Test-W53'; 'W-54' = 'Test-W54'; 'W-55' = 'Test-W55'; 'W-56' = 'Test-W56'; 'W-57' = 'Test-W57'; 'W-58' = 'Test-W58'; 'W-59' = 'Test-W59'; 'W-60' = 'Test-W60'
    'W-61' = 'Test-W61'; 'W-62' = 'Test-W62'; 'W-63' = 'Test-W63'; 'W-64' = 'Test-W64'
}

# ========================================
# 메인 검사 실행
# ========================================

function Invoke-SecurityInspection {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "Windows 보안 구성 검사 도구 v2.1.0 (64개 항목)" -ForegroundColor Cyan
    Write-Host "KISA 기술적 취약점 분석·평가 방법 상세가이드 기반" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Administrator)) {
        Write-Warning "일부 검사는 관리자 권한이 필요합니다. 관리자 권한으로 실행하면 더 정확한 결과를 얻을 수 있습니다."
        Write-Host ""
    }
    
    Write-Host "검사 정의 파일 로딩 중..." -ForegroundColor Yellow
    try {
        $definitions = Import-CheckDefinitions -Path $CheckDefinitionPath
        Write-Host "✓ $($definitions.checks.Count) 개의 검사 항목 로드 완료" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ 검사 정의 파일 로드 실패: $_" -ForegroundColor Red
        exit 1
    }
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
            based_on = "KISA 기술적 취약점 분석·평가 방법 상세가이드"
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

# ========================================
# 스크립트 실행
# ========================================

Invoke-SecurityInspection
