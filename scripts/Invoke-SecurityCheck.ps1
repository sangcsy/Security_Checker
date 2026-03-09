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
    .\scripts\Invoke-SecurityCheck.ps1
    모든 검사 항목을 실행하고 결과를 화면에 출력

.EXAMPLE
    .\scripts\Invoke-SecurityCheck.ps1 -OutputPath "result.json"
    모든 검사 항목을 실행하고 결과를 파일로 저장

.EXAMPLE
    .\scripts\Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02"
    특정 검사 항목만 실행
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string]$CheckDefinitionPath = "",
    
    [Parameter(Mandatory=$false)]
    [string]$OutputPath = "",
    
    [Parameter(Mandatory=$false)]
    [string[]]$CheckCodes = @()
)

$script:ProjectRoot = if ($PSScriptRoot) {
    Split-Path -Parent $PSScriptRoot
}
elseif ($PSCommandPath) {
    Split-Path -Parent (Split-Path -Parent $PSCommandPath)
}
else {
    (Get-Location).Path
}

if (-not $CheckDefinitionPath) {
    $CheckDefinitionPath = Join-Path $script:ProjectRoot "config\check_definitions.json"
}

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
    if ($CheckDefinitionPath -ne (Join-Path (Split-Path -Parent $PSScriptRoot) "config\check_definitions.json")) {
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

function Test-W13 {
    param($checkDef)

    try {
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
        $rdpUsersLine = Get-LocalGroupMember "Remote Desktop Users" -ErrorAction SilentlyContinue
                $rdpUser = ($rdpUsersLine | ForEach-Object {$_.Name.ToString().split('\')[1]}) -join ', '
                if ($rdpUsersLine.Count -eq 0) {
                    $status = "양호"
                }
                else {
                    $status = "수동 확인 필요"
                }
                $currentState = "현재 원격 데스크톱 사용자 ($($rdpUsersLine.Count)개): $rdpUser"
        
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

function Test-W21 {
    param($checkDef)

    try {
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

function Test-W22 {
    param($checkDef)

    try {
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

function Test-W23 {
    param($checkDef)

    try {
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

function Test-W24 {
    param($checkDef)

    try {
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

function Test-W25 {
    param($checkDef)

    try {
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
function Test-W26 {
    param($checkDef)

    try {
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

function Test-W27 {
    param($checkDef)

    try {
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

function Test-W28 {
    param($checkDef)

    try {
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

function Test-W29 {
    param($checkDef)

    try {
        $snmpService = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue

                if ($null -eq $snmpService -or $snmpService.Status -ne "Running") {
                    $status = "양호"
                    $currentState = "SNMP 서비스가 설치되지 않았거나 중지된 상태입니다."
                }
                else {
                    $status = "수동 확인 필요"
                    $currentState = "SNMP 서비스가 실행 중입니다. (불필요한 경우 서비스 비활성화 권고)"
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
function Test-W30 {
    param($checkDef)

    try {
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

function Test-W31 {
    param($checkDef)

    try {
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

function Test-W32 {
    param($checkDef)

    try {
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
function Test-W33 {
    param($checkDef)

    try {
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
function Test-W34 {
    param($checkDef)

    try {
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
function Test-W35 {
    param($checkDef)

    try {
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
function Test-W36 {
    param($checkDef)

    try {
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
function Test-W37 {
    param($checkDef)

    try {
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

function Test-W38 {
    param($checkDef)

    try {
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
function Test-W39 {
    param($checkDef)

    try {
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
function Test-W40 {
    param($checkDef)

    try {
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
function Test-W41 {
    param($checkDef)

    try {
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
function Test-W42 {
    param($checkDef)

    try {
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
function Test-W43 {
    param($checkDef)

    try {
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
function Test-W44 {
    param($checkDef)

    try {
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
function Test-W45 {
    param($checkDef)

    try {
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

function Test-W46 {
    param($checkDef)

    try {
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

function Test-W47 {
    param($checkDef)

    try {
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
    Write-Host "Windows 보안 구성 검사 도구 v1.0 (64개 항목)" -ForegroundColor Cyan
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
