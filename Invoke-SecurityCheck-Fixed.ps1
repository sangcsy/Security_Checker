<#
.SYNOPSIS
    Windows 蹂댁븞 援ъ꽦 寃???꾧뎄

.DESCRIPTION
    KISA 湲곗닠??痍⑥빟??遺꾩꽍쨌?됯? 諛⑸쾿 ?곸꽭媛?대뱶瑜?湲곕컲?쇰줈 
    Windows ?쒖뒪?쒖쓽 蹂댁븞 援ъ꽦 ?곹깭瑜?寃?ы빀?덈떎.
    
    ???꾧뎄???쎄린 ?꾩슜 寃?щ쭔 ?섑뻾?섎ŉ, ?쒖뒪???ㅼ젙??蹂寃쏀븯吏 ?딆뒿?덈떎.

.PARAMETER CheckDefinitionPath
    寃???뺤쓽 JSON ?뚯씪 寃쎈줈

.PARAMETER OutputPath
    寃곌낵 JSON ?뚯씪 ???寃쎈줈

.PARAMETER CheckCodes
    ?뱀젙 寃????ぉ留??ㅽ뻾 (?? "W-01","W-02")

.EXAMPLE
    .\Invoke-SecurityCheck.ps1
    紐⑤뱺 寃????ぉ???ㅽ뻾?섍퀬 寃곌낵瑜??붾㈃??異쒕젰

.EXAMPLE
    .\Invoke-SecurityCheck.ps1 -OutputPath "result.json"
    紐⑤뱺 寃????ぉ???ㅽ뻾?섍퀬 寃곌낵瑜??뚯씪濡????

.EXAMPLE
    .\Invoke-SecurityCheck.ps1 -CheckCodes "W-01","W-02"
    ?뱀젙 寃????ぉ留??ㅽ뻾

.NOTES
    ?묒꽦?? Security Operations Team
    紐⑹쟻: 蹂댁븞 援ъ꽦 寃??諛?而댄뵆?쇱씠?몄뒪 ?뺤씤
    二쇱쓽: 愿由ъ옄 沅뚰븳?쇰줈 ?ㅽ뻾 沅뚯옣
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

# 愿由ъ옄 沅뚰븳 ?뺤씤
function Test-Administrator {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# 寃???뺤쓽 ?뚯씪 濡쒕뱶
function Import-CheckDefinitions {
    param([string]$Path)
    
    if (-not (Test-Path $Path)) {
        throw "寃???뺤쓽 ?뚯씪??李얠쓣 ???놁뒿?덈떎: $Path"
    }
    
    try {
        $content = Get-Content -Path $Path -Raw -Encoding UTF8
        $definitions = $content | ConvertFrom-Json
        return $definitions
    }
    catch {
        throw "寃???뺤쓽 ?뚯씪???쎈뒗 以??ㅻ쪟 諛쒖깮: $_"
    }
}

# W-01: Administrator 怨꾩젙 ?대쫫 蹂寃??뺤씤
function Test-W01 {
    param($checkDef)
    
    try {
        $adminAccount = Get-LocalUser | Where-Object {$_.SID -like '*-500'}
        $adminName = $adminAccount.Name
        
        $status = if ($adminName -ne "Administrator") { "?묓샇" } else { "愿由??꾩슂" }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = "?꾩옱 Administrator SID(-500) 怨꾩젙 ?대쫫: $adminName"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
    catch {
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-02: Guest 怨꾩젙 鍮꾪솢?깊솕 ?뺤씤
function Test-W02 {
    param($checkDef)
    
    try {
        $guest = Get-LocalUser -Name 'Guest' -ErrorAction SilentlyContinue
        
        if ($null -eq $guest) {
            $status = "?묓샇"
            $currentState = "Guest 怨꾩젙??議댁옱?섏? ?딆쓬"
        }
        else {
            $status = if (-not $guest.Enabled) { "?묓샇" } else { "愿由??꾩슂" }
            $currentState = "Guest 怨꾩젙 ?곹깭: " + $(if ($guest.Enabled) { "?쒖꽦?? } else { "鍮꾪솢?깊솕" })
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-03: 遺덊븘?뷀븳 怨꾩젙 議댁옱 ?щ?
function Test-W03 {
    param($checkDef)
    
    try {
        $enabledUsers = Get-LocalUser | Where-Object {$_.Enabled -eq $true}
        $userList = $enabledUsers | ForEach-Object {
            "$($_.Name) (留덉?留?濡쒓렇?? $($_.LastLogon))"
        }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "?섎룞 ?뺤씤 ?꾩슂"
            current_state = "?쒖꽦?붾맂 怨꾩젙 紐⑸줉: $($userList -join ', ')"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
    catch {
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-04: ?뷀샇 蹂듭옟???ㅼ젙
function Test-W04 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $passwordComplexity = $netAccounts | Select-String "?뷀샇 蹂듭옟??Password complexity"
        
        # Windows ?몄뼱???곕씪 ?ㅻⅤ寃?泥섎━
        $complexityEnabled = $false
        if ($passwordComplexity) {
            $complexityEnabled = $passwordComplexity -match "??Yes"
        }
        
        $status = if ($complexityEnabled) { "?묓샇" } else { "愿由??꾩슂" }
        
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = $status
            current_state = "?뷀샇 蹂듭옟?? " + $(if ($complexityEnabled) { "?쒖꽦?? } else { "鍮꾪솢?깊솕" })
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
    catch {
        return @{
            item_code = $checkDef.item_code
            check_title = $checkDef.check_title
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-05: ?뷀샇 理쒖냼 湲몄씠 ?ㅼ젙
function Test-W05 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $minPasswordLength = $netAccounts | Select-String "理쒖냼 ?뷀샇 湲몄씠|Minimum password length"
        
        if ($minPasswordLength) {
            # ?レ옄 異붿텧
            if ($minPasswordLength -match '(\d+)') {
                $length = [int]$Matches[1]
                $status = if ($length -ge 8) { "?묓샇" } else { "愿由??꾩슂" }
                $currentState = "?뷀샇 理쒖냼 湲몄씠: $length ??
            }
            else {
                $status = "?먭? 遺덇?"
                $currentState = "?뷀샇 理쒖냼 湲몄씠瑜??뺤씤?????놁쓬"
            }
        }
        else {
            $status = "?먭? 遺덇?"
            $currentState = "?뷀샇 理쒖냼 湲몄씠 ?뺣낫瑜?李얠쓣 ???놁쓬"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-06: ?뷀샇 理쒕? ?ъ슜 湲곌컙
function Test-W06 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $maxPasswordAge = $netAccounts | Select-String "理쒕? ?뷀샇 ?ъ슜 湲곌컙|Maximum password age"
        
        if ($maxPasswordAge) {
            if ($maxPasswordAge -match '(\d+)') {
                $days = [int]$Matches[1]
                $status = if ($days -gt 0 -and $days -le 60) { "?묓샇" } else { "愿由??꾩슂" }
                $currentState = "?뷀샇 理쒕? ?ъ슜 湲곌컙: $days ??
            }
            elseif ($maxPasswordAge -match "臾댁젣??Unlimited") {
                $status = "愿由??꾩슂"
                $currentState = "?뷀샇 理쒕? ?ъ슜 湲곌컙: 臾댁젣??
            }
            else {
                $status = "?먭? 遺덇?"
                $currentState = "?뷀샇 理쒕? ?ъ슜 湲곌컙???뺤씤?????놁쓬"
            }
        }
        else {
            $status = "?먭? 遺덇?"
            $currentState = "?뷀샇 理쒕? ?ъ슜 湲곌컙 ?뺣낫瑜?李얠쓣 ???놁쓬"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-07: ?뷀샇 理쒖냼 ?ъ슜 湲곌컙
function Test-W07 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $minPasswordAge = $netAccounts | Select-String "理쒖냼 ?뷀샇 ?ъ슜 湲곌컙|Minimum password age"
        
        if ($minPasswordAge) {
            if ($minPasswordAge -match '(\d+)') {
                $days = [int]$Matches[1]
                $status = if ($days -ge 1) { "?묓샇" } else { "愿由??꾩슂" }
                $currentState = "?뷀샇 理쒖냼 ?ъ슜 湲곌컙: $days ??
            }
            else {
                $status = "?먭? 遺덇?"
                $currentState = "?뷀샇 理쒖냼 ?ъ슜 湲곌컙???뺤씤?????놁쓬"
            }
        }
        else {
            $status = "?먭? 遺덇?"
            $currentState = "?뷀샇 理쒖냼 ?ъ슜 湲곌컙 ?뺣낫瑜?李얠쓣 ???놁쓬"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-08: 怨꾩젙 ?좉툑 ?꾧퀎媛?
function Test-W08 {
    param($checkDef)
    
    try {
        $netAccounts = net accounts
        $lockoutThreshold = $netAccounts | Select-String "?좉툑 ?꾧퀎媛?Lockout threshold"
        
        if ($lockoutThreshold) {
            if ($lockoutThreshold -match '(\d+)') {
                $threshold = [int]$Matches[1]
                $status = if ($threshold -ge 1 -and $threshold -le 5) { "?묓샇" } else { "愿由??꾩슂" }
                $currentState = "怨꾩젙 ?좉툑 ?꾧퀎媛? $threshold ??
            }
            elseif ($lockoutThreshold -match "?놁쓬|Never") {
                $status = "愿由??꾩슂"
                $currentState = "怨꾩젙 ?좉툑 ?꾧퀎媛? ?ㅼ젙?섏? ?딆쓬"
            }
            else {
                $status = "?먭? 遺덇?"
                $currentState = "怨꾩젙 ?좉툑 ?꾧퀎媛믪쓣 ?뺤씤?????놁쓬"
            }
        }
        else {
            $status = "?먭? 遺덇?"
            $currentState = "怨꾩젙 ?좉툑 ?꾧퀎媛??뺣낫瑜?李얠쓣 ???놁쓬"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-09: 怨꾩젙 濡쒓렇???대깽??媛먯궗
function Test-W09 {
    param($checkDef)
    
    try {
        # auditpol 紐낅졊?대뒗 ?곸뼱濡?異쒕젰??
        $auditResult = auditpol /get /category:"Logon/Logoff" 2>$null
        
        if ($auditResult) {
            # Logon ?대깽???뺤씤
            $logonAudit = $auditResult | Select-String "Logon"
            $hasSuccess = $logonAudit -match "Success"
            $hasFailure = $logonAudit -match "Failure"
            
            $status = if ($hasSuccess -and $hasFailure) { "?묓샇" } elseif ($hasSuccess -or $hasFailure) { "遺遺??묓샇" } else { "愿由??꾩슂" }
            $currentState = "濡쒓렇??媛먯궗 - ?깃났: $hasSuccess, ?ㅽ뙣: $hasFailure"
        }
        else {
            $status = "?먭? 遺덇?"
            $currentState = "媛먯궗 ?뺤콉 ?뺣낫瑜?媛?몄삱 ???놁쓬 (愿由ъ옄 沅뚰븳 ?꾩슂)"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-10: 遺덊븘?뷀븳 ?쒕퉬???ㅽ뻾 ?щ?
function Test-W10 {
    param($checkDef)
    
    try {
        $runningServices = Get-Service | Where-Object {$_.Status -eq 'Running'}
        $serviceCount = $runningServices.Count
        
        # 二쇱슂 ?꾪뿕 ?쒕퉬??紐⑸줉 (?덉떆)
        $riskyServices = @('Telnet', 'RemoteRegistry', 'SNMP')
        $foundRiskyServices = $runningServices | Where-Object {$_.Name -in $riskyServices}
        
        if ($foundRiskyServices) {
            $status = "愿由??꾩슂"
            $currentState = "?ㅽ뻾 以묒씤 ?꾪뿕 ?쒕퉬??諛쒓껄: $($foundRiskyServices.Name -join ', ') (?꾩껜 ?쒕퉬?? $serviceCount 媛?"
        }
        else {
            $status = "?섎룞 ?뺤씤 ?꾩슂"
            $currentState = "?ㅽ뻾 以묒씤 ?쒕퉬?? $serviceCount 媛?(?꾪뿕 ?쒕퉬??誘몃컻寃? ?섎룞 寃???꾩슂)"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-11: 怨듭쑀 ?대뜑 議댁옱 ?щ?
function Test-W11 {
    param($checkDef)
    
    try {
        $shares = Get-SmbShare | Where-Object {$_.Special -eq $false}
        
        if ($shares) {
            $shareList = $shares | ForEach-Object { "$($_.Name) ($($_.Path))" }
            $status = "?섎룞 ?뺤씤 ?꾩슂"
            $currentState = "怨듭쑀 ?대뜑 諛쒓껄: $($shareList -join ', ')"
        }
        else {
            $status = "?묓샇"
            $currentState = "?ъ슜???뺤쓽 怨듭쑀 ?대뜑 ?놁쓬"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-12: ?먭꺽 ?곗뒪?ы넲 ?쒕퉬???ㅼ젙
function Test-W12 {
    param($checkDef)
    
    try {
        $rdpSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server' -Name 'fDenyTSConnections' -ErrorAction SilentlyContinue
        
        if ($null -eq $rdpSetting) {
            $status = "?먭? 遺덇?"
            $currentState = "?먭꺽 ?곗뒪?ы넲 ?ㅼ젙???뺤씤?????놁쓬"
        }
        else {
            $rdpEnabled = $rdpSetting.fDenyTSConnections -eq 0
            
            if (-not $rdpEnabled) {
                $status = "?묓샇"
                $currentState = "?먭꺽 ?곗뒪?ы넲: 鍮꾪솢?깊솕"
            }
            else {
                # NLA ?ㅼ젙 ?뺤씤
                $nlaSetting = Get-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -ErrorAction SilentlyContinue
                $nlaEnabled = $nlaSetting.UserAuthentication -eq 1
                
                $status = if ($nlaEnabled) { "遺遺??묓샇" } else { "愿由??꾩슂" }
                $currentState = "?먭꺽 ?곗뒪?ы넲: ?쒖꽦?? NLA: " + $(if ($nlaEnabled) { "?ъ슜" } else { "誘몄궗?? })
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-13: UAC ?ㅼ젙
function Test-W13 {
    param($checkDef)
    
    try {
        $uacSetting = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'EnableLUA' -ErrorAction SilentlyContinue
        
        if ($null -eq $uacSetting) {
            $status = "?먭? 遺덇?"
            $currentState = "UAC ?ㅼ젙???뺤씤?????놁쓬"
        }
        else {
            $uacEnabled = $uacSetting.EnableLUA -eq 1
            $status = if ($uacEnabled) { "?묓샇" } else { "愿由??꾩슂" }
            $currentState = "UAC: " + $(if ($uacEnabled) { "?쒖꽦?? } else { "鍮꾪솢?깊솕" })
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-14: Windows ?낅뜲?댄듃 ?ㅼ젙
function Test-W14 {
    param($checkDef)
    
    try {
        $wuService = Get-Service -Name 'wuauserv'
        $serviceRunning = $wuService.Status -eq 'Running'
        $serviceAuto = $wuService.StartType -in @('Automatic', 'AutomaticDelayedStart')
        
        $status = if ($serviceRunning -or $serviceAuto) { "?묓샇" } else { "愿由??꾩슂" }
        $currentState = "Windows Update ?쒕퉬??- ?곹깭: $($wuService.Status), ?쒖옉 ?좏삎: $($wuService.StartType)"
        
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-15: Windows 諛⑺솕踰??ㅼ젙
function Test-W15 {
    param($checkDef)
    
    try {
        $firewallProfiles = Get-NetFirewallProfile
        $allEnabled = ($firewallProfiles | Where-Object {$_.Enabled -eq $false}).Count -eq 0
        
        $profileStatus = $firewallProfiles | ForEach-Object {
            "$($_.Name): " + $(if ($_.Enabled) { "?쒖꽦?? } else { "鍮꾪솢?깊솕" })
        }
        
        $status = if ($allEnabled) { "?묓샇" } else { "愿由??꾩슂" }
        $currentState = "諛⑺솕踰??꾨줈??- $($profileStatus -join ', ')"
        
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-16: ?붾㈃ 蹂댄샇湲??ㅼ젙
function Test-W16 {
    param($checkDef)
    
    try {
        $screenSaverSecure = Get-ItemProperty -Path 'HKCU:\Control Panel\Desktop' -Name 'ScreenSaverIsSecure' -ErrorAction SilentlyContinue
        
        if ($null -eq $screenSaverSecure) {
            $status = "愿由??꾩슂"
            $currentState = "?붾㈃ 蹂댄샇湲??뷀샇 ?ㅼ젙 ?놁쓬"
        }
        else {
            $isSecure = $screenSaverSecure.ScreenSaverIsSecure -eq 1
            $status = if ($isSecure) { "?묓샇" } else { "愿由??꾩슂" }
            $currentState = "?붾㈃ 蹂댄샇湲??뷀샇: " + $(if ($isSecure) { "?ㅼ젙?? } else { "誘몄꽕?? })
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-17: 濡쒓렇??踰뺤쟻 怨좎? ?ㅼ젙
function Test-W17 {
    param($checkDef)
    
    try {
        $legalNotice = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System' -Name 'LegalNoticeCaption' -ErrorAction SilentlyContinue
        
        if ($null -eq $legalNotice -or [string]::IsNullOrWhiteSpace($legalNotice.LegalNoticeCaption)) {
            $status = "愿由??꾩슂"
            $currentState = "濡쒓렇??踰뺤쟻 怨좎? 誘몄꽕??
        }
        else {
            $status = "?묓샇"
            $currentState = "濡쒓렇??踰뺤쟻 怨좎? ?ㅼ젙?? $($legalNotice.LegalNoticeCaption)"
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-18: 愿由ъ옄 洹몃９ 援ъ꽦???뺤씤
function Test-W18 {
    param($checkDef)
    
    try {
        $adminMembers = Get-LocalGroupMember -Group 'Administrators'
        $memberList = $adminMembers | ForEach-Object { "$($_.Name) ($($_.ObjectClass))" }
        
        $status = "?섎룞 ?뺤씤 ?꾩슂"
        $currentState = "Administrators 洹몃９ 援ъ꽦??($($adminMembers.Count) 紐?: $($memberList -join ', ')"
        
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-19: ?먮룞 ?ㅽ뻾 鍮꾪솢?깊솕
function Test-W19 {
    param($checkDef)
    
    try {
        $autoRunSetting = Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name 'NoDriveTypeAutoRun' -ErrorAction SilentlyContinue
        
        if ($null -eq $autoRunSetting) {
            $status = "愿由??꾩슂"
            $currentState = "?먮룞 ?ㅽ뻾 ?ㅼ젙 ?놁쓬 (湲곕낯媛? ?쇰? ?쒖꽦??"
        }
        else {
            # 255 (0xFF) = 紐⑤뱺 ?쒕씪?대툕 ??낆뿉 ????먮룞 ?ㅽ뻾 鍮꾪솢?깊솕
            $value = $autoRunSetting.NoDriveTypeAutoRun
            $status = if ($value -eq 255) { "?묓샇" } else { "愿由??꾩슂" }
            $currentState = "?먮룞 ?ㅽ뻾 ?ㅼ젙 媛? $value " + $(if ($value -eq 255) { "(紐⑤뱺 ?쒕씪?대툕 鍮꾪솢?깊솕)" } else { "(?쇰? ?쒖꽦??" })
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# W-20: Windows Defender ?ㅼ떆媛?蹂댄샇
function Test-W20 {
    param($checkDef)
    
    try {
        $defenderPrefs = Get-MpPreference -ErrorAction SilentlyContinue
        
        if ($null -eq $defenderPrefs) {
            $status = "?먭? 遺덇?"
            $currentState = "Windows Defender ?ㅼ젙???뺤씤?????놁쓬"
        }
        else {
            $realtimeEnabled = -not $defenderPrefs.DisableRealtimeMonitoring
            $status = if ($realtimeEnabled) { "?묓샇" } else { "愿由??꾩슂" }
            $currentState = "?ㅼ떆媛?蹂댄샇: " + $(if ($realtimeEnabled) { "?쒖꽦?? } else { "鍮꾪솢?깊솕" })
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
            status = "?먭? 遺덇?"
            current_state = "?ㅻ쪟: $_"
            expected_state = $checkDef.expected_state
            operational_meaning = $checkDef.operational_meaning
        }
    }
}

# 寃???ㅽ뻾 ?⑥닔 留ㅽ븨
$checkFunctions = @{
    'W-01' = 'Test-W01'
    'W-02' = 'Test-W02'
    'W-03' = 'Test-W03'
    'W-04' = 'Test-W04'
    'W-05' = 'Test-W05'
    'W-06' = 'Test-W06'
    'W-07' = 'Test-W07'
    'W-08' = 'Test-W08'
    'W-09' = 'Test-W09'
    'W-10' = 'Test-W10'
    'W-11' = 'Test-W11'
    'W-12' = 'Test-W12'
    'W-13' = 'Test-W13'
    'W-14' = 'Test-W14'
    'W-15' = 'Test-W15'
    'W-16' = 'Test-W16'
    'W-17' = 'Test-W17'
    'W-18' = 'Test-W18'
    'W-19' = 'Test-W19'
    'W-20' = 'Test-W20'
}

# 硫붿씤 ?ㅽ뻾 濡쒖쭅
function Invoke-SecurityInspection {
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "Windows 蹂댁븞 援ъ꽦 寃???꾧뎄" -ForegroundColor Cyan
    Write-Host "KISA 湲곗닠??痍⑥빟??遺꾩꽍쨌?됯? 諛⑸쾿 ?곸꽭媛?대뱶 湲곕컲" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host ""
    
    # 愿由ъ옄 沅뚰븳 ?뺤씤
    if (-not (Test-Administrator)) {
        Write-Warning "?쇰? 寃?щ뒗 愿由ъ옄 沅뚰븳???꾩슂?⑸땲?? 愿由ъ옄 沅뚰븳?쇰줈 ?ㅽ뻾?섏떆硫????뺥솗??寃곌낵瑜??살쓣 ???덉뒿?덈떎."
        Write-Host ""
    }
    
    # 寃???뺤쓽 ?뚯씪 濡쒕뱶
    Write-Host "寃???뺤쓽 ?뚯씪 濡쒕뵫 以?.." -ForegroundColor Yellow
    $definitions = Import-CheckDefinitions -Path $CheckDefinitionPath
    Write-Host "??$($definitions.checks.Count) 媛쒖쓽 寃????ぉ 濡쒕뱶 ?꾨즺" -ForegroundColor Green
    Write-Host ""
    
    # 寃???ㅽ뻾
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
        Write-Progress -Activity "蹂댁븞 寃??吏꾪뻾 以? -Status "$current / $total - $($check.check_title)" -PercentComplete (($current / $total) * 100)
        
        $functionName = $checkFunctions[$check.item_code]
        
        if ($functionName -and (Get-Command $functionName -ErrorAction SilentlyContinue)) {
            Write-Host "[$($check.item_code)] $($check.check_title) 寃??以?.." -NoNewline
            $result = & $functionName -checkDef $check
            $results += $result
            
            # 寃곌낵???곕씪 ?됱긽 異쒕젰
            $color = switch ($result.status) {
                "?묓샇" { "Green" }
                "愿由??꾩슂" { "Red" }
                "?섎룞 ?뺤씤 ?꾩슂" { "Yellow" }
                "遺遺??묓샇" { "Yellow" }
                "?먭? 遺덇?" { "Gray" }
                default { "White" }
            }
            Write-Host " [$($result.status)]" -ForegroundColor $color
        }
        else {
            Write-Host "[$($check.item_code)] $($check.check_title) - 寃???⑥닔 ?놁쓬" -ForegroundColor Gray
        }
    }
    
    Write-Progress -Activity "蹂댁븞 寃??吏꾪뻾 以? -Completed
    Write-Host ""
    
    # 寃곌낵 ?붿빟
    Write-Host "=" * 80 -ForegroundColor Cyan
    Write-Host "寃??寃곌낵 ?붿빟" -ForegroundColor Cyan
    Write-Host "=" * 80 -ForegroundColor Cyan
    
    $summary = $results | Group-Object -Property status | Select-Object Name, Count
    foreach ($item in $summary) {
        $color = switch ($item.Name) {
            "?묓샇" { "Green" }
            "愿由??꾩슂" { "Red" }
            "?섎룞 ?뺤씤 ?꾩슂" { "Yellow" }
            "遺遺??묓샇" { "Yellow" }
            "?먭? 遺덇?" { "Gray" }
            default { "White" }
        }
        Write-Host "$($item.Name): $($item.Count) 嫄? -ForegroundColor $color
    }
    Write-Host ""
    
    # 寃곌낵 異쒕젰
    $output = @{
        metadata = @{
            scan_time = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            computer_name = $env:COMPUTERNAME
            os_version = [System.Environment]::OSVersion.VersionString
            total_checks = $results.Count
            based_on = $definitions.metadata.based_on
        }
        summary = @{
            good = ($results | Where-Object {$_.status -eq "?묓샇"}).Count
            needs_management = ($results | Where-Object {$_.status -eq "愿由??꾩슂"}).Count
            manual_check = ($results | Where-Object {$_.status -eq "?섎룞 ?뺤씤 ?꾩슂"}).Count
            partial_good = ($results | Where-Object {$_.status -eq "遺遺??묓샇"}).Count
            check_failed = ($results | Where-Object {$_.status -eq "?먭? 遺덇?"}).Count
        }
        results = $results
    }
    
    # JSON 異쒕젰
    if ($OutputPath) {
        $output | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-Host "??寃곌낵媛 ??λ릺?덉뒿?덈떎: $OutputPath" -ForegroundColor Green
    }
    else {
        Write-Host "?곸꽭 寃곌낵 (JSON):" -ForegroundColor Cyan
        Write-Host ($output | ConvertTo-Json -Depth 10)
    }
}

# ?ㅽ겕由쏀듃 ?ㅽ뻾
Invoke-SecurityInspection
