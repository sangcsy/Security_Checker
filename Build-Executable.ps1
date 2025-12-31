<#
.SYNOPSIS
    SecurityChecker를 단일 실행 파일(.exe)로 빌드하는 스크립트

.DESCRIPTION
    PS2EXE를 사용하여 PowerShell 스크립트를 실행 파일로 변환합니다.
    
.NOTES
    필수 사항:
    - PS2EXE 모듈 설치 필요
    - 관리자 권한 권장

.EXAMPLE
    .\Build-Executable.ps1
#>

param(
    [Parameter(Mandatory=$false)]
    [string]$OutputName = "SecurityChecker",
    
    [Parameter(Mandatory=$false)]
    [switch]$IncludeIcon
)

$ErrorActionPreference = "Stop"

Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host "SecurityChecker 실행 파일 빌드" -ForegroundColor Cyan
Write-Host "=" * 70 -ForegroundColor Cyan
Write-Host ""

# ========================================
# 1. PS2EXE 모듈 확인 및 설치
# ========================================

Write-Host "[1/4] PS2EXE 모듈 확인 중..." -ForegroundColor Yellow

if (-not (Get-Module -ListAvailable -Name PS2EXE)) {
    Write-Host "PS2EXE 모듈이 설치되어 있지 않습니다." -ForegroundColor Yellow
    $response = Read-Host "지금 설치하시겠습니까? (Y/N)"
    
    if ($response -eq 'Y' -or $response -eq 'y') {
        Write-Host "PS2EXE 모듈 설치 중..." -ForegroundColor Yellow
        Install-Module -Name PS2EXE -Scope CurrentUser -Force
        Write-Host "✓ PS2EXE 모듈 설치 완료" -ForegroundColor Green
    }
    else {
        Write-Host "빌드를 취소합니다." -ForegroundColor Red
        exit 1
    }
}
else {
    Write-Host "✓ PS2EXE 모듈 확인 완료" -ForegroundColor Green
}

Import-Module PS2EXE
Write-Host ""

# ========================================
# 2. 필수 파일 확인
# ========================================

Write-Host "[2/4] 필수 파일 확인 중..." -ForegroundColor Yellow

$scriptPath = Join-Path $PSScriptRoot "SecurityChecker-AllInOne.ps1"
$requiredFiles = @(
    "SecurityChecker-AllInOne.ps1",
    "dashboard.html",
    "dashboard.css",
    "dashboard.js",
    "check_definitions.json"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $PSScriptRoot $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
        Write-Host "  ✗ $file" -ForegroundColor Red
    }
    else {
        Write-Host "  ✓ $file" -ForegroundColor Green
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host ""
    Write-Host "오류: 필수 파일이 없습니다." -ForegroundColor Red
    Write-Host "모든 파일이 같은 폴더에 있는지 확인하세요." -ForegroundColor Yellow
    exit 1
}

Write-Host "✓ 모든 필수 파일 확인 완료" -ForegroundColor Green
Write-Host ""

# ========================================
# 3. 빌드 설정
# ========================================

Write-Host "[3/4] 빌드 설정 중..." -ForegroundColor Yellow

$outputPath = Join-Path $PSScriptRoot "dist"
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath -Force | Out-Null
}

$exePath = Join-Path $outputPath "$OutputName.exe"

# 아이콘 파일 (선택 사항)
$iconPath = Join-Path $PSScriptRoot "icon.ico"
$useIcon = $IncludeIcon -and (Test-Path $iconPath)

Write-Host "  출력 경로: $exePath" -ForegroundColor Cyan
if ($useIcon) {
    Write-Host "  아이콘: $iconPath" -ForegroundColor Cyan
}
Write-Host ""

# ========================================
# 4. EXE 빌드
# ========================================

Write-Host "[4/4] EXE 파일 빌드 중..." -ForegroundColor Yellow
Write-Host "이 작업은 수 분이 걸릴 수 있습니다..." -ForegroundColor Gray
Write-Host ""

try {
    $ps2exeParams = @{
        InputFile = $scriptPath
        OutputFile = $exePath
        NoConsole = $false
        NoOutput = $false
        NoError = $false
        RequireAdmin = $false
        Title = "Windows 보안 구성 검사 도구"
        Description = "KISA 기술적 취약점 분석·평가 방법 상세가이드 기반"
        Company = "Security Operations Team"
        Product = "SecurityChecker"
        Version = "2.0.0.0"
        Copyright = "© 2025 Security Operations Team"
    }
    
    if ($useIcon) {
        $ps2exeParams.IconFile = $iconPath
    }
    
    Invoke-PS2EXE @ps2exeParams
    
    Write-Host ""
    Write-Host "✓ EXE 파일 빌드 완료!" -ForegroundColor Green
    Write-Host ""
    
    # 파일 크기 확인
    $exeFile = Get-Item $exePath
    $sizeMB = [math]::Round($exeFile.Length / 1MB, 2)
    
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host "빌드 성공!" -ForegroundColor Green
    Write-Host "=" * 70 -ForegroundColor Green
    Write-Host ""
    Write-Host "실행 파일: $exePath" -ForegroundColor Cyan
    Write-Host "파일 크기: $sizeMB MB" -ForegroundColor Cyan
    Write-Host ""
    
    # 배포 파일 패키징
    Write-Host "배포 패키지 생성 중..." -ForegroundColor Yellow
    
    $deployFolder = Join-Path $outputPath "SecurityChecker_v2.0"
    if (Test-Path $deployFolder) {
        Remove-Item -Path $deployFolder -Recurse -Force
    }
    New-Item -ItemType Directory -Path $deployFolder -Force | Out-Null
    
    # EXE 복사
    Copy-Item -Path $exePath -Destination $deployFolder
    
    # 대시보드 파일 복사
    $dashboardFolder = Join-Path $deployFolder "dashboard"
    New-Item -ItemType Directory -Path $dashboardFolder -Force | Out-Null
    
    Copy-Item -Path (Join-Path $PSScriptRoot "dashboard.html") -Destination $dashboardFolder
    Copy-Item -Path (Join-Path $PSScriptRoot "dashboard.css") -Destination $dashboardFolder
    Copy-Item -Path (Join-Path $PSScriptRoot "dashboard.js") -Destination $dashboardFolder
    Copy-Item -Path (Join-Path $PSScriptRoot "check_definitions.json") -Destination $dashboardFolder
    
    # README 생성
    $readmePath = Join-Path $deployFolder "README.txt"
    $readmeContent = @"
Windows 보안 구성 검사 도구 v2.0
=========================================

사용 방법:
1. SecurityChecker.exe를 더블클릭하여 실행
2. 보안 검사가 자동으로 시작됩니다
3. 검사 완료 후 브라우저가 자동으로 열립니다
4. 대시보드에서 결과를 확인하세요

주의 사항:
- 관리자 권한으로 실행하는 것을 권장합니다
- 결과는 %APPDATA%\SecurityChecker\Results에 저장됩니다
- 오프라인에서도 완전히 작동합니다

문의:
Security Operations Team
"@
    
    $readmeContent | Out-File -FilePath $readmePath -Encoding UTF8
    
    Write-Host "✓ 배포 패키지 생성 완료: $deployFolder" -ForegroundColor Green
    Write-Host ""
    
    # ZIP 압축 (선택)
    $response = Read-Host "배포 패키지를 ZIP으로 압축하시겠습니까? (Y/N)"
    if ($response -eq 'Y' -or $response -eq 'y') {
        $zipPath = Join-Path $outputPath "SecurityChecker_v2.0.zip"
        if (Test-Path $zipPath) {
            Remove-Item -Path $zipPath -Force
        }
        
        Compress-Archive -Path $deployFolder -DestinationPath $zipPath -CompressionLevel Optimal
        Write-Host "✓ ZIP 파일 생성: $zipPath" -ForegroundColor Green
    }
    
    Write-Host ""
    Write-Host "배포 준비 완료!" -ForegroundColor Green
    Write-Host "다음 폴더를 배포하세요: $deployFolder" -ForegroundColor Cyan
    Write-Host ""
}
catch {
    Write-Host ""
    Write-Host "오류 발생: $_" -ForegroundColor Red
    Write-Host ""
    exit 1
}

Write-Host "Enter 키를 눌러 종료..." -ForegroundColor Gray
Read-Host
