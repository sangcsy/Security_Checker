<#
.SYNOPSIS
    Security Checker 올인원 스크립트를 EXE로 패키징합니다.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$OutputName = 'SecurityChecker',

    [Parameter(Mandatory = $false)]
    [switch]$IncludeIcon
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$inputScript = Join-Path $projectRoot 'scripts\SecurityChecker-AllInOne.ps1'
$outputRoot = Join-Path $projectRoot 'dist'
$tempBuildRoot = Join-Path $outputRoot '.build'
$dashboardDir = Join-Path $projectRoot 'dashboard'
$configDir = Join-Path $projectRoot 'config'
$iconPath = Join-Path $projectRoot 'icon.ico'

$requiredFiles = @(
    $inputScript,
    (Join-Path $dashboardDir 'dashboard.html'),
    (Join-Path $dashboardDir 'dashboard.css'),
    (Join-Path $dashboardDir 'dashboard.js'),
    (Join-Path $configDir 'check_definitions.json')
)

$missingFiles = $requiredFiles | Where-Object { -not (Test-Path $_) }
if ($missingFiles.Count -gt 0) {
    Write-Host '필수 파일이 없습니다.' -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
    exit 1
}

if (-not (Get-Module -ListAvailable -Name PS2EXE)) {
    Write-Host 'PS2EXE 모듈이 필요합니다. Install-Module PS2EXE 로 먼저 설치하세요.' -ForegroundColor Red
    exit 1
}

Import-Module PS2EXE
New-Item -ItemType Directory -Path $outputRoot -Force | Out-Null
if (Test-Path $tempBuildRoot) {
    Remove-Item -Recurse -Force $tempBuildRoot
}
New-Item -ItemType Directory -Path $tempBuildRoot -Force | Out-Null

$exePath = Join-Path $tempBuildRoot "$OutputName.exe"
$params = @{
    InputFile = $inputScript
    OutputFile = $exePath
    NoConsole = $false
    NoOutput = $false
    NoError = $false
    RequireAdmin = $false
    Title = 'Windows 보안 구성 검사 도구'
    Description = 'KISA 기반 Windows 보안 점검 도구'
    Company = 'Security Checker'
    Product = 'SecurityChecker'
    Version = '1.0.0.0'
}

if ($IncludeIcon -and (Test-Path $iconPath)) {
    $params.IconFile = $iconPath
}

Invoke-PS2EXE @params

$deployRoot = Join-Path $outputRoot 'SecurityChecker_v1.0'
if (Test-Path $deployRoot) {
    Remove-Item -Recurse -Force $deployRoot
}
New-Item -ItemType Directory -Path $deployRoot -Force | Out-Null
Copy-Item -Path $exePath -Destination $deployRoot
Copy-Item -Path $dashboardDir -Destination (Join-Path $deployRoot 'dashboard') -Recurse
Copy-Item -Path $configDir -Destination (Join-Path $deployRoot 'config') -Recurse
Remove-Item -Recurse -Force $tempBuildRoot

@"
Windows 보안 구성 검사 도구
============================

실행 파일: $OutputName.exe
대시보드: dashboard\\dashboard.html
정의 파일: config\\check_definitions.json
"@ | Set-Content -Path (Join-Path $deployRoot 'README.txt') -Encoding UTF8

Write-Host "빌드 완료: $(Join-Path $deployRoot "$OutputName.exe")" -ForegroundColor Green
Write-Host "배포 폴더: $deployRoot" -ForegroundColor Green
