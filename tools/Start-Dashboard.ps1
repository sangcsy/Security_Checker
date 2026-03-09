<#
.SYNOPSIS
    로컬 HTTP 서버로 대시보드를 실행합니다.

.DESCRIPTION
    프로젝트 루트를 기준으로 dashboard 및 config 폴더를 서빙합니다.
    기본 경로는 /dashboard/dashboard.html 입니다.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [int]$Port = 8080
)

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $PSScriptRoot
$dashboardDir = Join-Path $projectRoot 'dashboard'
$configFile = Join-Path $projectRoot 'config\check_definitions.json'
$defaultPage = '/dashboard/dashboard.html'
$url = "http://localhost:$Port/"

$requiredFiles = @(
    (Join-Path $dashboardDir 'dashboard.html'),
    (Join-Path $dashboardDir 'dashboard.css'),
    (Join-Path $dashboardDir 'dashboard.js'),
    $configFile
)

$missingFiles = $requiredFiles | Where-Object { -not (Test-Path $_) }
if ($missingFiles.Count -gt 0) {
    Write-Host '필수 파일이 없습니다.' -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "- $_" -ForegroundColor Red }
    exit 1
}

$portInUse = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "포트 $Port 는 이미 사용 중입니다." -ForegroundColor Red
    exit 1
}

Write-Host ('=' * 70) -ForegroundColor Cyan
Write-Host 'Security Checker Dashboard Server' -ForegroundColor Cyan
Write-Host ('=' * 70) -ForegroundColor Cyan
Write-Host "프로젝트 루트: $projectRoot" -ForegroundColor DarkGray
Write-Host "대시보드 주소: ${url}dashboard/dashboard.html" -ForegroundColor Green
Write-Host ''

$listener = $null
try {
    $listener = [System.Net.HttpListener]::new()
    $listener.Prefixes.Add($url)
    $listener.Start()

    Start-Process "${url}dashboard/dashboard.html"

    while ($listener.IsListening) {
        $context = $listener.GetContext()
        $request = $context.Request
        $response = $context.Response
        $path = $request.Url.LocalPath

        if ([string]::IsNullOrWhiteSpace($path) -or $path -eq '/') {
            $path = $defaultPage
        }

        $relativePath = $path.TrimStart('/').Replace('/', '\\')
        $filePath = Join-Path $projectRoot $relativePath

        if (Test-Path $filePath) {
            $content = [System.IO.File]::ReadAllBytes($filePath)
            $extension = [System.IO.Path]::GetExtension($filePath)
            $response.ContentType = switch ($extension) {
                '.html' { 'text/html; charset=utf-8' }
                '.css' { 'text/css; charset=utf-8' }
                '.js' { 'application/javascript; charset=utf-8' }
                '.json' { 'application/json; charset=utf-8' }
                default { 'application/octet-stream' }
            }
            $response.StatusCode = 200
            $response.ContentLength64 = $content.Length
            $response.OutputStream.Write($content, 0, $content.Length)
        } else {
            $body = [System.Text.Encoding]::UTF8.GetBytes("404 Not Found: $path")
            $response.StatusCode = 404
            $response.ContentType = 'text/plain; charset=utf-8'
            $response.ContentLength64 = $body.Length
            $response.OutputStream.Write($body, 0, $body.Length)
        }

        $response.Close()
    }
}
catch {
    Write-Host "서버 실행 중 오류: $_" -ForegroundColor Red
    exit 1
}
finally {
    if ($listener -and $listener.IsListening) {
        $listener.Stop()
    }
    if ($listener) {
        $listener.Close()
    }
}

