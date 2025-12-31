<#
.SYNOPSIS
    간단한 HTTP 서버를 시작하여 보안 검사 대시보드를 실행합니다.

.DESCRIPTION
    이 스크립트는 PowerShell을 사용하여 간단한 HTTP 서버를 시작하고
    웹 브라우저에서 대시보드를 자동으로 엽니다.

.PARAMETER Port
    서버가 실행될 포트 번호 (기본값: 8080)

.EXAMPLE
    .\Start-Dashboard.ps1
    기본 포트(8080)로 대시보드 서버 시작

.EXAMPLE
    .\Start-Dashboard.ps1 -Port 3000
    포트 3000으로 대시보드 서버 시작

.NOTES
    Ctrl+C를 눌러 서버를 종료할 수 있습니다.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int]$Port = 8080
)

$ErrorActionPreference = "Stop"

# 현재 스크립트 경로
$scriptPath = $PSScriptRoot

Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host "🌐 Windows 보안 검사 대시보드 서버" -ForegroundColor Cyan
Write-Host "=" * 80 -ForegroundColor Cyan
Write-Host ""

# 필수 파일 확인
$requiredFiles = @(
    "dashboard.html",
    "dashboard.css",
    "dashboard.js",
    "check_definitions.json"
)

$missingFiles = @()
foreach ($file in $requiredFiles) {
    $filePath = Join-Path $scriptPath $file
    if (-not (Test-Path $filePath)) {
        $missingFiles += $file
    }
}

if ($missingFiles.Count -gt 0) {
    Write-Host "❌ 다음 파일이 없습니다:" -ForegroundColor Red
    $missingFiles | ForEach-Object { Write-Host "   - $_" -ForegroundColor Red }
    Write-Host ""
    Write-Host "모든 파일이 같은 폴더에 있는지 확인하세요." -ForegroundColor Yellow
    exit 1
}

# 포트 사용 여부 확인
$portInUse = Get-NetTCPConnection -LocalPort $Port -ErrorAction SilentlyContinue
if ($portInUse) {
    Write-Host "❌ 포트 $Port 는 이미 사용 중입니다." -ForegroundColor Red
    Write-Host "다른 포트를 지정하거나 해당 포트를 사용 중인 프로그램을 종료하세요." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "예: .\Start-Dashboard.ps1 -Port 3000" -ForegroundColor Cyan
    exit 1
}

Write-Host "✓ 모든 필수 파일 확인 완료" -ForegroundColor Green
Write-Host "✓ 포트 $Port 사용 가능" -ForegroundColor Green
Write-Host ""

# URL 구성
$url = "http://localhost:$Port/"

# 서버 시작 안내
Write-Host "🚀 서버 시작 중..." -ForegroundColor Yellow
Write-Host ""
Write-Host "📍 서버 주소: $url" -ForegroundColor Green
Write-Host "📁 서버 경로: $scriptPath" -ForegroundColor Cyan
Write-Host ""
Write-Host "대시보드 사용 방법:" -ForegroundColor Yellow
Write-Host "1. 브라우저가 자동으로 열립니다" -ForegroundColor White
Write-Host "2. '검사 결과 파일 선택' 버튼을 클릭하세요" -ForegroundColor White
Write-Host "3. JSON 결과 파일을 선택하세요" -ForegroundColor White
Write-Host ""
Write-Host "⚠️  서버를 종료하려면 Ctrl+C를 누르세요" -ForegroundColor Yellow
Write-Host ""
Write-Host "-" * 80 -ForegroundColor Gray

# 간단한 HTTP 서버 시작
try {
    # HTTP 리스너 생성
    $listener = New-Object System.Net.HttpListener
    $listener.Prefixes.Add($url)
    $listener.Start()

    Write-Host "✓ 서버가 시작되었습니다!" -ForegroundColor Green
    Write-Host ""

    # 브라우저 자동 열기
    Start-Process $url

    Write-Host "서버 로그:" -ForegroundColor Cyan
    Write-Host ""

    # 요청 처리 루프
    while ($listener.IsListening) {
        # 요청 대기 (비동기)
        $contextTask = $listener.GetContextAsync()
        
        while (-not $contextTask.IsCompleted) {
            if ([Console]::KeyAvailable) {
                $key = [Console]::ReadKey($true)
                if ($key.Key -eq 'C' -and $key.Modifiers -eq 'Control') {
                    Write-Host ""
                    Write-Host "🛑 서버 종료 중..." -ForegroundColor Yellow
                    $listener.Stop()
                    break
                }
            }
            Start-Sleep -Milliseconds 100
        }
        
        if (-not $listener.IsListening) {
            break
        }
        
        $context = $contextTask.Result
        $request = $context.Request
        $response = $context.Response
        
        # 요청 URL
        $requestUrl = $request.Url.LocalPath
        $timestamp = Get-Date -Format "HH:mm:ss"
        
        Write-Host "[$timestamp] " -NoNewline -ForegroundColor Gray
        Write-Host "$($request.HttpMethod) " -NoNewline -ForegroundColor Cyan
        Write-Host "$requestUrl" -ForegroundColor White
        
        # 파일 경로 결정
        $filePath = if ($requestUrl -eq "/") {
            Join-Path $scriptPath "dashboard.html"
        } else {
            Join-Path $scriptPath $requestUrl.TrimStart('/')
        }
        
        # 파일 존재 여부 확인 및 응답
        if (Test-Path $filePath) {
            try {
                # 파일 읽기
                $content = [System.IO.File]::ReadAllBytes($filePath)
                
                # MIME 타입 설정
                $extension = [System.IO.Path]::GetExtension($filePath)
                $mimeType = switch ($extension) {
                    ".html" { "text/html; charset=utf-8" }
                    ".css"  { "text/css; charset=utf-8" }
                    ".js"   { "application/javascript; charset=utf-8" }
                    ".json" { "application/json; charset=utf-8" }
                    ".png"  { "image/png" }
                    ".jpg"  { "image/jpeg" }
                    ".ico"  { "image/x-icon" }
                    default { "application/octet-stream" }
                }
                
                $response.ContentType = $mimeType
                $response.ContentLength64 = $content.Length
                $response.StatusCode = 200
                $response.OutputStream.Write($content, 0, $content.Length)
            }
            catch {
                Write-Host "   ❌ 파일 읽기 오류: $_" -ForegroundColor Red
                $response.StatusCode = 500
            }
        }
        else {
            Write-Host "   ⚠️  파일을 찾을 수 없음: $filePath" -ForegroundColor Yellow
            $response.StatusCode = 404
            $errorMessage = "404 - File Not Found: $requestUrl"
            $buffer = [System.Text.Encoding]::UTF8.GetBytes($errorMessage)
            $response.ContentLength64 = $buffer.Length
            $response.OutputStream.Write($buffer, 0, $buffer.Length)
        }
        
        $response.Close()
    }
}
catch {
    Write-Host ""
    Write-Host "❌ 서버 오류: $_" -ForegroundColor Red
}
finally {
    if ($listener -and $listener.IsListening) {
        $listener.Stop()
    }
    $listener.Close()
    Write-Host ""
    Write-Host "✓ 서버가 종료되었습니다." -ForegroundColor Green
    Write-Host ""
}
