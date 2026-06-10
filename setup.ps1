# Orange3 Web Convert — 초기 환경 설정 스크립트
# 사용법: git clone ... && cd orange3webconvert && .\setup.ps1
# 이 스크립트는 .env 생성, 디렉토리 생성, CRLF 변환, 빌드, 기동을 한 번에 처리합니다.

param(
    [switch]$BuildOnly,   # 빌드만 하고 기동하지 않음
    [switch]$StartOnly,   # 빌드 없이 기동만 함 (이미지 기존재 시)
    [switch]$NoBuild      # 별칭: -StartOnly 와 동일
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── 1. 현재 디렉토리 확인 ──────────────────────────────────────────────────────
$ProjectRoot = $PSScriptRoot
if (-not $ProjectRoot) { $ProjectRoot = (Get-Location).Path }
Write-Host "`n[1/6] 프로젝트 경로: $ProjectRoot" -ForegroundColor Cyan

# ── 2. HOST_BASE 자동 계산 ────────────────────────────────────────────────────
# Windows 경로 → Docker 경로 변환 (예: D:\Foo\Bar → /d/Foo/Bar)
$drive = ($ProjectRoot -replace '^([A-Za-z]):\\.*', '$1').ToLower()
$rest  = ($ProjectRoot -replace '^[A-Za-z]:\\', '') -replace '\\', '/'
$HostBase = "/$drive/$rest"
Write-Host "[2/6] HOST_BASE = $HostBase" -ForegroundColor Cyan

# ── 3. .env 생성 (기존 파일 백업 후 덮어쓰기) ──────────────────────────────────
$EnvPath = "$ProjectRoot\.env"

# 기존 .env 에서 Google/Firebase 값 보존
$existingOAuth = ""
$existingFirebase = ""
$existingAdminEmails = ""
if (Test-Path $EnvPath) {
    $existing = Get-Content $EnvPath
    $existingOAuth = ($existing | Where-Object { $_ -match "^GOOGLE_OAUTH_CLIENT_ID=" }) -replace "^GOOGLE_OAUTH_CLIENT_ID=", ""
    $existingSecret = ($existing | Where-Object { $_ -match "^GOOGLE_OAUTH_CLIENT_SECRET=" }) -replace "^GOOGLE_OAUTH_CLIENT_SECRET=", ""
    $existingRedirect = ($existing | Where-Object { $_ -match "^GOOGLE_OAUTH_REDIRECT_URI=" }) -replace "^GOOGLE_OAUTH_REDIRECT_URI=", ""
    $existingFirebase = ($existing | Where-Object { $_ -match "^FIREBASE_PROJECT_ID=" }) -replace "^FIREBASE_PROJECT_ID=", ""
    $existingFbConfig = ($existing | Where-Object { $_ -match "^FIREBASE_WEB_CONFIG=" }) -replace "^FIREBASE_WEB_CONFIG=", ""
    $existingAdminEmails = ($existing | Where-Object { $_ -match "^ADMIN_EMAILS=" }) -replace "^ADMIN_EMAILS=", ""
    Copy-Item $EnvPath "$EnvPath.bak" -Force
    Write-Host "       기존 .env 백업 → .env.bak" -ForegroundColor DarkGray
} else {
    $existingSecret = ""
    $existingRedirect = "http://localhost:8888/api/gdrive/callback"
    $existingFbConfig = ""
}

$EnvContent = @"
# Orange3 Web Convert 환경 설정 — setup.ps1 이 자동 생성함 (수정 가능)
# 재생성: .\setup.ps1  (기존 Google/Firebase 값은 보존됨)

# 호스트 베이스 경로 (자동 감지) — Docker 볼륨 마운트에 사용
HOST_BASE=$HostBase

# Google Drive OAuth (OPEN 모달 → LOGIN TO GOOGLE)
# 비워두면 로그인 버튼 비활성. Google Cloud Console 에서 발급 후 입력.
GOOGLE_OAUTH_CLIENT_ID=$existingOAuth
GOOGLE_OAUTH_CLIENT_SECRET=$existingSecret
GOOGLE_OAUTH_REDIRECT_URI=$existingRedirect

# 관리자 페이지 Firebase 인증 (비워두면 개발 모드 — 인증 없이 접근 가능)
FIREBASE_PROJECT_ID=$existingFirebase
FIREBASE_WEB_CONFIG=$existingFbConfig
ADMIN_EMAILS=$existingAdminEmails
"@

[System.IO.File]::WriteAllText($EnvPath, $EnvContent, [System.Text.UTF8Encoding]::new($false))
Write-Host "       .env 생성 완료" -ForegroundColor Green

# ── 4. 필요 디렉토리 생성 ──────────────────────────────────────────────────────
Write-Host "[3/6] 런타임 디렉토리 생성 중..." -ForegroundColor Cyan
$dirs = @(
    "sessions",        # 세션별 설정 (admin_settings.json 포함)
    "data",            # 공유 데이터 (읽기 전용)
    "_upload_ows_",    # 사용자 업로드 OWS 워크플로우
    "thumbs_shared",   # 공유 썸네일 SVG 캐시
    "logs",            # 사용 로그 JSONL
    "splash_custom"    # 관리자 업로드 스플래시 이미지
)
foreach ($d in $dirs) {
    $path = "$ProjectRoot\$d"
    if (-not (Test-Path $path)) {
        New-Item -ItemType Directory -Force $path | Out-Null
        Write-Host "       생성: $d\" -ForegroundColor DarkGray
    } else {
        Write-Host "       기존: $d\" -ForegroundColor DarkGray
    }
}

# ── 5. CRLF → LF 변환 (Windows 클론 시 .sh 파일이 CRLF 일 수 있음) ────────────
Write-Host "[4/6] 셸 스크립트 줄바꿈 확인 중..." -ForegroundColor Cyan
$scripts = Get-ChildItem -Recurse -Filter "*.sh" $ProjectRoot | Select-Object -ExpandProperty FullName
$fixedCount = 0
foreach ($f in $scripts) {
    $bytes = [System.IO.File]::ReadAllBytes($f)
    $text  = [System.Text.Encoding]::UTF8.GetString($bytes)
    if ($text.Contains("`r`n")) {
        [System.IO.File]::WriteAllText($f, $text.Replace("`r`n", "`n"), [System.Text.UTF8Encoding]::new($false))
        $fixedCount++
    }
}
if ($fixedCount -gt 0) {
    Write-Host "       CRLF→LF 변환: $fixedCount 개 파일" -ForegroundColor Yellow
} else {
    Write-Host "       줄바꿈 정상 (LF)" -ForegroundColor DarkGray
}

# ── 6. Docker 이미지 빌드 ──────────────────────────────────────────────────────
if (-not $StartOnly -and -not $NoBuild) {
    Write-Host "[5/6] Docker 이미지 빌드 중 (캐시 사용, 최초 빌드 시 수십 분 소요)..." -ForegroundColor Cyan

    # orange3-gui 먼저 (orange3-xpra 가 이 이미지에 의존)
    Write-Host "       Step 1/2: orange3-gui 빌드..." -ForegroundColor DarkGray
    docker compose -f "$ProjectRoot\docker-compose.yml" build orange3-gui
    if ($LASTEXITCODE -ne 0) { throw "orange3-gui 빌드 실패" }

    # 나머지 이미지 (session-manager, web-server, orange3-xpra)
    Write-Host "       Step 2/2: 나머지 이미지 빌드..." -ForegroundColor DarkGray
    docker compose -f "$ProjectRoot\docker-compose.yml" --profile build-only build
    if ($LASTEXITCODE -ne 0) { throw "이미지 빌드 실패" }

    Write-Host "       빌드 완료" -ForegroundColor Green
} else {
    Write-Host "[5/6] 빌드 생략 (-StartOnly 또는 -NoBuild 플래그)" -ForegroundColor DarkGray
}

# ── 7. 서비스 기동 ─────────────────────────────────────────────────────────────
if (-not $BuildOnly) {
    Write-Host "[6/6] 서비스 기동 중..." -ForegroundColor Cyan
    docker compose -f "$ProjectRoot\docker-compose.yml" up -d
    if ($LASTEXITCODE -ne 0) { throw "서비스 기동 실패" }

    Write-Host "`n완료! 서비스 주소:" -ForegroundColor Green
    Write-Host "  세션 매니저 (메인): http://localhost:8888" -ForegroundColor White
    Write-Host "  Nginx 프록시:       http://localhost:8889" -ForegroundColor White
    Write-Host "  웹 서버:            http://localhost:9508" -ForegroundColor White
    Write-Host "`n워밍풀이 채워지는 데 약 40~60초 소요됩니다." -ForegroundColor DarkGray
    Write-Host "로그 확인: docker compose -f `"$ProjectRoot\docker-compose.yml`" logs -f session-manager`n" -ForegroundColor DarkGray
} else {
    Write-Host "[6/6] 기동 생략 (-BuildOnly 플래그)`n" -ForegroundColor DarkGray
}
