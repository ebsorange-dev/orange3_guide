@echo off
chcp 65001 >nul
setlocal

set PROJECT_DIR=d:\_26_Use_Orange_New_set_OSS
set DOCKER_DESKTOP=C:\Program Files\Docker\Docker\Docker Desktop.exe

echo [Orange3] 서버 시작 중...

:: Docker Desktop 실행 확인
docker info >nul 2>&1
if %errorlevel% neq 0 (
    echo [1/3] Docker Desktop 시작 중...
    start "" "%DOCKER_DESKTOP%"

    :: Docker 데몬 대기 (최대 60초)
    set /a count=0
    :wait_loop
    timeout /t 5 /nobreak >nul
    set /a count+=5
    docker info >nul 2>&1
    if %errorlevel% equ 0 goto docker_ready
    if %count% geq 60 (
        echo [오류] Docker Desktop 시작 실패. 수동으로 실행 후 다시 시도하세요.
        pause
        exit /b 1
    )
    echo     대기 중... (%count%초)
    goto wait_loop
) else (
    echo [1/3] Docker Desktop 이미 실행 중
)

:docker_ready
echo [2/3] 컨테이너 시작 중...
cd /d "%PROJECT_DIR%"
docker compose up -d
if %errorlevel% neq 0 (
    echo.
    echo [!] 포트 충돌 감지 - WinNAT 재시작 시도 중...
    powershell -Command "Start-Process powershell -Verb RunAs -WindowStyle Hidden -ArgumentList '-Command','net stop winnat; net start winnat' -Wait"
    timeout /t 3 /nobreak >nul
    docker compose up -d
    if %errorlevel% neq 0 (
        echo [오류] 서버 시작 실패.
        pause
        exit /b 1
    )
)

echo [3/3] 상태 확인 중...
timeout /t 5 /nobreak >nul
docker compose ps

echo.
echo [완료] Orange3 서버가 실행 중입니다.
echo   접속 주소: http://127.0.0.1:8888
echo.
pause
