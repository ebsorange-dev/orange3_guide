@echo off
chcp 65001 >nul
setlocal

set PROJECT_DIR=d:\_26_Use_Orange_New_set_OSS

echo [Orange3] 서버 종료 중...

cd /d "%PROJECT_DIR%"
docker compose down

echo.
echo [완료] Orange3 서버가 종료되었습니다.
echo.
pause
