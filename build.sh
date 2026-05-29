#!/bin/bash
# Orange3 Docker 이미지 빌드 스크립트
set -e

echo "=== Orange3 Docker 이미지 빌드 ==="
echo ""

# orange3-gui 이미지 빌드
echo "[1/3] orange3-gui 이미지 빌드 중..."
docker compose build orange3-gui
echo "      완료: orange3-gui"

# session-manager 이미지 빌드
echo "[2/3] session-manager 이미지 빌드 중..."
docker compose build session-manager
echo "      완료: orange3-session-manager"

# web-server 이미지 빌드
echo "[3/3] web-server 이미지 빌드 중..."
docker compose build web-server
echo "      완료: orange3-web-server"

echo ""
echo "=== 빌드 완료 ==="
echo ""
echo "전체 서비스 시작:  docker compose up -d web-server session-manager"
echo "session-manager:  docker compose up -d session-manager"
echo "로그 확인:         docker compose logs -f session-manager"
echo ""
echo "접속 URL:"
echo "  메인 페이지:      http://localhost:9508"
echo "  세션 매니저:      http://localhost:8888"
