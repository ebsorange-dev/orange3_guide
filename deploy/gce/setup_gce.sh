#!/usr/bin/env bash
# =============================================================================
# orange3web — Google Compute Engine (Ubuntu 22.04) 부트스트랩
# Docker 설치 + .env 생성(HOST_BASE 자동) 까지. 빌드/기동은 마지막 안내대로.
# 사용: VM 에서 repo clone 후
#   cd orange3web && bash deploy/gce/setup_gce.sh
# =============================================================================
set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$REPO_DIR"
echo "[i] repo: $REPO_DIR"

# ── 1) Docker + compose plugin 설치 (공식 apt repo) ──────────────────────────
if ! command -v docker >/dev/null 2>&1; then
  echo "[+] Docker 설치 중..."
  sudo apt-get update
  sudo apt-get install -y ca-certificates curl gnupg git
  sudo install -m 0755 -d /etc/apt/keyrings
  curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
    | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
  sudo chmod a+r /etc/apt/keyrings/docker.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
    | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
  sudo apt-get update
  sudo apt-get install -y docker-ce docker-ce-cli containerd.io \
                          docker-buildx-plugin docker-compose-plugin
  sudo usermod -aG docker "$USER"
  echo "[!] docker 그룹 적용을 위해 재로그인 또는: newgrp docker"
else
  echo "[i] Docker 이미 설치됨: $(docker --version)"
fi

# ── 2) .env 생성/교정 (HOST_BASE = repo 절대경로) ────────────────────────────
# docker.sock 으로 띄우는 GUI 컨테이너의 bind 마운트는 호스트 절대경로가 필요하다.
# ★ 재발방지: .env 가 이미 있어도 HOST_BASE 가 현재 repo 경로와 다르면 강제 교정.
#   (로컬 Windows 의 .env(HOST_BASE=/e/...) 가 따라온 채로 기동되면 위젯 스타일이
#    조용히 빠지는 사고를 차단한다.)
if [ ! -f .env ]; then
  cp deploy/gce/.env.gce.example .env
  sed -i "s#__HOST_BASE__#${REPO_DIR}#g" .env
  echo "[+] .env 생성 — HOST_BASE=${REPO_DIR}"
  echo "    (Google OAuth 를 쓸 경우 .env 의 GOOGLE_OAUTH_* 와 외부 IP/도메인 편집)"
else
  CUR_HB="$(sed -n 's/^HOST_BASE=//p' .env | head -1)"
  if [ "$CUR_HB" = "$REPO_DIR" ]; then
    echo "[i] .env 존재 — HOST_BASE 정상(${CUR_HB})"
  else
    cp .env ".env.bak.$(date +%Y%m%d%H%M%S)"
    if grep -q '^HOST_BASE=' .env; then
      sed -i "s#^HOST_BASE=.*#HOST_BASE=${REPO_DIR}#" .env
    else
      printf '\nHOST_BASE=%s\n' "${REPO_DIR}" >> .env
    fi
    echo "[!] .env 의 HOST_BASE 를 교정: '${CUR_HB:-<없음>}' → '${REPO_DIR}' (백업: .env.bak.*)"
    case "$CUR_HB" in
      /[A-Za-z]/*) echo "    ※ 이전 값이 Windows 드라이브식 경로였음 — GCP 에선 위젯 스타일 누락 원인." ;;
    esac
  fi
fi

# ── 3) 런타임 디렉터리 보장 (compose 볼륨 대상) ──────────────────────────────
mkdir -p sessions config data thumbs_shared

cat <<EOF

[✓] 준비 완료.

다음 단계:
  1) (재로그인 했거나 newgrp docker 적용 후)
  2) 이미지 빌드:
       docker compose -f docker-compose.yml --profile build-only build
  3) 기동:
       docker compose up -d
  4) 접속:  http://<VM_EXTERNAL_IP>:8888

방화벽(아직 안 열었다면, 로컬 gcloud 에서):
  gcloud compute firewall-rules create orange3web-allow \\
    --allow=tcp:8888,tcp:10000-10199 \\
    --target-tags=orange3web --source-ranges=0.0.0.0/0

작은 VM 이면 docker-compose.yml 의 WARM_POOL_SIZE 를 낮추세요(기본 25 → 예 5).
EOF
