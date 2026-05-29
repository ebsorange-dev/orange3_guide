#!/bin/bash
# ── Xpra 전환 PoC 기동 스크립트 (Phase 1, 2026-05-23) ────────────────────────
# Orange3 를 Xpra HTML5 데스크톱 세션으로 노출한다.
#   xpra start-desktop : 내장 X 서버(:100) + 데스크톱 세션 생성
#   --html=on          : 브라우저용 HTML5 클라이언트 동시 서빙
#   --bind-tcp         : HTTP/Xpra 프로토콜 수신 포트
# noVNC 스택과 무관 — 이 스크립트는 PoC 이미지 전용.
set -u

export HOME=/root
export DISPLAY=:100
# 한글 입력기 (orange3-gui 베이스에 ibus-hangul 이미 설치됨)
export GTK_IM_MODULE=ibus
export QT_IM_MODULE=ibus
export XMODIFIERS=@im=ibus

# ── 마우스 커서 테마 (2026-05-24) — Windows 기본 흰색 화살표 (DMZ-White) ──
# 기본 X11 left_ptr(검은 화살표)는 Windows 사용자에게 낯섦. DMZ-White 가
# Windows 11 기본 커서와 시각적으로 가장 가까움.
export XCURSOR_THEME=DMZ-White
export XCURSOR_SIZE=24

# Xcursor.theme 리소스도 명시 (일부 앱은 환경변수 대신 Xresources 조회)
mkdir -p /root
printf 'Xcursor.theme: DMZ-White\nXcursor.size: 24\n' > /root/.Xresources

mkdir -p /root/.config /root/.xpra /run/user/0
export XDG_RUNTIME_DIR=/run/user/0

echo "[xpra-poc] Xpra 데스크톱 세션 시작 — Orange3 (cursor=DMZ-White)"

# D-Bus 세션 버스 (ibus 의존)
if [ -z "${DBUS_SESSION_BUS_ADDRESS:-}" ]; then
    eval "$(dbus-launch --sh-syntax 2>/dev/null)" || true
    export DBUS_SESSION_BUS_ADDRESS
fi

# ── Xpra HTML5 데스크톱 세션 (포그라운드) ─────────────────────────────────────
# --start          : 세션 안에서 실행할 명령 (창 관리자 + 한글 입력기 + Orange3)
# --start-child    : 종료 추적 대상 자식 (Orange3 종료 시 세션 종료)
# --resize-display : 브라우저 창 크기에 맞춰 디스플레이 리사이즈
exec xpra start-desktop :100 \
    --bind-tcp=0.0.0.0:10000 \
    --html=on \
    --daemon=no \
    --resize-display=yes \
    --start="openbox" \
    --start="xrdb -merge /root/.Xresources" \
    --start="xsetroot -xcf /usr/share/icons/DMZ-White/cursors/left_ptr 24" \
    --start="ibus-daemon -drx" \
    --start="/init_ibus_hangul.sh" \
    --start="/maximize_orange3.sh" \
    --start-child="python3 /app/orange3_launcher.py" \
    --exit-with-children=yes \
    --input-method=IBus \
    --mdns=no \
    --pulseaudio=no \
    --notifications=no \
    --bell=no \
    --speaker=disabled \
    --microphone=disabled \
    --webcam=no \
    --printing=no \
    --system-tray=no \
    --clipboard=no \
    --bandwidth-detection=yes \
    --bandwidth-limit=0 \
    --quality=80 \
    --min-quality=30 \
    --speed=80 \
    --min-speed=30 \
    --auto-refresh-delay=2 \
    --encoding=auto
