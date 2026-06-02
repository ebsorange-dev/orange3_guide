#!/bin/sh
export QT_X11_NO_MITSHM=1
export XDG_CURRENT_DESKTOP=XFCE
export DISPLAY=:0

# X11 루트 윈도우 배경을 흰색으로 설정
xsetroot -solid white 2>/dev/null || true
# X 커서를 표준 포인터(left_ptr)로 설정 — DMZ-White 테마 사용
xsetroot -cursor_name left_ptr 2>/dev/null || true

# 이전 준비 파일 삭제
rm -f /config/.app_ready

# noVNC 캔버스 설정 UI 비노출 처리 + body 배경 흰색 강제 (Phase 5, 2026-05-24)
# base.css 의 body{background:#313131} 다크 그레이가 VNC 픽셀 도착 전 노출되어
# 사용자 화면이 검게 보임 → html,body,#noVNC_screen 모두 흰색 override.
for _html in $(find /opt -name "index.html" 2>/dev/null); do
    grep -q "x-hide-settings" "$_html" 2>/dev/null && continue
    sed -i 's|</head>|<style id="x-hide-settings">#settings_btn,#noVNC_settings_btn,#settings,.settings-panel,.noVNC_panel_content[id*="setting"],[id*="settings_menu"],[data-page="settings"],a[href*="settings"],button[title*="ettings"],button[aria-label*="ettings"],li.noVNC_heading + li,#noVNC_control_bar_anchor,#noVNC_control_bar_handle,#noVNC_control_bar,.noVNC_vcenter{display:none!important}html,body,#noVNC_screen{background:#ffffff!important}</style></head>|' "$_html" 2>/dev/null
done

# 창 하단 리사이즈 핸들 라인 + 창 테두리 라인 제거 (10-openbox.sh 이후 실행됨)
# border.width:1 + window.*.border.color:#585a5d 가 최대화 창 상단에 어두운 1px 라인을
# 만들어 캔버스 상단 검은 라인으로 보임 → border.width:0 으로 제거 (2026-05-22)
THEMERC="/config/xdg/data/themes/OpenboxTheme/openbox-3/themerc"
[ -f "$THEMERC" ] && sed -i \
    -e 's/^window\.handle\.width:.*/window.handle.width: 0/' \
    -e 's/^border\.width:.*/border.width: 0/' \
    "$THEMERC"
openbox --reconfigure 2>/dev/null || true

# ── 한글 입력기(ibus) 시작 (2026-05-22) ──────────────────────────────────────
# Orange3(Qt5) 가 ibus 를 통해 한글을 직접 조합하도록 데몬을 먼저 띄운다.
# 한/영 전환: Hangul 키 또는 Shift+Space (dconf hangul-keys 설정).
if ! pgrep -x ibus-daemon >/dev/null 2>&1; then
    # D-Bus 세션 버스 확보 (없으면 새로 시작)
    if [ -z "$DBUS_SESSION_BUS_ADDRESS" ]; then
        eval "$(dbus-launch --sh-syntax 2>/dev/null)"
        export DBUS_SESSION_BUS_ADDRESS
    fi
    # -d 데몬, -r 기존 교체, -x XIM 서버 활성
    ibus-daemon -drx 2>/dev/null &
    sleep 2
    # hangul 엔진을 활성 엔진으로 설정 (best-effort)
    ibus engine hangul 2>/dev/null || true
    echo "[startapp] ibus-daemon 시작 (한글 입력기)"
fi

# Orange3 시작 루프 (언어 변경 재시작 포함)
while true; do

# ── 언어 변경 재시작 감지 ─────────────────────────────────────────────────────
# 아래 PYEOF 가 .lang_override 를 Orange.ini 에 적용한 뒤 삭제하므로 그 전에 확인한다.
# _NEW_LANG = 적용할 새 언어 이름(English/Korean/Slovenian) → 언어별 사전 빌드 캐시 선택용.
_LANG_CHANGED=""
_NEW_LANG=""
if [ -f /config/.lang_override ]; then
    _LANG_CHANGED=1
    _NEW_LANG=$(sed -n 's/^language=//p' /config/.lang_override | head -1)
fi

# ── Orange3 시작 전 설정 초기화 ──────────────────────────────────────────────
# Orange3는 QSettings.setDefaultFormat(IniFormat)을 사용하므로
# QSettings()와 QSettings(IniFormat) 모두 Orange.ini 에 읽고 씀
# Orange.ini 가 없을 때만 기본값(Korean) 생성, 이후에는 Orange3가 직접 관리
python3 << 'PYEOF'
import os

config_dir = '/config/xdg/config/biolab.si'
os.makedirs(config_dir, exist_ok=True)
ini_path = os.path.join(config_dir, 'Orange.ini')

import re

if not os.path.exists(ini_path):
    # 최초 실행: English 기본값으로 생성
    with open(ini_path, 'w') as f:
        f.write('[application]\nlanguage=English\nlast-used-language=Korean\n\n'
                '[startup]\nshow-welcome-screen=false\ncheck-updates=false\n\n'
                '[introjuction]\nshow-intro=false\n\n'
                '[notifications]\ncheck-notifications=false\n'
                'announcements=false\nblog=false\nnew-features=false\n')
else:
    # 기존 파일 유지 (language 건드리지 않음)
    with open(ini_path) as f:
        content = f.read()

    # QSettings 인코딩 버그로 깨진 Slovenian 값 자동 수정
    # 'Slovenščina' → QSettings가 \xc4\x8d 등으로 깨지게 저장
    # Slovenian.json 식별자를 'Slovenian'으로 변경했으므로 통일
    if re.search(r'=Sloven(?!ian)', content):
        content = re.sub(r'=Sloven\S*', '=Slovenian', content)
        with open(ini_path, 'w') as f:
            f.write(content)

    # last-used-language 가 없으면 현재 language 와 다른 값으로 설정
    # → language_changed()=True 가 되어 캐시 없이 새로 탐색하도록 강제
    if 'last-used-language' not in content:
        m = re.search(r'language\s*=\s*(\S+)', content)
        cur_lang = m.group(1) if m else 'Korean'
        # 현재 언어와 다른 값으로 설정 (Korean↔English)
        other = 'English' if cur_lang == 'Korean' else 'Korean'
        content = re.sub(
            r'(\[application\][^\[]*)',
            lambda mm: mm.group(1).rstrip() + f'\nlast-used-language={other}\n',
            content, flags=re.DOTALL
        )
        with open(ini_path, 'w') as f:
            f.write(content)

    # 팝업 설정 누락 시 추가
    with open(ini_path) as f:
        content = f.read()
    additions = ''
    if 'show-welcome-screen' not in content:
        additions += '\n[startup]\nshow-welcome-screen=false\n'
    if 'check-updates' not in content:
        # [startup] 섹션이 이미 있으면 그 안에 추가, 없으면 새 섹션
        if re.search(r'(?m)^\[startup\]', content):
            content = re.sub(
                r'(?ms)(^\[startup\][^\[]*)',
                lambda m: m.group(1).rstrip() + '\ncheck-updates=false\n',
                content, count=1
            )
            with open(ini_path, 'w') as f:
                f.write(content)
        else:
            additions += '\n[startup]\ncheck-updates=false\n'
    if 'show-intro' not in content:
        additions += '\n[introjuction]\nshow-intro=false\n'
    if 'check-notifications' not in content:
        additions += '\n[notifications]\ncheck-notifications=false\nannouncements=false\nblog=false\nnew-features=false\n'
    if additions:
        with open(ini_path, 'a') as f:
            f.write(additions)

# ── 언어 오버라이드 적용 (언어 변경 재시작 시 QSettings.sync() 이후 덮어씀) ──
lang_override = '/config/.lang_override'
if os.path.exists(lang_override):
    try:
        with open(lang_override) as f:
            lang_content = f.read().strip()
        if os.path.exists(ini_path):
            with open(ini_path) as f:
                content = f.read()
            for line in lang_content.split('\n'):
                line = line.strip()
                if '=' not in line:
                    continue
                k, v = line.split('=', 1)
                k, v = k.strip(), v.strip()
                if re.search(r'(?m)^' + re.escape(k) + r'\s*=', content):
                    content = re.sub(r'(?m)^' + re.escape(k) + r'\s*=.*', k + '=' + v, content)
                else:
                    content = re.sub(
                        r'(?s)(\[application\][^\[]*)',
                        lambda m: m.group(1).rstrip() + '\n' + k + '=' + v + '\n',
                        content
                    )
            with open(ini_path, 'w') as f:
                f.write(content)
        os.remove(lang_override)
        for sig in ['/config/.restart_language']:
            if os.path.exists(sig):
                os.remove(sig)
        print('[startapp] 언어 오버라이드 적용:', lang_content)
    except Exception as e:
        print('[startapp] 언어 오버라이드 오류:', e)

# ── 이력 삭제 신호 처리 (.clear_history) ─────────────────────────────────────
# Orange3 종료 후(QSettings.sync 완료) + 재시작 전에 실행되므로 타이밍 안전
clear_flag = '/config/.clear_history'
if os.path.exists(clear_flag):
    try:
        import glob as _glob
        # Orange.ini 에서 최근 워크플로우 목록([quickaccess]) 섹션 제거
        if os.path.exists(ini_path):
            with open(ini_path) as f:
                content = f.read()
            # [quickaccess] 섹션 전체 제거 (Orange3 최근 파일 목록)
            content = re.sub(r'\[quickaccess\][^\[]*', '', content, flags=re.DOTALL)
            # 연속 빈 줄 정리
            content = re.sub(r'\n{3,}', '\n\n', content)
            with open(ini_path, 'w') as f:
                f.write(content)
            print('[startapp] 최근 워크플로우 이력 삭제 완료')
        # xdg data/cache 내 OWS 파일 및 crash-recovery(.swp.p) 삭제
        for _pattern in [
            '/config/xdg/data/Orange/**/*.ows',
            '/config/xdg/cache/Orange/**/*.ows',
            '/config/xdg/data/Orange/**/*.swp.p',
            '/config/xdg/cache/Orange/**/*.swp.p',
        ]:
            for _fp in _glob.glob(_pattern, recursive=True):
                try:
                    os.remove(_fp)
                except OSError:
                    pass
        os.remove(clear_flag)
        print('[startapp] 이력 삭제 완료')
    except Exception as _ce:
        print(f'[startapp] 이력 삭제 오류: {_ce}')
        try:
            os.remove(clear_flag)
        except OSError:
            pass

PYEOF

# ── 레지스트리 캐시 처리 ──────────────────────────────────────────────────────
if [ -n "$_LANG_CHANGED" ]; then
    # 언어 변경 재시작: 새 언어의 사전 빌드 캐시를 복사해 재탐색(10s+, CPU 경합 시 수십초)을 회피.
    # 동시에 last-used-language 를 새 언어와 일치시켜 Orange3 가 캐시를 신뢰하게 한다
    # (language==last-used → language_changed()=False → 캐시 재사용, 재탐색 생략).
    _SRC="/opt/orange3-regcache-$_NEW_LANG"
    _INI="/config/xdg/config/biolab.si/Orange.ini"
    if [ -n "$_NEW_LANG" ] && [ -d "$_SRC" ]; then
        mkdir -p /config/xdg/cache
        rm -rf /config/xdg/cache/Orange
        cp -r "$_SRC/Orange" /config/xdg/cache/Orange 2>/dev/null || true
        if [ -f "$_INI" ] && grep -q '^last-used-language=' "$_INI"; then
            sed -i 's/^last-used-language=.*/last-used-language='"$_NEW_LANG"'/' "$_INI"
        fi
        echo "[startapp] 언어별 레지스트리 캐시 적용: $_NEW_LANG (재탐색 생략)"
    else
        # 사전 빌드 캐시 없는 언어 → 기존 동작(캐시 삭제 후 Orange3 가 재탐색)
        rm -f /config/xdg/cache/Orange/3.*/registry-cache.pck \
               /config/xdg/cache/Orange/3.*/widget-registry.pck 2>/dev/null || true
        echo "[startapp] 사전 빌드 캐시 없음: $_NEW_LANG → 재탐색"
    fi
elif [ -d /opt/orange3-regcache ] && [ ! -d /config/xdg/cache/Orange ]; then
    # 최초 기동: 사전 빌드된 캐시(영어) 복사 → Orange3 시작 시간 60-90s → 15-20s
    mkdir -p /config/xdg/cache
    cp -r /opt/orange3-regcache/Orange /config/xdg/cache/Orange 2>/dev/null || true
    echo "[startapp] 레지스트리 캐시 복사 완료"
fi

# ── 커스텀 런처로 Orange3 시작 ────────────────────────────────────────────────
# X11 루트 배경 재적용 (스플래시 화면 주변 검은 배경 방지 — X 서버 완전 기동 후)
DISPLAY=:0 xsetroot -solid white 2>/dev/null || true
DISPLAY=:0 xsetroot -cursor_name left_ptr 2>/dev/null || true
python3 /app/orange3_launcher.py &
APP_PID=$!

# ── Orange3 창 나타날 때까지 대기 + 최대화 (두 루프 통합, 최대 90초) ──────────
WIN=""
i=0
while [ $i -lt 90 ] && [ -z "$WIN" ]; do
    sleep 1
    i=$((i + 1))
    _PID=$(pgrep -f orange3_launcher.py | head -1)
    WIN=$([ -n "$_PID" ] && DISPLAY=:0 xdotool search --pid "$_PID" 2>/dev/null | head -1)
    [ -z "$WIN" ] && WIN=$(DISPLAY=:0 xdotool search --onlyvisible . 2>/dev/null | head -1)
done
if [ -n "$WIN" ]; then
    DISPLAY=:0 xdotool windowactivate --sync "$WIN" 2>/dev/null
    DISPLAY=:0 xdotool windowmove "$WIN" 0 0 2>/dev/null
    DISPLAY=:0 xdotool windowstate --add MAXIMIZED_VERT,MAXIMIZED_HORZ "$WIN" 2>/dev/null
fi

# ── 준비 신호 생성 ────────────────────────────────────────────────────────────
touch /config/.app_ready

# ── Orange3 종료 대기 ─────────────────────────────────────────────────────────
wait $APP_PID
EXIT_CODE=$?

rm -f /config/.app_ready

if [ "$EXIT_CODE" = "96" ]; then
    # 언어 변경 등으로 인한 계획된 재시작 — 루프 재실행
    echo "[startapp] Orange3 계획적 재시작 (코드 96), 재실행..."
    sleep 1
    continue
fi

# 정상 종료 또는 비정상 종료 → 루프 탈출 (s6 감독자가 재시작 처리)
break

done
