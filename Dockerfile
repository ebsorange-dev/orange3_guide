FROM jlesage/baseimage-gui:ubuntu-22.04-v4.6.4

ENV APP_NAME="Orange3 Canvas"

# ── 시스템 패키지 ─────────────────────────────────────────────────────────────
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    python3-pyqt5 \
    python3-pyqt5.qtwebengine \
    python3-pyqt5.qtsvg \
    libegl1-mesa \
    xvfb \
    dbus-x11 \
    libgl1-mesa-glx \
    fonts-nanum \
    libgeos-dev \
    build-essential \
    python3-dev \
    libxml2-dev \
    libxslt1-dev \
    xdotool \
    dmz-cursor-theme \
    && rm -rf /var/lib/apt/lists/*

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
ENV XCURSOR_THEME=DMZ-White
ENV XCURSOR_SIZE=24

# ── Python 패키지 (레이어 분리: 기본 → 애드온 순서로 캐시 최적화) ────────────
RUN apt-get update && apt-get install -y --no-install-recommends scrot x11-xserver-utils && rm -rf /var/lib/apt/lists/*

# ── 한글 입력기 (ibus-hangul) — 캔버스 직접 한글 입력 (2026-05-22) ─────────────
# Qt5 ibus 플러그인(libibusplatforminputcontextplugin.so)은 베이스 이미지에 이미 존재.
RUN apt-get update && apt-get install -y --no-install-recommends \
    ibus ibus-hangul dconf-cli \
    && rm -rf /var/lib/apt/lists/*

# Qt/GTK 입력 모듈을 ibus 로 지정 — Orange3(Qt5) 가 ibus 통해 한글 조합
ENV GTK_IM_MODULE=ibus
ENV QT_IM_MODULE=ibus
ENV XMODIFIERS=@im=ibus

# ibus 시스템 dconf 기본값 — hangul 엔진 사전 로드 (사용자 dconf 없이도 적용)
RUN mkdir -p /etc/dconf/db/local.d /etc/dconf/profile && \
    printf 'user-db:user\nsystem-db:local\n' > /etc/dconf/profile/user && \
    printf '%s\n' \
      '[org/freedesktop/ibus/general]' \
      "preload-engines=['hangul']" \
      'use-system-keyboard-layout=true' \
      '' \
      '[org/freedesktop/ibus/engine/hangul]' \
      "hangul-keys=['Hangul','Shift+space']" \
      > /etc/dconf/db/local.d/00-ibus && \
    dconf update

RUN pip3 install --no-cache-dir --upgrade pip requests urllib3 charset-normalizer
RUN pip3 install --no-cache-dir orange3 koreanize-matplotlib PyQtWebEngine
RUN pip3 install --no-cache-dir orange3-geo
RUN pip3 install --no-cache-dir orange3-imageanalytics
RUN pip3 install --no-cache-dir orange3-text
RUN pip3 install --no-cache-dir orange3-timeseries
# orange3-network: orange3-text 의 "Corpus to Network" 위젯이 의존
# 미설치 시 해당 위젯이 "Please install network add-on" 오류 표시
RUN pip3 install --no-cache-dir orange3-network

# ── 추가 Orange3 addons (Phase 5, 2026-05-24) ─────────────────────────────────
# 가벼운 것부터 → 무거운 것 순. 각각 별도 RUN 으로 분리해 캐시·실패 격리.
RUN pip3 install --no-cache-dir orange3-associate
RUN pip3 install --no-cache-dir orange3-educational
RUN pip3 install --no-cache-dir orange3-explain
RUN pip3 install --no-cache-dir orange3-fairness
RUN pip3 install --no-cache-dir orange3-survival-analysis
RUN pip3 install --no-cache-dir orange3-bioinformatics
# Spectroscopy: PyPI 패키지명은 orange-spectroscopy (Orange3- 접두 없음)
RUN pip3 install --no-cache-dir orange-spectroscopy
# Single Cell: PyPI 패키지명 Orange3-SingleCell (정규화: orange3-singlecell).
# 무거운 의존 (scanpy/anndata) → 마지막 배치. 일부 환경에서 빌드 실패할 수
# 있어 || true 로 격리 — 실패해도 다른 7개 addon 영향 없게.
RUN pip3 install --no-cache-dir Orange3-SingleCell || \
    echo "[warn] Orange3-SingleCell 설치 실패 — 메뉴에서 누락됨"

# ── 추가 Orange3 addons (2026-05-25) — 사용자 요청 4종 ─────────────────────────
# Textable: 텍스트 마이닝 위젯 세트 (Text addon 보조)
# Pumice: ML 모델 비교/벤치마크 위젯
# WorldHappiness: World Happiness 데이터셋 + 시각화 위젯
# Orange-SNOM: 분광 현미경(SNOM) 데이터 분석 (PyPI 패키지명 dash 없음)
# 각각 || true 로 격리 — 일부 실패해도 다른 addon 영향 없게.
RUN pip3 install --no-cache-dir Orange3-Textable || \
    echo "[warn] Orange3-Textable 설치 실패"
RUN pip3 install --no-cache-dir Orange3-Pumice || \
    echo "[warn] Orange3-Pumice 설치 실패"
RUN pip3 install --no-cache-dir Orange3-WorldHappiness || \
    echo "[warn] Orange3-WorldHappiness 설치 실패"
RUN pip3 install --no-cache-dir Orange-SNOM || \
    echo "[warn] Orange-SNOM 설치 실패"

# ── TensorFlow 설치 제거 (2026-05-29) — 사용자 요청. orange3-fairness 의
# Adversarial Debiasing 위젯이 비활성 됨. 필요 시 아래 블록 주석 해제 후 재빌드:
# RUN pip3 install --no-cache-dir 'tensorflow-cpu==2.18.0' || \
#     pip3 install --no-cache-dir tensorflow-cpu || \
#     echo "[warn] TensorFlow 설치 실패 — Adversarial Debiasing 위젯 비활성"

# ── Python 설치 경로 동적 탐지 후 환경변수로 설정 ─────────────────────────────
RUN PYVER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')") && \
    echo "PYTHON_SITE=/usr/local/lib/python${PYVER}/dist-packages" > /etc/orange3_env && \
    echo "Python site-packages: /usr/local/lib/python${PYVER}/dist-packages"

# ── 설치 경로를 쉘 변수로 참조하기 위한 헬퍼 ─────────────────────────────────
ARG PYVER=3.10
ENV SITE=/usr/local/lib/python${PYVER}/dist-packages

# ── 앱 파일 복사 ──────────────────────────────────────────────────────────────
COPY startapp.sh /startapp.sh
COPY orange3_launcher.py /app/orange3_launcher.py
COPY ko_gui_patch.py /app/ko_gui_patch.py

# ── orangecanvas 번역 ─────────────────────────────────────────────────────────
COPY Korean.json                              ${SITE}/orangecanvas/i18n/Korean.json
COPY orange3/orangecanvas_Slovenian.json      ${SITE}/orangecanvas/i18n/Slovenian.json

# ── orangewidget 번역 + 패치 ──────────────────────────────────────────────────
COPY orange3/orangewidget/widget.py           ${SITE}/orangewidget/widget.py
COPY orange3/orangewidget/Korean.json         ${SITE}/orangewidget/i18n/Korean.json

# ── Orange 코어 번역 + 패치 ───────────────────────────────────────────────────
COPY orange3/Orange/Slovenian.json            ${SITE}/Orange/i18n/Slovenian.json
COPY orange3/Orange/Korean.json               ${SITE}/Orange/i18n/Korean.json
COPY orange3/Orange/widgets/data/owfile.py    ${SITE}/Orange/widgets/data/owfile.py
COPY orange3/Orange/widgets/model/__init__.py ${SITE}/Orange/widgets/model/__init__.py
# Split 위젯 — PyPI Orange3 3.39.0에는 없음 (3.40.0+에 추가됨). 호스트 소스에서 백포트.
COPY orange3/Orange/widgets/data/owsplit.py             ${SITE}/Orange/widgets/data/owsplit.py
COPY orange3/Orange/widgets/data/icons/Split.svg        ${SITE}/Orange/widgets/data/icons/Split.svg

# ── 애드온 번역: Geo ──────────────────────────────────────────────────────────
COPY orange3/orangecontrib/geo/i18n/English.json   ${SITE}/orangecontrib/geo/i18n/English.json
COPY orange3/orangecontrib/geo/i18n/Slovenian.json ${SITE}/orangecontrib/geo/i18n/Slovenian.json
COPY orange3/orangecontrib/geo/i18n/Korean.json    ${SITE}/orangecontrib/geo/i18n/Korean.json
COPY orange3/orangecontrib/geo/widgets/__init__.py ${SITE}/orangecontrib/geo/widgets/__init__.py

# ── 애드온 번역: ImageAnalytics ───────────────────────────────────────────────
COPY orange3/orangecontrib/imageanalytics/i18n/Korean.json \
     ${SITE}/orangecontrib/imageanalytics/i18n/Korean.json

# ── 애드온 번역: Text ─────────────────────────────────────────────────────────
RUN mkdir -p ${SITE}/orangecontrib/text/i18n
COPY orange3/orangecontrib/text/i18n/English.json  ${SITE}/orangecontrib/text/i18n/English.json
COPY orange3/orangecontrib/text/i18n/Korean.json   ${SITE}/orangecontrib/text/i18n/Korean.json
COPY orange3/orangecontrib/text/widgets/__init__.py ${SITE}/orangecontrib/text/widgets/__init__.py

# ── 애드온 번역: TimeSeries ───────────────────────────────────────────────────
RUN mkdir -p ${SITE}/orangecontrib/timeseries/i18n
COPY orange3/orangecontrib/timeseries/i18n/English.json  ${SITE}/orangecontrib/timeseries/i18n/English.json
COPY orange3/orangecontrib/timeseries/i18n/Korean.json   ${SITE}/orangecontrib/timeseries/i18n/Korean.json
COPY orange3/orangecontrib/timeseries/widgets/__init__.py ${SITE}/orangecontrib/timeseries/widgets/__init__.py

# ── 애드온 번역: Network ──────────────────────────────────────────────────────
COPY orange3/orangecontrib/network/i18n/Korean.json   ${SITE}/orangecontrib/network/i18n/Korean.json

# CRLF 방어: 빌드 컨텍스트에 CRLF 가 섞여도(Windows 클론·ZIP 등) 컨테이너 실행 보장.
# .gitattributes 로 LF 강제하지만 belt-and-suspenders 로 \r 제거 후 실행권한 부여.
RUN sed -i 's/\r$//' /startapp.sh && chmod +x /startapp.sh

# ── noVNC 컨트롤 바(좌측 하단 아이콘) 제거 ──────────────────────────────────
RUN printf '%s\n' \
    '#noVNC_control_bar_anchor { display: none !important; }' \
    'body, html, #app, #noVNC_screen, #noVNC_container, #noVNC_canvas,' \
    '#noVNC_fallback_error, #noVNC_status, #noVNC_transition,' \
    '.noVNC_vcenter, .noVNC_status_bar, #noVNC_notification,' \
    '#noVNC_loading, .noVNC_loading { background: #ffffff !important; color: #222 !important; }' \
    '#noVNC_status { display: none !important; }' \
    '#noVNC_transition { opacity: 0 !important; pointer-events: none !important; }' \
    '#noVNC_screen, #noVNC_screen *, #noVNC_canvas, #noVNC_container canvas { cursor: default !important; }' \
    >> /opt/noVNC/app/styles/base.css


# ── shap numpy 2.x 호환 패치 (Orange3-Explain 위젯 복구) ──────────────────────
# shap 0.42.1(orange3-explain 0.6.10 이 shap==0.42.1 로 핀)이 numpy 2.0 에서 제거된
# np.obj2sctype 를 _colorconv.py 에서 사용 → explain 위젯(Explain Model/Prediction/
# Predictions) import 실패로 레지스트리에서 누락됐었다. shap 버전 유지(핀 충족)하고
# 해당 호출만 numpy2 호환(np.dtype().type)으로 치환. 검증: discovery 위젯 270→273 복구.
RUN sed -i 's/np\.obj2sctype(\([^)]*\))/np.dtype(\1).type/g' \
    /usr/local/lib/python3.10/dist-packages/shap/plots/colors/_colorconv.py

# ── Orange3 위젯 레지스트리 캐시 언어별 사전 생성 (English/Korean/Slovenian) ──
# 캐시에는 위젯명·카테고리 번역이 박혀 언어별로 다르다(실측 확인). 언어 변경 시
# startapp.sh 가 해당 언어 캐시를 복사 → Orange3 재탐색(10s+, CPU 경합 시 수십초) 생략.
# 각 언어는 반드시 별도 python3 프로세스로 — 한 프로세스 내 재import 시 번역 미반영.
# /opt/orange3-regcache(접미사 없음)는 워밍풀 최초 기동(영어)용으로 English 복제 유지.
RUN Xvfb :99 -screen 0 1280x800x24 -nolisten tcp & XVFB_PID=$!; \
    sleep 2; \
    for L in English Korean Slovenian; do \
      mkdir -p /tmp/regconf-$L/biolab.si; \
      printf '[application]\nlanguage=%s\nlast-used-language=%s\n' "$L" "$L" > /tmp/regconf-$L/biolab.si/Orange.ini; \
      XDG_CACHE_HOME=/opt/orange3-regcache-$L XDG_CONFIG_HOME=/tmp/regconf-$L DISPLAY=:99 HOME=/root \
      python3 -c "import sys, os, pickle, importlib.metadata; from PyQt5.QtWidgets import QApplication; from PyQt5.QtCore import QCoreApplication, QStandardPaths; app = QApplication(sys.argv); QCoreApplication.setApplicationName('Orange'); ver = importlib.metadata.version('Orange3'); QCoreApplication.setApplicationVersion(ver); cache_base = QStandardPaths.writableLocation(QStandardPaths.CacheLocation); cache_dir = os.path.join(cache_base, ver); os.makedirs(cache_dir, exist_ok=True); from orangecanvas.registry import WidgetRegistry; from orangewidget.workflow.discovery import WidgetDiscovery; r = WidgetRegistry(); d = WidgetDiscovery(r); d.run('orange.widgets'); cache_file = os.path.join(cache_dir, 'registry-cache.pck'); f = open(cache_file, 'wb'); pickle.dump(d.cached_descriptions, f); f.close(); print('[cache]', '$L', len(r.widgets()), 'cached to', cache_file)"; \
    done; \
    rm -rf /opt/orange3-regcache; cp -r /opt/orange3-regcache-English /opt/orange3-regcache; \
    rm -rf /tmp/regconf-English /tmp/regconf-Korean /tmp/regconf-Slovenian; \
    kill $XVFB_PID 2>/dev/null || true

# ── 오렌지 캔버스 메뉴바 + 단축 아이콘 툴바 제거 ────────────────────────────────
RUN sed -i \
    -e 's/dock2\.layout()\.addWidget(actions_toolbar)/pass  # hidden/' \
    -e 's/dock2\.layout()\.setContentsMargins(0, 0, 0, 0)/dock2.layout().setContentsMargins(16, 0, 16, 0)/' \
    -e 's/self\.setMenuBar(menu_bar)/self.setMenuBar(menu_bar); self.menuBar().setMaximumHeight(0); self.menuBar().hide()/' \
    -e 's/(_tr\.m\[50, "Select a widget to show its description\."\] + (".*$/_tr.m[50, "Select a widget to show its description."]/' \
    /usr/local/lib/python3.10/dist-packages/orangecanvas/application/canvasmain.py && \
    sed -i \
    -e 's/layout\.addWidget(self\.toolbar)/pass  # toolbar hidden/' \
    /usr/local/lib/python3.10/dist-packages/orangecanvas/application/canvastooldock.py

# ── noVNC 기본 배경색 흰색으로 변경 (리사이즈 시 검은 배경 제거) ──────────────
# rfb.js가 _screen div에 인라인 스타일로 어두운 배경을 설정하므로 소스에서 직접 수정
RUN sed -i "s/const DEFAULT_BACKGROUND = 'rgb(40, 40, 40)'/const DEFAULT_BACKGROUND = 'rgb(255, 255, 255)'/" \
    /opt/noVNC/core/rfb.js

# ── noVNC secure-context 거짓 경고 제거 ──────────────────────────────────────
# rfb.js는 isSecureContext가 false면(HTTP + 비-localhost IP 접속) 무조건
# "noVNC requires a secure context (TLS). Expect crashes!" 를 출력한다.
# secure context가 필요한 API(crypto.subtle)는 RSA-AES 인증(ra2.js)에서만 쓰는데
# 이 이미지의 VNC 서버는 -SecurityTypes=None 으로 실행되어 그 경로를 절대 타지 않음.
# → 거짓 경보이므로 조건을 무력화 (실제 동작에는 영향 없음).
RUN sed -i 's/if (!window\.isSecureContext) {/if (false) {/' \
    /opt/noVNC/core/rfb.js

# ── noVNC 리사이즈 즉시 반응: resize=remote 시 scaleViewport도 동시 활성화 ──────
# resize=remote 단독: VNC 서버 응답 전까지 캔버스가 구 크기로 남아 빈 공간 노출
# scaleViewport 병행: 브라우저 리사이즈 즉시 캔버스를 CSS 스케일로 뷰포트에 맞추고
#   VNC 응답 후 1:1 해상도로 전환 → 리사이즈 중 변동 최소화
RUN sed -i \
    "s/UI\.rfb\.scaleViewport = UI\.getSetting('resize') === 'scale';/UI.rfb.scaleViewport = UI.getSetting('resize') === 'scale' || UI.getSetting('resize') === 'remote';/" \
    /opt/noVNC/app/ui.js

# ── noVNC Delete/BackSpace 키 → parent postMessage (xdotool 경유) ────────────
# noVNC는 VNC 프로토콜로 키를 전달하지만 X11 창 포커스를 보장하지 않아
# Orange3가 Delete를 무시하는 문제가 발생함.
# capture 단계에서 Delete/BackSpace를 가로채 부모 wrapper 페이지로 postMessage →
# 부모가 /sendkey(xdotool)로 Orange3 창을 명시 포커스한 뒤 키를 전달함.
RUN for _f in $(find /opt/noVNC -name "*.html" 2>/dev/null); do \
        grep -q "x-del-intercept" "$_f" && continue; \
        sed -i \
            's|</head>|<script id="x-del-intercept">document.addEventListener("keydown",function(e){if(e.key==="Delete"||e.key==="Backspace"){e.stopImmediatePropagation();e.preventDefault();window.parent.postMessage({type:"vnc-del",key:e.key},"*");}},true);</script></head>|' \
            "$_f" 2>/dev/null || true; \
    done

# ── Openbox 흰색 배경 강제 설정 (재시작 후에도 유지) ─────────────────────────
RUN mkdir -p /etc/openbox && \
    printf 'xsetroot -solid white\n' >> /etc/openbox/autostart

ENV DISPLAY_WIDTH=1920
ENV DISPLAY_HEIGHT=1080

# ── Python 바이트코드 사전 컴파일 (⑤ 콜드스타트 단축, 2026-05-22) ──────────────
# Orange3 첫 기동은 numpy·scipy·sklearn·PyQt5·Orange 전체를 import 하며
# 이때 .py → .pyc 컴파일이 발생한다. 빌드 시점에 __pycache__ 를 미리 만들어 두면
# 각 컨테이너의 첫 실행에서 이 컴파일 패스를 건너뛴다 (콜드스타트 2~4s 단축).
# 이후 sed 로 수정되는 파일이 없도록 Dockerfile 최하단에 배치 — 모든 변경분 반영.
RUN python3 -m compileall -q -j 0 /usr/local/lib/python3.10/dist-packages 2>/dev/null || true
