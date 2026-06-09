#!/usr/bin/env python3
"""
Orange3 커스텀 런처

핵심 원리:
  - CanvasApplication 을 orange_main() 보다 먼저 생성
    → QApplication 이 main thread 에 존재하는 상태에서 Handler(QObject) 생성 가능
  - pyqtSignal(QueuedConnection) 으로 백그라운드 스레드 → Qt 메인 스레드 안전 호출
  - exec_() 패칭 없음 (이전 크래시 원인 제거)

재시작 처리:
  - Orange3 가 언어 변경 등으로 exit(96) 요청 시 startapp.sh 루프가 재시작을 담당
  - run_after_exit 는 비활성화하여 s6 감독자 + startapp.sh 루프와의 이중 실행 방지
"""

# NumPy 2.0 호환 shim — 반드시 다른 패키지 import 보다 먼저 실행되어야 함.
# 컨테이너는 numpy 2.2.x 인데 shap (orangecontrib.explain 의존성) 구버전이
# NumPy 2.0 에서 제거된 np.obj2sctype 를 사용 → AttributeError: _ARRAY_API
# not found 발생 (사용자에게 큰 에러 다이얼로그 노출). 새 함수로 대체.
# 참고: shap/plots/colors/_colorconv.py:819 가 호출 지점.
import warnings as _warnings
# ⚠ CPU 폭증 방지 (2026-05-31, py-spy 진단):
#   Orange 의 warnings 핸들러(_log_warning, Orange/util.py:57)는 매 경고마다
#   inspect.stack() (전 호출 프레임의 소스 파일을 읽음) 를 호출한다 — 극도로 비쌈.
#   shap(orangecontrib.explain 의존) import 시 numpy Deprecation 경고가 대량
#   발생 → inspect.stack() 가 수천 회 → 컨테이너당 코어 50~65% 소모 → 머신 포화.
#   해당 경고들을 사전 필터로 무시하여 비싼 핸들러 경로 자체를 차단한다.
_warnings.filterwarnings("ignore", category=DeprecationWarning)
_warnings.filterwarnings("ignore", category=FutureWarning)
try:
    import numpy as _np
    if not hasattr(_np, 'obj2sctype'):
        def _np_obj2sctype_compat(t, default=None):
            # 경고 억제(이중 안전장치): shap 이 대량 호출 → _log_warning CPU 폭증 방지
            try:
                with _warnings.catch_warnings():
                    _warnings.simplefilter("ignore")
                    return _np.dtype(t).type
            except Exception:
                return default
        _np.obj2sctype = _np_obj2sctype_compat
    # asfarray 도 NumPy 2.0 에서 제거됨 — 일부 구 addon 호환
    if not hasattr(_np, 'asfarray'):
        def _np_asfarray_compat(a, dtype=_np.float64):
            return _np.asarray(a, dtype=dtype)
        _np.asfarray = _np_asfarray_compat
    print("[launcher] numpy 2.x 호환 shim 적용 (obj2sctype, asfarray)", flush=True)
except Exception as _e:
    print(f"[launcher] numpy shim 적용 실패: {_e}", flush=True)

# Orange3 내장 run_after_exit 비활성화 (startapp.sh 루프가 재시작 담당)
try:
    import orangecanvas.utils.after_exit as _ae
    _ae.run_after_exit = lambda *args, **kwargs: None
except Exception:
    pass

# 한국어 GUI 레이블 패치 (text/timeseries 애드온 위젯용)
try:
    from ko_gui_patch import install_korean_patches
    install_korean_patches()
except Exception as _e:
    print(f"[launcher] ko_gui_patch 로드 실패: {_e}", flush=True)
import os
import re
import sys
import threading
import time

# Phase 3D-3 debug (2026-05-23): launcher 의 print 가 xpra start-child stdout 으로
# 가면 docker logs 까지 안 닿는 경우가 있다. /config/launcher_debug.log 에 tee →
# host sessions/{sid}/launcher_debug.log 로 즉시 확인 가능 (마운트 활용).
try:
    _log_f = open('/config/launcher_debug.log', 'a', encoding='utf-8', buffering=1)
    _orig_stdout = sys.stdout
    _orig_stderr = sys.stderr
    class _Tee:
        def __init__(self, primary):
            self.primary = primary
        def write(self, s):
            try: self.primary.write(s); self.primary.flush()
            except Exception: pass
            try: _log_f.write(s); _log_f.flush()
            except Exception: pass
        def flush(self):
            try: self.primary.flush()
            except Exception: pass
            try: _log_f.flush()
            except Exception: pass
        # 일부 라이브러리(PyQt5 logging, warnings 모듈 등)가 sys.stdout.isatty()
        # / fileno() / encoding / mode 등을 호출. _Tee 가 그 메서드를 누락하면
        # AttributeError → launcher startup crash → tee 위 일부 print 만 남고 정지.
        # primary stream 으로 위임해 file-like 인터페이스를 만족시킨다.
        def __getattr__(self, name):
            return getattr(self.primary, name)
    sys.stdout = _Tee(_orig_stdout)
    sys.stderr = _Tee(_orig_stderr)
    print(f"[launcher] tee → /config/launcher_debug.log 활성", flush=True)
except Exception as _te:
    print(f"[launcher] tee 설정 실패: {_te}", flush=True)

OPEN_SIGNAL     = "/config/.open_workflow"
SAVE_SIGNAL     = "/config/.save_workflow"
SAVE_DONE       = "/config/.save_done"
EXAMPLES_SIGNAL = "/config/.open_examples"
TOOL_SIGNAL     = "/config/.tool_activate"
RESTART_SIGNAL  = "/config/.restart_language"   # 언어 변경 재시작 신호
WF_INFO_QUERY   = "/config/.workflow_info_query"           # ⓘ 모달 열림: 현재 정보 조회 신호
WF_INFO_RESPONSE = "/config/.workflow_info_response.json"  # 응답: 현재 title/description JSON
WF_INFO_UPDATE  = "/config/.workflow_info_update.json"     # ⓘ 모달 확인: title/description 적용
# 단계 1: 위젯 카탈로그 dump 요청 / 응답
WIDGET_CATALOG_QUERY    = "/config/.widget_catalog_query"
WIDGET_CATALOG_RESPONSE = "/config/.widget_catalog.json"
# 단계 3B: 위젯 추가 신호 (frontend POST /add-widget → backend → 이 파일)
ADD_WIDGET_SIGNAL       = "/config/.add_widget.json"


def main():
    # ── 0. X11 루트 배경을 흰색으로 강제 (로딩 시 검은 배경 노출 방지) ──────────
    # startapp.sh의 xsetroot가 race condition으로 가끔 실패. 런처 시작 직후
    # 짧은 retry 루프로 확실하게 흰색 설정. Orange3 splash 표시 전에 적용 보장.
    import subprocess as _subp
    _env = dict(os.environ); _env['DISPLAY'] = ':0'
    for _i in range(8):
        try:
            r = _subp.run(['xsetroot', '-solid', 'white'], env=_env,
                          stdout=_subp.DEVNULL, stderr=_subp.DEVNULL, timeout=2)
            if r.returncode == 0:
                _subp.run(['xsetroot', '-cursor_name', 'left_ptr'], env=_env,
                          stdout=_subp.DEVNULL, stderr=_subp.DEVNULL, timeout=2)
                print("[launcher] X11 root 흰색 배경 설정 완료", flush=True)
                break
        except Exception:
            pass
        time.sleep(0.3)

    # 백그라운드에서 영구적으로 흰색 배경 유지 — 시작·실행·종료 어느 시점에도 검정 노출 방지
    # (Qt 초기화·X11 redraw·Orange3 종료 시 main window unmap 등 모든 단계 대비)
    def _enforce_white_bg():
        # 초기 10초: 0.5s 간격 (빠른 반응)
        for _ in range(20):
            try:
                _subp.run(['xsetroot', '-solid', 'white'], env=_env,
                          stdout=_subp.DEVNULL, stderr=_subp.DEVNULL, timeout=1)
            except Exception:
                pass
            time.sleep(0.5)
        # 이후 영구 루프: 2s 간격 (CPU 부담 최소화, 검정 깜빡임 발견 시 자동 복구)
        while True:
            try:
                _subp.run(['xsetroot', '-solid', 'white'], env=_env,
                          stdout=_subp.DEVNULL, stderr=_subp.DEVNULL, timeout=1)
            except Exception:
                pass
            time.sleep(2.0)
    threading.Thread(target=_enforce_white_bg, daemon=True).start()

    # ── 1. QApplication (CanvasApplication) 생성 ─────────────────────────────
    from PyQt5.QtWidgets import QApplication                     # type: ignore
    from PyQt5.QtCore import Qt as _Qt, QCoreApplication as _QCoreApplication  # type: ignore

    # PyQt5 제약: QtWebEngineWidgets 는 QCoreApplication 생성 전에 임포트돼야 함
    # AA_ShareOpenGLContexts 도 QGuiApplication 생성 전에 설정 필요
    # 이 두 조건이 빠지면 Word Cloud 등 WebView 위젯 로드 시
    # "Orange.widgets.gui has no attribute WebviewWidget" 오류 발생
    _QCoreApplication.setAttribute(_Qt.AA_ShareOpenGLContexts, True)
    try:
        from PyQt5 import QtWebEngineWidgets as _QtWebEngineWidgets  # noqa: F401
    except ImportError:
        pass

    from orangecanvas.application.application import CanvasApplication  # type: ignore

    # ── 시작 시 노출되는 Orange 캔버스 요소 비활성화 (2026-05-30) ──────────────
    #  · startup/show-welcome-screen → "Welcome to Orange" 환영 대화상자 (항상 off)
    #  · startup/check-updates       → "Orange Update Available" 업데이트 알림 (항상 off)
    #  · startup/show-splash-screen  → Orange3 native 로딩 splash (admin loading=False 시 off)
    # 중요: Orange 와 동일한 QSettings 위치를 명시 지정해야 실제 반영된다.
    #   Orange.canvas.config: OrganizationDomain="biolab.si", ApplicationName="Orange"
    #   → IniFormat/UserScope, org="biolab.si", app="Orange" (biolab.si/Orange.ini)
    #   (기존 org="Orange" 는 다른 파일에 기록돼 무효였음)
    try:
        from PyQt5.QtCore import QSettings as _QSettings
        _qs = _QSettings(_QSettings.IniFormat, _QSettings.UserScope, "biolab.si", "Orange")
        _qs.setValue("startup/show-welcome-screen", False)
        _qs.setValue("startup/check-updates", False)
        # 알림 피드 전체 차단 — 공지/블로그/새기능/설문·통계 권유 등 모든 알림.
        _qs.setValue("notifications/check-notifications", False)
        _qs.setValue("notifications/announcements", False)
        _qs.setValue("notifications/blog", False)
        _qs.setValue("notifications/new-features", False)
        # 비정상 종료 워크플로우 복원 프롬프트 차단 + 사용통계 전송 off.
        _qs.setValue("startup/load-crashed-workflows", False)
        _qs.setValue("reporting/send-statistics", False)
        # loading splash 노출 여부 — 라이브 파일(/config/.splash_loading) 우선, 없으면
        # env (2026-05-31). 라이브 파일은 session-manager 가 언어 변경/재시작 시 현재
        # admin 설정으로 갱신 → 컨테이너 재생성 없이 토글이 다음 부팅부터 반영된다.
        # show-splash-screen=False 는 splash UI 만 숨김(addon 로딩 등 내부 초기화는 유지).
        _splash_val = os.environ.get("ORANGE3_SPLASH_LOADING", "1")
        try:
            with open("/config/.splash_loading") as _spf:
                _spv = _spf.read().strip()
            if _spv in ("0", "1"):
                _splash_val = _spv
        except Exception:
            pass
        _splash_off = _splash_val == "0"
        if _splash_off:
            _qs.setValue("startup/show-splash-screen", False)
        _qs.sync()
        print(f"[launcher] 시작 메시지 전체 차단: welcome/update/notifications/"
              f"crashed-restore/statistics off, splash={'off' if _splash_off else 'keep'}",
              flush=True)
    except Exception as _se:
        print(f"[launcher] 시작 화면 설정 실패: {_se}", flush=True)

    if QApplication.instance() is None:
        _qapp = CanvasApplication(sys.argv)                      # noqa: F841  GC 방지

    # ── 1.3. QToolTip 스타일 — HTML 사이드바 #hwd-tip 과 동일 (2026-05-24 톤 정렬) ──
    # NodeItem 등 캔버스 hover 툴팁을 사이드바 카탈로그 툴팁과 같은 흰 배경 + 회색
    # 테두리 + 부드러운 그림자 로 통일. 기존 주황 베이지 톤(#FBE6D2/#F47B20) 제거.
    # 참고: session_manager/main.py 의 #hwd-tip CSS 와 색·라운드·폰트 동기화.
    try:
        _qapp_inst = QApplication.instance()
        if _qapp_inst is not None:
            # NodeItem 풍선 툴팁(이미지 2)와 같은 룩 (2026-05-26 정렬):
            # border-radius 10px (NodeItem 카드 라운드와 동일 — 18px → 10px 축소),
            # padding 10 14, font-size 12.5px, font-weight 500. 흰 배경 + 회색 테두리
            # 부드러운 그림자. (tail/arrow 는 QToolTip 한계로 스타일시트에서 미지원)
            _tip_qss = (
                "QToolTip {"
                " background-color: #ffffff;"
                " color: #1a1a1c;"
                " border: 1px solid #e5e7eb;"
                " border-radius: 10px;"
                " padding: 10px 14px;"
                " font-size: 12.5px;"
                " font-weight: 500;"
                " font-family: \"Segoe UI\", \"Malgun Gothic\", \"맑은 고딕\", sans-serif;"
                " opacity: 250;"
                "}"
            )
            _existing_qss = _qapp_inst.styleSheet() or ""
            if "QToolTip" not in _existing_qss:
                _qapp_inst.setStyleSheet(_existing_qss + "\n" + _tip_qss)
                print("[launcher] QToolTip 사이드바 톤 스타일 적용", flush=True)
            else:
                # 이전 다크/주황 톤이 이미 들어있을 수 있으므로 QToolTip 블록만 제거 후 재적용
                import re as _re
                _cleaned = _re.sub(r"QToolTip\s*\{[^}]*\}", "", _existing_qss)
                _qapp_inst.setStyleSheet(_cleaned + "\n" + _tip_qss)
                print("[launcher] QToolTip 스타일 재설정 (기존 블록 교체)", flush=True)
    except Exception as _qe:
        print(f"[launcher] QToolTip 스타일 적용 실패: {_qe}", flush=True)

    # ── 1.3a. QPushButton 카드 스타일 (2026-05-24) ─────────────────────────────
    # 위젯 다이얼로그 안 버튼(File 의 "...", Dataset, Reload, Reset, Apply 등)을
    # 흰 배경 + 둥근 모서리 + 옅은 그림자 형태의 "카드 버튼" 으로 통일.
    # Qt 의 QPushButton 은 box-shadow 미지원 — border + hover 색 변화로 흉내.
    # 사이드바 .info-note 톤 (#fff / #e5e7eb / 6px radius) 과 같은 디자인 언어.
    try:
        _qapp_inst = QApplication.instance()
        if _qapp_inst is not None:
            # 사이즈는 Qt 표준 버튼 (변경 전) 수준으로 작게 — 카드 룩만 유지.
            # padding 6→2, min-height 22→18, radius 6→4, font 12→11.5.
            _btn_qss = (
                "QPushButton {"
                " background-color: #ffffff;"
                " color: #1a1a1c;"
                " border: 1px solid #e5e7eb;"
                " border-radius: 4px;"
                " padding: 2px 10px;"
                " font-size: 11.5px;"
                " min-height: 18px;"
                "}"
                "QPushButton:hover {"
                " background-color: #f5f5f7;"
                " border-color: #d1d5db;"
                "}"
                "QPushButton:pressed {"
                " background-color: #ececef;"
                " border-color: #c5c8cd;"
                "}"
                "QPushButton:disabled {"
                " color: #9ca3af;"
                " background-color: #fafafb;"
                " border-color: #ececef;"
                "}"
                "QPushButton:default {"
                " border: 1px solid #c5c8cd;"
                " font-weight: 600;"
                "}"
                "QPushButton:checked {"
                " background-color: #eef2ff;"
                " border-color: #c7d2fe;"
                " color: #1e40af;"
                "}"
            )
            import re as _re2
            _existing_qss2 = _qapp_inst.styleSheet() or ""
            _cleaned2 = _re2.sub(r"QPushButton(:\w+)?\s*\{[^}]*\}", "", _existing_qss2)
            _qapp_inst.setStyleSheet(_cleaned2 + "\n" + _btn_qss)
            print("[launcher] QPushButton 카드 스타일 적용", flush=True)
    except Exception as _be:
        print(f"[launcher] QPushButton 스타일 적용 실패: {_be}", flush=True)

    # ── 1.3b. QComboBox 카드 스타일 (2026-05-25) ─────────────────────────────
    # File 위젯의 datasets 선택 드롭다운(이미지 1 빨간 영역) + 열린 드롭다운
    # 리스트(이미지 2 빨간 영역) 둘 다 카드 룩으로 통일. 사이즈는 변경 없음 —
    # 기존 Qt 기본 높이(min-height:18) + 작은 padding 유지.
    try:
        _qapp_inst = QApplication.instance()
        if _qapp_inst is not None:
            _combo_qss = (
                # closed 본체
                "QComboBox {"
                " background-color: #ffffff;"
                " color: #1a1a1c;"
                " border: 1px solid #e5e7eb;"
                " border-radius: 4px;"
                " padding: 1px 8px;"
                " min-height: 18px;"
                " font-size: 11.5px;"
                " selection-background-color: #eef2ff;"
                " selection-color: #1e40af;"
                "}"
                "QComboBox:hover { border-color: #d1d5db; }"
                "QComboBox:focus { border-color: #93c5fd; }"
                "QComboBox:disabled {"
                " color: #9ca3af; background-color: #fafafb;"
                " border-color: #ececef;"
                "}"
                # 우측 화살표 영역 — 본체에서 분리된 카드 느낌
                "QComboBox::drop-down {"
                " subcontrol-origin: padding;"
                " subcontrol-position: top right;"
                " width: 18px;"
                " border-left: 1px solid #ececef;"
                " border-top-right-radius: 4px;"
                " border-bottom-right-radius: 4px;"
                " background: transparent;"
                "}"
                "QComboBox::down-arrow { width: 8px; height: 8px; }"
                # 열린 드롭다운 popup (item view) — 카드 룩
                "QComboBox QAbstractItemView {"
                " background-color: #ffffff;"
                " color: #1a1a1c;"
                " border: 1px solid #e5e7eb;"
                " border-radius: 6px;"
                " padding: 4px 0;"
                " outline: 0;"
                " selection-background-color: #eef2ff;"
                " selection-color: #1e40af;"
                "}"
                "QComboBox QAbstractItemView::item {"
                " padding: 4px 10px;"
                " min-height: 20px;"
                " border: none;"
                "}"
                "QComboBox QAbstractItemView::item:hover {"
                " background-color: #f5f5f7;"
                " color: #1a1a1c;"
                "}"
                "QComboBox QAbstractItemView::item:selected {"
                " background-color: #eef2ff;"
                " color: #1e40af;"
                "}"
            )
            import re as _re3
            _existing_qss3 = _qapp_inst.styleSheet() or ""
            _cleaned3 = _re3.sub(
                r"QComboBox(\s+QAbstractItemView(::item(:\w+)?)?|::\w[\w-]*|:\w+)?\s*\{[^}]*\}",
                "", _existing_qss3,
            )
            _qapp_inst.setStyleSheet(_cleaned3 + "\n" + _combo_qss)
            print("[launcher] QComboBox 카드 스타일 적용", flush=True)
    except Exception as _ce:
        print(f"[launcher] QComboBox 스타일 적용 실패: {_ce}", flush=True)

    # ── 1.35. 알림(Notifications) 설정 4개 항목 모두 비활성화 ────────────────
    # Preferences → Notifications 탭의 체크박스 4개를 항상 꺼진 상태로 강제.
    #   notifications/check-notifications = Enable notifications
    #   notifications/announcements       = Announcements
    #   notifications/blog                = Blog posts
    #   notifications/new-features        = New features
    # (config.py 의 spec 기본값은 모두 True 이므로 부팅 시마다 명시적으로 덮어씀)
    try:
        from PyQt5.QtCore import QSettings as _QSettingsNotif      # type: ignore
        _qs_notif = _QSettingsNotif()
        for _nk in ("notifications/check-notifications",
                    "notifications/announcements",
                    "notifications/blog",
                    "notifications/new-features"):
            _qs_notif.setValue(_nk, False)
        # Welcome dialog 비활성화 — "Welcome to Orange" 다이얼로그 (New/Open/Recent
        # /Video Tutorials 표시) 부팅 시 자동 표시 차단.
        # Orange3 의 정확한 키를 모르니 가능한 후보 모두 False 강제.
        for _wk in ("welcomedialog/show-at-startup",
                    "startup/show-welcome-screen",
                    "mainwindow/show-welcome-screen",
                    "schemeinfo/show-at-new-scheme"):
            _qs_notif.setValue(_wk, False)
        # Update check 비활성화 — "Orange Update Available" 알림 차단.
        for _uk in ("startup/check-updates",
                    "updates/check",
                    "updates/check-updates",
                    "notifications/check-updates"):
            _qs_notif.setValue(_uk, False)
        _qs_notif.sync()
        print("[launcher] 알림/Welcome/Update 설정 비활성화 완료", flush=True)
    except Exception as _ne:
        print(f"[launcher] 알림 설정 비활성화 실패: {_ne}", flush=True)

    # ── 1.4. 베이직 워크플로우 썸네일 일괄 사전 생성 ─────────────────────────
    # orangecanvas.preview.scanner.scheme_svg_thumbnail() 으로 각 OWS 파일을
    # CanvasScene 에 로드해 SVG 로 렌더 → /config/.thumbs/<base>.svg 에 저장
    # Registry 가 위젯을 로드한 시점에 실행 (위젯 아이콘 포함)
    from PyQt5.QtCore import QTimer as _QTimerBoot                # type: ignore
    _thumb_state = {"timer": None, "attempts": 0, "done": False}

    def _optimize_svg(svg: str) -> str:
        """Qt SVG 최적화 (2026-05-29) — 평균 420KB → 90KB (~80% 축소).
        주된 redundancy:
          - <radialGradient> 중복 정의 (위젯 카테고리마다 같은 색상을 매번 재선언)
          - 공백 + 줄바꿈 (들여쓰기 ~2% 분량)
          - <desc>Generated with Qt</desc> 등 메타데이터
        제거 대상은 시각 출력 변화 없는 항목만 — 색상/좌표/path 데이터는 보존."""
        import re as _re
        try:
            # 1) <title>/<desc> 메타데이터 제거 (시각 영향 0)
            svg = _re.sub(r'<title[^>]*>.*?</title>\s*', '', svg, flags=_re.S)
            svg = _re.sub(r'<desc[^>]*>.*?</desc>\s*', '', svg, flags=_re.S)
            # 2) XML 주석 제거
            svg = _re.sub(r'<!--.*?-->\s*', '', svg, flags=_re.S)
            # 3) gradient 중복 제거: 같은 stop sequence 를 가진 gradient 들을 하나로 통합
            #    Qt SVG 는 위젯 N개에 대해 gradient N개를 정의하지만 stop 색상은 카테고리당
            #    한 가지 뿐 → 본문에서 id 만 다른 동일 정의를 처음 본 id 로 통일.
            grad_pattern = _re.compile(
                r'<(radialGradient|linearGradient)([^>]*?)\bid="([^"]+)"([^>]*)>(.*?)</\1>',
                flags=_re.S,
            )
            seen: dict[str, str] = {}     # body_hash → first_id
            replacements: dict[str, str] = {}  # dup_id → canonical_id
            def _canon(match):
                tag, pre, gid, post, body = match.group(1, 2, 3, 4, 5)
                # body + 속성으로 hash 키 생성 (공백 제거)
                key = (tag + pre + post + body).replace(' ', '').replace('\n', '')
                if key in seen:
                    replacements[gid] = seen[key]
                    return ''  # 중복 — 본문에서 삭제
                seen[key] = gid
                return match.group(0)
            svg = grad_pattern.sub(_canon, svg)
            # url(#dup_id) → url(#canonical_id) 치환
            for dup, canon in replacements.items():
                svg = svg.replace(f'url(#{dup})', f'url(#{canon})')
                svg = svg.replace(f'"{dup}"', f'"{canon}"')
            # 4) 공백/들여쓰기 압축 (path d 내부는 건드리지 않음)
            #    줄 시작 공백 + 빈 줄 제거
            svg = _re.sub(r'\n[\t ]+', '\n', svg)
            svg = _re.sub(r'\n+', '\n', svg)
            return svg
        except Exception as _ex:
            print(f"[launcher] SVG 최적화 실패 (원본 유지): {_ex}", flush=True)
            return svg

    def _generate_workflow_thumbs_now():
        """모든 OWS 파일에 대해 썸네일 SVG 생성 (재생성, 위젯 아이콘 포함).
        2026-05-29: 공유 디렉토리 /shared_thumbs 가 존재하면 우선 사용 (모든 세션 공유) +
                   SVG 사이즈 최적화 (gradient dedup + 공백 압축)."""
        try:
            from orangecanvas.preview.scanner import scheme_svg_thumbnail  # type: ignore
            # 공유 디렉토리 우선 — 모든 세션이 같은 SVG 를 read-only 공유 (디스크 100× 절감)
            # docker-compose 에서 ./thumbs_shared:/shared_thumbs:rw 마운트되어 있어야 함.
            shared_dir = '/shared_thumbs'
            output_dir = shared_dir if os.path.isdir(shared_dir) else '/config/.thumbs'
            os.makedirs(output_dir, exist_ok=True)
            using_shared = (output_dir == shared_dir)
            roots = [
                '/usr/local/lib/python3.10/dist-packages/Orange/canvas/workflows',
                '/usr/local/lib/python3.10/dist-packages/orangecontrib',
                '/upload_ows',  # 사용자 업로드 .ows (초등/중등/교재 BOOK)
            ]
            paths = []
            for root_dir in roots:
                if not os.path.isdir(root_dir):
                    continue
                for r, _d, files in os.walk(root_dir):
                    if 'test' in r.lower():
                        continue
                    for f in files:
                        if f.endswith('.ows'):
                            paths.append(os.path.join(r, f))
            ok_count = 0
            skip_count = 0
            for p in paths:
                try:
                    base = os.path.basename(p)[:-4]
                    out_f = os.path.join(output_dir, base + '.svg')
                    # 공유 디렉토리 사용 시 이미 있으면 skip (다른 컨테이너가 만들었음)
                    if using_shared and os.path.isfile(out_f) and os.path.getsize(out_f) > 0:
                        skip_count += 1
                        ok_count += 1
                        continue
                    svg = scheme_svg_thumbnail(p)
                    if svg:
                        svg_optimized = _optimize_svg(svg)
                        with open(out_f, 'w', encoding='utf-8') as fp:
                            fp.write(svg_optimized)
                        ok_count += 1
                except Exception as _ex:
                    print(f"[launcher] thumb 실패 {os.path.basename(p)}: {_ex}", flush=True)
            mode = "shared" if using_shared else "per-session"
            print(f"[launcher] thumbnail 재생성 완료 ({ok_count}/{len(paths)} 파일, "
                  f"mode={mode}, skipped={skip_count})", flush=True)
        except Exception as _ex:
            print(f"[launcher] thumbnail 일괄 생성 실패: {_ex}", flush=True)

    def _try_generate_thumbs():
        """Registry 가 위젯을 충분히 로드했는지 확인 후 썸네일 생성."""
        if _thumb_state["done"]:
            return
        _thumb_state["attempts"] += 1
        try:
            from orangecanvas.registry import global_registry  # type: ignore
            reg = global_registry()
            widgets = list(reg.widgets())
            n = len(widgets)
            if n >= 100 or _thumb_state["attempts"] >= 30:
                # 위젯 100개 이상 로드 또는 60초 경과 → 생성 시작
                print(f"[launcher] thumbnail 생성 시작 (위젯 {n}개 로드, 시도 {_thumb_state['attempts']})", flush=True)
                _generate_workflow_thumbs_now()
                _thumb_state["done"] = True
                if _thumb_state["timer"]:
                    _thumb_state["timer"].stop()
        except Exception as _ex:
            if _thumb_state["attempts"] >= 30:
                print(f"[launcher] thumbnail registry 확인 실패, 강행: {_ex}", flush=True)
                _generate_workflow_thumbs_now()
                _thumb_state["done"] = True
                if _thumb_state["timer"]:
                    _thumb_state["timer"].stop()

    _thumb_state["timer"] = _QTimerBoot()
    _thumb_state["timer"].timeout.connect(_try_generate_thumbs)
    _thumb_state["timer"].start(2000)  # 2초마다 registry 확인

    # ── 1.4. message() 함수 대체 — 카드 chrome 다이얼로그 ──────────────────────
    #  wiget_card_26_work.md 의 카드 chrome 을 경고 다이얼로그에도 적용.
    #
    #  QMessageBox 자체 패치는 한글 모드에서 모두 실패:
    #  - __init__ : sip C-slot, Python 패치 불가
    #  - showEvent: hide/recreate 사이클 → 크래시
    #  - PolishRequest: 다이얼로그가 invisible 됨
    #
    #  해결: orangecanvas.gui.utils.message() 함수를 monkey-patch 하여
    #  QMessageBox 대신 우리가 만든 _CardMessageDialog (QDialog 서브클래스) 사용.
    #  서브클래스 생성자에서 FramelessWindowHint 적용 → 안전하게 chrome 적용 가능.
    try:
        from AnyQt.QtWidgets import (
            QDialog, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
            QFrame, QSizePolicy, QApplication, QStyle, QMessageBox,
        )
        from AnyQt.QtCore import Qt as _Qt, QSize as _QSize
        from AnyQt.QtGui import QPalette
        import orangecanvas.gui.utils as _ocu

        class _CardMessageDialog(QDialog):
            """분석데이터셋 카탈로그 톤 의 모달 메시지 다이얼로그.
            디자인 참조: orange3_analysis_datasets.html (4분할 그리드 로고 + 흰 헤더 + 청색 액센트)."""

            def __init__(self, icon, title, text, informative_text=None,
                         details=None, buttons=QMessageBox.Ok,
                         default_button=None, parent=None):
                super().__init__(parent)
                self._result_button = QMessageBox.Cancel
                self._drag_pos = None
                # ✅ 생성자에서 즉시 frameless + 모달 적용
                self.setWindowFlags(_Qt.Dialog | _Qt.FramelessWindowHint)
                self.setWindowModality(_Qt.ApplicationModal)
                # 외곽 윈도우는 투명 — 안쪽 카드 QFrame 만 보임 (그림자 효과 위해)
                self.setAttribute(_Qt.WA_TranslucentBackground, True)
                self.setWindowTitle(title or "Orange")

                # 외곽 layout (그림자 + 카드 안쪽 패딩 확보)
                outer = QVBoxLayout(self)
                outer.setContentsMargins(12, 12, 12, 12)  # 그림자 영역
                outer.setSpacing(0)

                # ── 안쪽 카드 컨테이너 (회색 테두리 + 그림자) ──
                card = QFrame(self)
                card.setObjectName("_DlgCard")
                card.setStyleSheet(
                    "#_DlgCard{background:#ffffff;"
                    "border:1px solid #9ca3af;border-radius:10px;}"
                )
                # 부드러운 drop shadow
                try:
                    from AnyQt.QtWidgets import QGraphicsDropShadowEffect
                    from AnyQt.QtGui import QColor
                    shadow = QGraphicsDropShadowEffect(self)
                    shadow.setBlurRadius(18)
                    shadow.setOffset(0, 2)
                    shadow.setColor(QColor(0, 0, 0, 70))
                    card.setGraphicsEffect(shadow)
                except Exception:
                    pass
                outer.addWidget(card)

                root = QVBoxLayout(card)
                root.setContentsMargins(0, 0, 0, 0)
                root.setSpacing(0)

                # ── 헤더 (분석데이터셋 카탈로그 스타일) ──
                hdr = QFrame(self)
                hdr.setObjectName("_DlgHdr")
                hdr.setStyleSheet(
                    "#_DlgHdr{background:#ffffff;"
                    "border-top-left-radius:10px;border-top-right-radius:10px;"
                    "border-bottom:1px solid #e5e7eb;}"
                )
                hl = QHBoxLayout(hdr)
                hl.setContentsMargins(20, 16, 16, 14)
                hl.setSpacing(12)

                # 4분할 그리드 로고 (orange3_analysis_datasets.html 참조)
                logo_box = QFrame()
                logo_box.setFixedSize(22, 22)
                logo_box.setStyleSheet("background:transparent;")
                from AnyQt.QtWidgets import QGridLayout
                lg_lay = QGridLayout(logo_box)
                lg_lay.setContentsMargins(0, 0, 0, 0)
                lg_lay.setSpacing(3)
                for r in range(2):
                    for c in range(2):
                        sq = QFrame()
                        sq.setStyleSheet("background:#1f2937;border-radius:3px;")
                        lg_lay.addWidget(sq, r, c)

                # 타이틀 + 부제 (세로 정렬)
                title_box = QVBoxLayout()
                title_box.setContentsMargins(0, 0, 0, 0)
                title_box.setSpacing(2)
                title_lbl = QLabel(title or "Orange")
                title_lbl.setStyleSheet(
                    "color:#111827;font-size:16px;font-weight:700;")
                title_box.addWidget(title_lbl)
                if informative_text:
                    info_lbl = QLabel(informative_text)
                    info_lbl.setWordWrap(True)
                    info_lbl.setStyleSheet(
                        "color:#6b7280;font-size:12.5px;line-height:1.4;")
                    title_box.addWidget(info_lbl)
                title_box.addStretch(1)

                # 닫기 버튼 (둥근 사각형 SVG X — 분석데이터셋 카탈로그 스타일)
                close = QPushButton()
                close.setFixedSize(34, 34)
                close.setCursor(_Qt.PointingHandCursor)
                close.setStyleSheet(
                    "QPushButton{background:#ffffff;color:#6b7280;"
                    "border:1px solid #e5e7eb;border-radius:8px;"
                    "padding:0;font-size:18px;font-weight:300;}"
                    "QPushButton:hover{background:#f9fafb;border-color:#d1d5db;color:#111827;}"
                )
                close.setText("✕")
                close.clicked.connect(self.reject)

                hl.addWidget(logo_box, 0, _Qt.AlignTop)
                hl.addLayout(title_box, 1)
                hl.addWidget(close, 0, _Qt.AlignTop)
                hdr.installEventFilter(self)
                self._hdr = hdr
                root.addWidget(hdr)

                # ── 본문 영역 ──
                body = QFrame(self)
                body.setStyleSheet("background:#ffffff;")
                bl = QVBoxLayout(body)
                bl.setContentsMargins(20, 16, 20, 12)
                bl.setSpacing(10)

                # 점(아이콘 색) + 메인 텍스트 박스 (분석데이터셋 카탈로그의 desc-box 스타일)
                _dot_color = {
                    QMessageBox.Warning:  "#f59e0b",
                    QMessageBox.Critical: "#ef4444",
                    QMessageBox.Information: "#3b82f6",
                    QMessageBox.Question: "#3b82f6",
                }.get(icon, "#9ca3af")
                msg_box = QFrame()
                msg_box.setStyleSheet(
                    f"QFrame{{background:#f9fafb;"
                    f"border-left:3px solid {_dot_color};"
                    f"border-radius:4px;padding:10px 14px;}}"
                )
                msg_lay = QVBoxLayout(msg_box)
                msg_lay.setContentsMargins(0, 0, 0, 0)
                msg_lbl = QLabel(text or "")
                msg_lbl.setWordWrap(True)
                msg_lbl.setStyleSheet(
                    "color:#374151;font-size:13px;line-height:1.5;background:transparent;")
                msg_lay.addWidget(msg_lbl)
                bl.addWidget(msg_box)

                # details (펼침/접힘 토글)
                self._details_widget = None
                self._details_btn = None
                if details:
                    btn_row = QHBoxLayout()
                    self._details_btn = QPushButton("▶  Show Details")
                    self._details_btn.setStyleSheet(
                        "QPushButton{background:transparent;border:none;"
                        "color:#3b82f6;font-size:12.5px;font-weight:500;"
                        "padding:4px 0;text-align:left;}"
                        "QPushButton:hover{color:#1d4ed8;}"
                    )
                    self._details_btn.setCursor(_Qt.PointingHandCursor)
                    self._details_btn.clicked.connect(self._toggle_details)
                    btn_row.addWidget(self._details_btn)
                    btn_row.addStretch(1)
                    bl.addLayout(btn_row)
                    self._details_widget = QTextEdit()
                    self._details_widget.setReadOnly(True)
                    self._details_widget.setLineWrapMode(QTextEdit.WidgetWidth)
                    self._details_widget.setPlainText(details)
                    self._details_widget.setStyleSheet(
                        "QTextEdit{background:#f9fafb;border:1px solid #e5e7eb;"
                        "border-radius:6px;padding:10px;font-size:11.5px;"
                        "color:#374151;font-family:monospace;}"
                    )
                    self._details_widget.setMinimumHeight(200)
                    self._details_widget.hide()
                    bl.addWidget(self._details_widget)
                bl.addStretch(1)
                root.addWidget(body, 1)

                # ── 버튼 영역 ──
                btn_frame = QFrame(self)
                btn_frame.setStyleSheet(
                    "QFrame{background:#ffffff;"
                    "border-top:1px solid #e5e7eb;"
                    "border-bottom-left-radius:10px;border-bottom-right-radius:10px;}"
                )
                btn_layout = QHBoxLayout(btn_frame)
                btn_layout.setContentsMargins(20, 12, 20, 12)
                btn_layout.setSpacing(8)
                btn_layout.addStretch(1)

                _BTN_LABELS = {
                    QMessageBox.Ok:     "확인",
                    QMessageBox.Cancel: "취소",
                    QMessageBox.Yes:    "예",
                    QMessageBox.No:     "아니오",
                    QMessageBox.Abort:  "중단",
                    QMessageBox.Ignore: "무시",
                }
                buttons_int = int(buttons) if buttons else int(QMessageBox.Ok)
                for flag, label in _BTN_LABELS.items():
                    if buttons_int & int(flag):
                        b = QPushButton(label)
                        b.setMinimumWidth(80)
                        b.setMinimumHeight(34)
                        b.setCursor(_Qt.PointingHandCursor)
                        is_default = (flag == default_button) or (
                            default_button is None and flag == QMessageBox.Ok)
                        b.setDefault(is_default)
                        if is_default:
                            b.setStyleSheet(
                                "QPushButton{background:#3b82f6;color:#ffffff;"
                                "border:1px solid #3b82f6;border-radius:6px;"
                                "padding:7px 18px;font-size:13px;font-weight:500;}"
                                "QPushButton:hover{background:#2563eb;border-color:#2563eb;}"
                                "QPushButton:pressed{background:#1d4ed8;}"
                            )
                        else:
                            b.setStyleSheet(
                                "QPushButton{background:#ffffff;color:#374151;"
                                "border:1px solid #d1d5db;border-radius:6px;"
                                "padding:7px 18px;font-size:13px;font-weight:500;}"
                                "QPushButton:hover{background:#f9fafb;border-color:#9ca3af;}"
                            )
                        b.clicked.connect(
                            lambda _checked=False, fl=flag: self._on_button(fl)
                        )
                        btn_layout.addWidget(b)
                root.addWidget(btn_frame)

                # 다이얼로그 크기 (분석데이터셋 카탈로그와 비슷한 비율)
                self.resize(560, 240 if not details else 280)

            def _toggle_details(self):
                if not self._details_widget:
                    return
                if self._details_widget.isVisible():
                    self._details_widget.hide()
                    self._details_btn.setText("▶  Show Details")
                    self.resize(self.width(), 280)
                else:
                    self._details_widget.show()
                    self._details_btn.setText("▼  Hide Details")
                    self.resize(max(self.width(), 720), 540)

            def _on_button(self, flag):
                self._result_button = flag
                if flag in (QMessageBox.Cancel, QMessageBox.Abort, QMessageBox.No):
                    self.reject()
                else:
                    self.accept()

            def exec(self):
                # 부모의 top-level 윈도우 중앙에 배치 (backdrop 없음)
                parent = self.parent()
                if parent is not None:
                    try:
                        top = parent
                        while top.parent() is not None:
                            top = top.parent()
                        pg = top.geometry() if hasattr(top, "geometry") else None
                        if pg:
                            self.move(
                                pg.x() + (pg.width() - self.width()) // 2,
                                pg.y() + (pg.height() - self.height()) // 2,
                            )
                    except Exception:
                        pass
                super().exec()
                return self._result_button

            def exec_(self):
                return self.exec()

            # 헤더 드래그 → 다이얼로그 이동
            def eventFilter(self, obj, ev):
                if obj is self._hdr:
                    if ev.type() == ev.MouseButtonPress and ev.button() == _Qt.LeftButton:
                        self._drag_pos = ev.globalPos() - self.frameGeometry().topLeft()
                        return True
                    elif ev.type() == ev.MouseMove and self._drag_pos is not None and (ev.buttons() & _Qt.LeftButton):
                        self.move(ev.globalPos() - self._drag_pos)
                        return True
                    elif ev.type() == ev.MouseButtonRelease:
                        self._drag_pos = None
                        return True
                return super().eventFilter(obj, ev)

        # ── orangecanvas.gui.utils.message() 함수 교체 ──
        def _patched_message(icon, text, title=None, informative_text=None,
                             details=None, buttons=None, default_button=None,
                             exc_info=False, parent=None):
            import traceback as _tb
            if title is None:
                title = "Message"
            if not text:
                text = ""
            if buttons is None:
                buttons = QMessageBox.Ok
            if details is None and exc_info:
                details = _tb.format_exc(limit=20)
            dlg = _CardMessageDialog(
                icon=icon, title=title, text=text,
                informative_text=informative_text, details=details,
                buttons=buttons, default_button=default_button, parent=parent,
            )
            return dlg.exec_()

        _ocu.message = _patched_message
        print("[launcher] message() 카드 다이얼로그 교체 적용", flush=True)
    except Exception as _e:
        import traceback as _tb
        print(f"[launcher] message() 교체 실패: {_e}", flush=True)
        _tb.print_exc()

    # ── 1.4-d. DomainContextHandler.decode_setting 안전 처리 ─────────────────
    #  옛 .ows 워크플로우의 위젯 settings 형식이 현재 Orange3 와 달라서 발생:
    #    TypeError: 'DiscreteVariable' object is not subscriptable
    #  Orange/widgets/settings.py:180 (DomainContextHandler.decode_setting)
    #  에서 name_type 이 (name, type) 튜플이 아니라 Variable 인스턴스일 때 충돌.
    #  → 예외 잡고 Variable 인스턴스인 경우 그대로 사용.
    try:
        from Orange.widgets.settings import DomainContextHandler as _DCH
        from Orange.data import Variable as _Variable
        _orig_decode = _DCH.decode_setting

        def _safe_decode_setting(self, setting, value, domain=None, *args):
            try:
                return _orig_decode(self, setting, value, domain, *args)
            except TypeError as e:
                if "not subscriptable" not in str(e):
                    raise
                # name_type 이 Variable 인스턴스인 경우 → tuple 형태로 변환 후 재시도
                if not (isinstance(value, tuple) and len(value) == 2):
                    return value
                data, dtype = value
                if dtype == -3 and isinstance(data, (list, tuple)):
                    # Variable 객체를 (name, type_marker) 튜플로 변환
                    fixed = []
                    for nt in data:
                        if nt is None:
                            fixed.append(None)
                        elif isinstance(nt, _Variable):
                            # type 마커: Discrete=1, Continuous=2, String=3 (Orange 내부 코드)
                            type_code = getattr(nt, 'var_type', 1)
                            fixed.append((nt.name, type_code))
                        else:
                            fixed.append(nt)
                    try:
                        return _orig_decode(self, setting, (fixed, dtype), domain, *args)
                    except Exception:
                        # 재시도도 실패하면 Variable 인스턴스 그대로 반환
                        return [None if nt is None
                                else (nt if isinstance(nt, _Variable)
                                      else (domain[nt[0]] if domain else None))
                                for nt in data]
                return value

        _DCH.decode_setting = _safe_decode_setting
        print("[launcher] DomainContextHandler.decode_setting 안전 패치 적용", flush=True)
    except Exception as _e:
        import traceback as _tb
        print(f"[launcher] decode_setting 패치 실패: {_e}", flush=True)
        _tb.print_exc()

    # ── 1.4-c. SignalManager 삭제된 C++ 객체 에러 silent 처리 ────────────────
    #  워크플로우 로드/탭 전환 직후 백그라운드 작업이 완료되어 결과를
    #  send 하려고 할 때, WidgetsSignalManager Qt C++ 객체가 이미 삭제된 경우:
    #    RuntimeError: wrapped C/C++ object of type WidgetsSignalManager has been deleted
    #  이 경고 다이얼로그가 사용자에게 표시되어 UX 저해.
    #  → SignalManager.send / _schedule 을 try/except 로 감싸서 silent 처리.
    try:
        from orangecanvas.scheme.signalmanager import SignalManager as _SM
        _orig_send = _SM.send
        _orig_schedule = _SM._schedule

        def _safe_send(self, *args, **kwargs):
            try:
                return _orig_send(self, *args, **kwargs)
            except RuntimeError as e:
                if "has been deleted" in str(e):
                    return None  # silently drop
                raise

        def _safe_schedule(self, *args, **kwargs):
            try:
                return _orig_schedule(self, *args, **kwargs)
            except RuntimeError as e:
                if "has been deleted" in str(e):
                    return None  # silently drop
                raise

        _SM.send = _safe_send
        _SM._schedule = _safe_schedule
        print("[launcher] SignalManager 삭제객체 에러 silent 패치 적용", flush=True)
    except Exception as _e:
        print(f"[launcher] SignalManager 패치 실패: {_e}", flush=True)

    # ── 1.4-b. readwrite 채널 매칭 함수 패치 ──────────────────────────────────
    #  한글 모드에서 워크플로우 로드 시 source/sink_channel 매칭 실패 회피.
    #  원본: id 매칭(있으면) → name 매칭. 한글 모드는 name 이 한글로 번역되어
    #       영어 .ows 파일의 source_channel="Learner" 와 매칭 실패.
    #  패치: name 매칭 실패 시, source_channel 문자열을 channel.id 와도 매칭 시도.
    try:
        from orangecanvas.scheme import readwrite as _rw
        from orangecanvas.utils import findf as _findf

        _orig_find_source = _rw._find_source_channel
        _orig_find_sink = _rw._find_sink_channel

        def _patched_find_source_channel(node, link):
            try:
                return _orig_find_source(node, link)
            except ValueError:
                # name/id_id 매칭 실패 → source_channel 문자열을 id 에 매칭
                ch = _findf(node.output_channels(),
                            lambda c: c.id == link.source_channel)
                if ch is not None:
                    return ch
                raise

        def _patched_find_sink_channel(node, link):
            try:
                return _orig_find_sink(node, link)
            except ValueError:
                ch = _findf(node.input_channels(),
                            lambda c: c.id == link.sink_channel)
                if ch is not None:
                    return ch
                raise

        _rw._find_source_channel = _patched_find_source_channel
        _rw._find_sink_channel = _patched_find_sink_channel
        print("[launcher] readwrite 채널 매칭 fallback 패치 적용 (한글↔영어 호환)",
              flush=True)
    except Exception as _e:
        print(f"[launcher] readwrite 패치 실패: {_e}", flush=True)

    # ── 1.5. WidgetManager 패치 ────────────────────────────────────────────────
    #  ① 위젯 다이얼로그를 캔버스 노드 좌하단 +20px 위치에 배치
    #  ② 카드 chrome (이미지 1→2 변환, 이미지 3 하단 라인) — windowwk.md 준수
    #  ③ 헤더 클릭 → 툴바 → 색상 피커 (위젯 색상 변경 기능)

    # 색상 팔레트 (이미지 2 참조 — 흰색 + 파스텔 + 진회색)
    _CLEAN_PALETTE = [
        '#FFFFFF', '#F4C2C2', '#FFD4A8', '#E8DCC0', '#C8E6C9',
        '#B3D8E0', '#D5C5E5', '#F8C8D5', '#F5EFC0', '#5A5A5A',
    ]
    # 위젯 클래스별 색상 저장 (세션 내 유지)
    _CLEAN_COLOR_BY_CLASS = {}

    def _lighten_color(hex_color, white_amount=0.80):
        """hex 색상을 흰색과 mix. white_amount=1.0 → 순백, 0.0 → 원색."""
        h = hex_color.lstrip('#')
        r, g, b = int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
        r = int(r + (255 - r) * white_amount)
        g = int(g + (255 - g) * white_amount)
        b = int(b + (255 - b) * white_amount)
        return f'#{r:02X}{g:02X}{b:02X}'

    # WidgetsScheme.sync_node_properties 패치 — chrome_color 보존
    # Orange3 가 Save 시 widget.settingsHandler 의 declared Setting 만으로
    # node.properties 를 통째 대입(line 101: node.properties = settings)하여
    # 우리가 추가한 _chrome_color 키가 사라짐. sync 전후로 백업/복원.
    try:
        from orangewidget.workflow.widgetsscheme import WidgetsScheme as _WS  # type: ignore
        _orig_sync_props = _WS.sync_node_properties

        def _patched_sync_props(self):
            saved = {}
            for _node in self.nodes:
                if _node.properties and '_chrome_color' in _node.properties:
                    saved[id(_node)] = _node.properties['_chrome_color']
            _result = _orig_sync_props(self)
            for _node in self.nodes:
                _key = id(_node)
                if _key in saved:
                    if _node.properties is None:
                        _node.properties = {}
                    _node.properties['_chrome_color'] = saved[_key]
                    # _chrome_color 복원이 sync 변경 결과를 바꿀 수 있으므로
                    # changed=True 강제로 변환 (보수적 — 다음 dirty check 안전)
                    _result = True
            return _result

        _WS.sync_node_properties = _patched_sync_props
        print("[launcher] WidgetsScheme.sync_node_properties 패치 적용 (chrome_color 보존)", flush=True)
    except Exception as _e:
        print(f"[launcher] sync_node_properties 패치 실패: {_e}", flush=True)


    def _apply_clean_chrome(widget, node=None):
        """이미지 2·3 분위기로 카드 chrome 적용. windowwk.md 의 Qt.Dialog 보존 규칙 준수.
        node: SchemeNode — 워크플로우 .ows 에 색상 영구 저장용. None 이면 클래스별 세션 색상만 사용."""
        if getattr(widget, '_clean_chrome_applied', False):
            return
        try:
            from PyQt5.QtCore import Qt as _QtCH, QPoint as _QPCH               # type: ignore
            from PyQt5.QtWidgets import (QWidget as _QWCH, QHBoxLayout,         # type: ignore
                                          QLabel, QPushButton, QFrame)           # type: ignore

            cls_name = type(widget).__name__
            # 색상 우선순위: ① 노드별 저장된 색상 (.ows 에 영구 보존)
            #               ② 클래스별 세션 색상 (같은 종류 위젯 일관성)
            #               ③ 카테고리 색상 (사이드바 아이콘 배경색 — 신규 위젯 기본)
            #               ④ 기본값 #bdbdbd
            init_color = '#bdbdbd'
            if node is not None and getattr(node, 'properties', None):
                _saved = node.properties.get('_chrome_color')
                if _saved:
                    init_color = _saved
            if init_color == '#bdbdbd':
                init_color = _CLEAN_COLOR_BY_CLASS.get(cls_name, '#bdbdbd')
            # ③ 카테고리 색상 — widget.description.background 는 보통 None 이므로
            #    description.category(이름)로 widget registry 의 cat_desc.background 조회.
            #    (Data → '#FFD39F', Transform → '#FF9D5E' 등). 사이드바 아이콘과 동일 컬러.
            #    Registry 위치: CanvasMainWindow.widget_registry — topLevelWidgets 에서 검색.
            if init_color == '#bdbdbd':
                try:
                    _desc = getattr(node, 'description', None)
                    _bg = getattr(_desc, 'background', None) if _desc is not None else None
                    if not _bg and _desc is not None:
                        _cat_name = getattr(_desc, 'category', None)
                        if _cat_name:
                            from PyQt5.QtWidgets import QApplication as _QA
                            _app = _QA.instance()
                            _reg = None
                            for _tw in (_app.topLevelWidgets() if _app else []):
                                _reg = getattr(_tw, 'widget_registry', None)
                                if _reg is not None:
                                    break
                            if _reg is not None and hasattr(_reg, 'category'):
                                try:
                                    _cat_desc = _reg.category(_cat_name)
                                    if _cat_desc is not None:
                                        _bg = getattr(_cat_desc, 'background', None)
                                except Exception:
                                    pass
                    if _bg:
                        _cat_hex = str(_bg)
                        if _cat_hex.startswith('#') and len(_cat_hex) >= 7:
                            init_color = _cat_hex[:7].upper()
                            print(f"[launcher] chrome 카테고리 색 적용: {cls_name} → {init_color}", flush=True)
                except Exception as _e:
                    print(f"[launcher] chrome 카테고리 색 조회 실패: {_e}", flush=True)

            # 1) [windowwk.md 준수] OS 타이틀바 제거 — 반드시 windowFlags() 보존.
            #    widgets_override 의 Qt.Dialog 설정이 유지되어야 Openbox 의
            #    <application type="normal"><maximized>true</maximized></application>
            #    규칙을 회피하여 전체창 확대 방지.
            #    Qt.Window 로 덮어쓰면 NORMAL 타입이 되어 강제 전체창이 됨.
            widget.setWindowFlags(widget.windowFlags() | _QtCH.FramelessWindowHint)

            # 1c) Save Image 액션 비노출 — 위젯 하단 status bar 의 💾 아이콘 제거
            #     statusbar 가 lazy 생성이므로 즉시 + QTimer 지연 두 번 시도하여 확실히 hide
            try:
                from PyQt5.QtWidgets import QAction as _QAction                    # type: ignore
                from PyQt5.QtCore import QTimer as _QTimerSA                       # type: ignore

                def _hide_save_image():
                    try:
                        for _act in widget.findChildren(_QAction):
                            if _act.objectName() == 'action-save-image':
                                _act.setVisible(False)
                                _act.setEnabled(False)
                    except Exception:
                        pass
                # 즉시 1회 + 50ms 지연 1회 (statusbar lazy 생성 대응)
                _hide_save_image()
                _QTimerSA.singleShot(50, _hide_save_image)
                _QTimerSA.singleShot(300, _hide_save_image)
            except Exception:
                pass

            # 2) 다이얼로그 전체 둥근 모서리 + 외곽선 (이미지 2 카드 스타일)
            #    - dynamic property selector 로 scope 한정 → widgets_override QSS 충돌 회피
            #    - setMask 로 실제 shape 클립
            #    - base QSS 를 widget._clean_base_qss 에 저장 → set_color 시 base + 새 색상 재구성
            try:
                widget.setProperty('cleanRoot', True)
                widget._clean_base_qss = widget.styleSheet() or ''
                _scope_qss = (
                    'QDialog[cleanRoot="true"]{'
                    'background-color:#ffffff;'
                    'border:1px solid #d0d0d0;'
                    'border-radius:8px;}'
                )
                _selection_qss = (
                    'QAbstractItemView::item:selected,'
                    'QTreeView::item:selected,'
                    'QTableView::item:selected,'
                    'QListView::item:selected{'
                    'background-color:#3879d9;color:#ffffff;}'
                    'QAbstractItemView::item:hover{background-color:#e8f0fe;}'
                )
                widget.setStyleSheet(widget._clean_base_qss + _scope_qss + _selection_qss)
                widget.style().unpolish(widget)
                widget.style().polish(widget)
            except Exception:
                pass

            # 2b) 다이얼로그 둥근 모서리 클립 — QPainterPath + QRegion mask
            def _apply_round_mask():
                try:
                    from PyQt5.QtGui import QPainterPath, QRegion                  # type: ignore
                    from PyQt5.QtCore import QRectF                                # type: ignore
                    path = QPainterPath()
                    path.addRoundedRect(QRectF(0, 0, widget.width(), widget.height()), 8, 8)
                    region = QRegion(path.toFillPolygon().toPolygon())
                    widget.setMask(region)
                except Exception:
                    pass
            widget._apply_round_mask = _apply_round_mask

            # 3) 색상 피커 팝업 (이미지 2 — 색상 원 가로 배열, Qt.Popup)
            class _CleanColorPicker(QFrame):
                def __init__(self, owner_hdr, parent):
                    super().__init__(parent, _QtCH.Popup)
                    self._owner = owner_hdr
                    self.setStyleSheet(
                        'QFrame{background:#ffffff;border:1px solid #d0d0d0;'
                        'border-radius:20px;}'
                        'QPushButton{border:1px solid #d0d0d0;border-radius:13px;}'
                        'QPushButton:hover{border:2px solid #3879d9;}'
                    )
                    lay = QHBoxLayout(self)
                    lay.setContentsMargins(10, 8, 10, 8)
                    lay.setSpacing(6)
                    for c in _CLEAN_PALETTE:
                        b = QPushButton(self)
                        b.setFixedSize(26, 26)
                        b.setStyleSheet(b.styleSheet() +
                            f'QPushButton{{background-color:{c};}}')
                        b.clicked.connect(lambda _, col=c: self._pick(col))
                        lay.addWidget(b)
                def _pick(self, color):
                    self._owner.set_color(color)
                    self.close()

            # 4) 헤더 클릭 시 표시되는 툴바 (이미지 1 — 색상점/공유)
            #    위젯 외부 상단에 floating window 로 표시 (Qt.Tool + StaysOnTop)
            #    parent=dialog 로 설정 → 다이얼로그 destroy 시 자동 cleanup
            class _CleanToolbar(QFrame):
                def __init__(self, owner_hdr):
                    super().__init__(owner_hdr._target,
                                      _QtCH.Tool | _QtCH.FramelessWindowHint
                                      | _QtCH.WindowStaysOnTopHint)
                    self._owner = owner_hdr
                    self.setAttribute(_QtCH.WA_TranslucentBackground, False)
                    self.setObjectName('__cleanToolbar')
                    self.setAttribute(_QtCH.WA_StyledBackground, True)
                    self.setStyleSheet(
                        'QFrame#__cleanToolbar{background:#ffffff;'
                        'border:1px solid #d0d0d0;border-radius:10px;}'
                        'QPushButton{border:none;background:transparent;'
                        'color:#444;font-size:14px;border-radius:5px;'
                        'padding:0px;}'
                        'QPushButton:hover{background:#eaeaea;}'
                        'QLabel#__sep{color:#d0d0d0;background:transparent;}'
                    )
                    lay = QHBoxLayout(self)
                    lay.setContentsMargins(6, 4, 6, 4)
                    lay.setSpacing(2)

                    def _make_btn(text, tip, slot):
                        b = QPushButton(text, self)
                        b.setFixedSize(28, 28)
                        b.setCursor(_QtCH.PointingHandCursor)
                        b.setToolTip(tip)
                        if slot is not None:
                            b.clicked.connect(slot)
                        return b

                    def _make_sep():
                        s = QLabel('|', self)
                        s.setObjectName('__sep')
                        s.setFixedWidth(6)
                        return s

                    # 색상 점 + 드롭다운 (클릭 시 색상 팔레트)
                    self.color_btn = _make_btn('●', '색상 변경', None)
                    self.color_btn.clicked.connect(self._show_picker)
                    self._refresh_color_btn()
                    lay.addWidget(self.color_btn)
                    drop = QLabel('⌄', self)
                    drop.setStyleSheet('color:#888;font-size:11px;')
                    lay.addWidget(drop)
                    lay.addWidget(_make_sep())
                    # 색상 재지정 — 팔레트 첫 번째 색(흰색)으로 초기화
                    lay.addWidget(_make_btn('↪', '색상 초기화', self._reset_color))
                    self.hide()

                def _reset_color(self):
                    """팔레트 첫 번째 색(흰색 #FFFFFF)으로 색상 초기화."""
                    if _CLEAN_PALETTE:
                        self._owner.set_color(_CLEAN_PALETTE[0])

                def _refresh_color_btn(self):
                    cur = self._owner._dot_color
                    # 흰색 점은 보더로 식별
                    border_color = '#bdbdbd' if cur.upper() == '#FFFFFF' else 'transparent'
                    self.color_btn.setStyleSheet(
                        f'QPushButton{{color:{cur};font-size:18px;'
                        f'border:1px solid {border_color};border-radius:14px;'
                        'background:transparent;}'
                        'QPushButton:hover{background:#eaeaea;}'
                    )

                def _show_picker(self):
                    picker = _CleanColorPicker(self._owner, self._owner._target)
                    btn_pos = self.color_btn.mapToGlobal(_QPCH(0, 0))
                    # 색상 팔레트는 툴바 위쪽에 표시 (이미지 2 레이아웃)
                    picker.adjustSize()
                    pos_x = btn_pos.x() - picker.width() // 2 + self.color_btn.width() // 2
                    pos_y = btn_pos.y() - picker.height() - 6
                    picker.move(pos_x, pos_y)
                    picker.show()

                def toggle(self, anchor_widget):
                    if self.isVisible():
                        self.hide()
                        return
                    self.adjustSize()
                    # 위젯 외부 상단 — 왼쪽 정렬 (글로벌 좌표)
                    target = self._owner._target
                    target_pos = target.mapToGlobal(_QPCH(0, 0))
                    x = target_pos.x()  # 위젯 왼쪽 가장자리에 맞춤
                    y = target_pos.y() - self.height() - 8  # 위젯 위 8px 간격
                    self.move(max(0, x), max(0, y))
                    self.show()
                    self.raise_()

            # 5) 커스텀 헤더 — 이미지 2·3 스타일 (점 + 이름 + × + 하단 라인)
            class _CleanHdr(_QWCH):
                def __init__(self, parent):
                    super().__init__(parent)
                    self._target = parent
                    self._drag_offset = None
                    self._press_pos = None
                    self._is_dragging = False
                    self._dot_color = init_color
                    self._node = node  # SchemeNode — set_color 시 .ows 영구 저장용
                    self.setObjectName('__cleanHdr')
                    self.setFixedHeight(34)
                    self.setAttribute(_QtCH.WA_StyledBackground, True)

                    title_text = parent.windowTitle() or ''
                    if ' — ' in title_text:
                        title_text = title_text.split(' — ', 1)[0]

                    lay = QHBoxLayout(self)
                    lay.setContentsMargins(12, 0, 6, 0)
                    lay.setSpacing(8)
                    self.dot = QLabel('●')
                    self.dot.setObjectName('__cleanDot')
                    self.title_lbl = QLabel(title_text)
                    self.title_lbl.setObjectName('__cleanTitle')
                    btn = QPushButton('×')
                    btn.setObjectName('__cleanClose')
                    # 이미지 2 (분석 데이터셋 카탈로그) 닫기 버튼 스타일 — 흰 배경 +
                    # 회색 테두리 + 둥근 사각형. 24×24 → 26×26 으로 살짝 확대.
                    btn.setFixedSize(26, 26)
                    btn.setCursor(_QtCH.PointingHandCursor)
                    btn.clicked.connect(parent.close)
                    lay.addWidget(self.dot)
                    lay.addWidget(self.title_lbl)
                    lay.addStretch()
                    lay.addWidget(btn)
                    # 헤더 배경/색상 적용 (저장된 색상 또는 기본값)
                    self._refresh_hdr_bg()
                    # 하단 구분 라인
                    self._line = QFrame(self)
                    self._line.setObjectName('__cleanLine')
                    self._line.setStyleSheet(
                        'QFrame#__cleanLine{background-color:#d0d0d0;border:none;}')
                    self._line.setFixedHeight(1)
                    self._line.setGeometry(0, 33, max(200, parent.width()), 1)
                    self._line.show()
                    self._line.raise_()
                    # 툴바 (이미지 1) — 위젯 외부 상단에 floating 표시
                    self._toolbar = _CleanToolbar(self)
                    # 저장된 색상이 있으면 본문 배경도 자동 적용
                    if init_color and init_color != '#bdbdbd':
                        self._refresh_body_bg()

                def _refresh_hdr_bg(self):
                    """헤더 배경/텍스트/점 색상을 선택한 색상에 맞춰 일괄 갱신.
                    ComfyUI Cloud 스타일 — 헤더 전체 배경이 변경되어 변화가 명확히 보임.
                    Close 버튼은 이미지 2 (분석 데이터셋 카탈로그) 스타일 — 흰 배경 +
                    회색 테두리 + 둥근 사각형 (헤더 배경과 분리되어 카드처럼 보임)."""
                    color = self._dot_color
                    upper = color.upper()
                    is_default = upper == '#BDBDBD'   # 사용자 미선택 (기본값)
                    is_white = upper == '#FFFFFF'      # 팔레트의 흰색
                    is_dark = upper == '#5A5A5A'       # 팔레트의 진회색
                    # 기본값/흰색은 tint 없이 fafafa 유지, 그 외는 선택 색상 그대로
                    if is_default or is_white:
                        bg = '#fafafa'
                        text_color = '#222'
                        dot_color = '#bdbdbd'
                        # 카드형 close 버튼 — 흰 배경 + 얇은 회색 테두리 (2026-05-26 v2)
                        close_bg = '#ffffff'
                        close_border = '#f0f0f0'           # 더 옅음 (이전 #e5e7eb)
                        close_color = '#9ca3af'             # 더 옅은 회색 (× 글자 자체도 얇게 보임)
                        close_hover_bg = '#f8f8fa'
                        close_hover_border = '#e0e0e0'
                        close_hover_color = '#374151'
                    elif is_dark:
                        bg = color
                        text_color = '#ffffff'
                        dot_color = '#ffffff'
                        # 어두운 헤더 — 더 옅은 반투명 테두리
                        close_bg = 'rgba(255,255,255,0.10)'
                        close_border = 'rgba(255,255,255,0.18)'  # 더 옅음
                        close_color = '#e5e7eb'
                        close_hover_bg = 'rgba(255,255,255,0.18)'
                        close_hover_border = 'rgba(255,255,255,0.30)'
                        close_hover_color = '#ffffff'
                    else:
                        # 파스텔 배경 — 더 옅은 카드형 close
                        bg = color
                        text_color = '#222'
                        dot_color = '#222'
                        close_bg = '#ffffff'
                        close_border = 'rgba(0,0,0,0.08)'        # 더 옅음
                        close_color = '#6b7280'
                        close_hover_bg = '#f5f5f7'
                        close_hover_border = 'rgba(0,0,0,0.15)'
                        close_hover_color = '#000000'
                    self.setStyleSheet(
                        f'QWidget#__cleanHdr{{background-color:{bg};'
                        'border-top-left-radius:8px;border-top-right-radius:8px;}'
                        f'QLabel#__cleanTitle{{color:{text_color};font-size:13px;font-weight:500;}}'
                        f'QLabel#__cleanDot{{color:{dot_color};font-size:12px;}}'
                        f'QPushButton#__cleanClose{{'
                        f'background:{close_bg};border:1px solid {close_border};'
                        f'border-radius:7px;color:{close_color};'
                        f'font-size:14px;font-weight:400;padding:0px;}}'
                        f'QPushButton#__cleanClose:hover{{background:{close_hover_bg};'
                        f'border-color:{close_hover_border};color:{close_hover_color};}}'
                    )

                def set_color(self, color):
                    self._dot_color = color
                    _CLEAN_COLOR_BY_CLASS[type(self._target).__name__] = color
                    # 노드별 색상 영구 저장 — Save / Save a Copy 시 .ows 에 함께 직렬화
                    # SchemeNode.properties 는 .ows 의 <properties> 요소로 자동 직렬화됨.
                    # 위젯 자체 settings 와 같은 dict 이지만 '_chrome_color' 키는
                    # 위젯이 declare 한 Setting 이 아니므로 widget settings handler 가 무시 → 안전.
                    if self._node is not None:
                        try:
                            if getattr(self._node, 'properties', None) is None:
                                self._node.properties = {}
                            self._node.properties['_chrome_color'] = color
                        except Exception:
                            pass
                    self._refresh_hdr_bg()
                    self._refresh_body_bg()
                    if hasattr(self, '_toolbar') and self._toolbar:
                        self._toolbar._refresh_color_btn()

                def _refresh_body_bg(self):
                    """다이얼로그 본문 배경을 선택 색의 옅은 버전으로 변경.
                    QDialog[cleanRoot=true] selector 로 scope 한정."""
                    color = self._dot_color
                    upper = color.upper()
                    if upper in ('#BDBDBD', '#FFFFFF'):
                        body_bg = '#ffffff'
                    elif upper == '#5A5A5A':
                        body_bg = '#f5f5f5'
                    else:
                        # 파스텔: 80% 흰색 + 20% 색상 = 매우 옅은 tint
                        body_bg = _lighten_color(color, 0.80)
                    base = getattr(self._target, '_clean_base_qss', '') or ''
                    extra = (
                        f'QDialog[cleanRoot="true"]{{'
                        f'background-color:{body_bg};'
                        'border:1px solid #d0d0d0;border-radius:8px;}'
                        'QAbstractItemView::item:selected,'
                        'QTreeView::item:selected,'
                        'QTableView::item:selected,'
                        'QListView::item:selected{'
                        'background-color:#3879d9;color:#ffffff;}'
                        'QAbstractItemView::item:hover{background-color:#e8f0fe;}'
                    )
                    self._target.setStyleSheet(base + extra)
                    self._target.style().unpolish(self._target)
                    self._target.style().polish(self._target)

                def resizeEvent(self, ev):
                    super().resizeEvent(ev)
                    try:
                        self._line.setGeometry(0, self.height() - 1, self.width(), 1)
                        self._line.raise_()
                    except Exception:
                        pass

                def mousePressEvent(self, ev):
                    if ev.button() == _QtCH.LeftButton:
                        self._press_pos = ev.pos()
                        self._is_dragging = False
                        self._drag_offset = ev.globalPos() - \
                            self._target.frameGeometry().topLeft()
                        ev.accept()

                def mouseMoveEvent(self, ev):
                    if self._press_pos is not None:
                        if (ev.pos() - self._press_pos).manhattanLength() > 4:
                            self._is_dragging = True
                            self._target.move(ev.globalPos() - self._drag_offset)
                            ev.accept()

                def mouseReleaseEvent(self, ev):
                    if not self._is_dragging and self._press_pos is not None:
                        # 클릭(드래그 아님) → 툴바 토글
                        try:
                            self._toolbar.toggle(self)
                        except Exception:
                            pass
                    self._press_pos = None
                    self._drag_offset = None
                    self._is_dragging = False

            hdr = _CleanHdr(widget)
            hdr.setGeometry(0, 0, max(200, widget.width()), 34)
            hdr.show()
            hdr.raise_()
            widget._clean_hdr = hdr

            # 4) 위젯 layout top margin 늘려 헤더와 겹치지 않게
            try:
                lay = widget.layout()
                if lay is not None:
                    m = lay.contentsMargins()
                    lay.setContentsMargins(m.left(), m.top() + 34,
                                            m.right(), m.bottom())
            except Exception:
                pass

            # 5) 초기 mask 적용 (둥근 모서리 클립)
            _apply_round_mask()

            # 6) resize 시 헤더 폭 자동 갱신 + mask 재계산
            _orig_resize = widget.resizeEvent
            def _new_resize(ev):
                try:
                    hdr.setGeometry(0, 0, widget.width(), 34)
                    hdr.raise_()
                    _apply_round_mask()
                except Exception:
                    pass
                if callable(_orig_resize):
                    _orig_resize(ev)
            widget.resizeEvent = _new_resize

            # 7) 다이얼로그 close/hide 시 툴바도 같이 hide (2026-05-26 강화)
            # 인스턴스 메서드 재할당(widget.closeEvent = ...) 은 PyQt 에서 Qt
            # 이벤트 전달을 항상 인터셉트하지 못해 위젯 닫혀도 툴바가 남는 경우 발생.
            # eventFilter 로 Hide/Close 를 확실히 캐치 + 위젯 destroyed 신호로
            # 완전 cleanup (deleteLater).
            from AnyQt.QtCore import QObject as _QObjCH, QEvent as _QEvCH
            def _hide_toolbar():
                try:
                    tb = getattr(hdr, '_toolbar', None)
                    if tb is not None:
                        tb.hide()
                except Exception:
                    pass

            def _kill_toolbar():
                try:
                    tb = getattr(hdr, '_toolbar', None)
                    if tb is not None:
                        try: tb.hide()
                        except Exception: pass
                        try: tb.setParent(None)
                        except Exception: pass
                        try: tb.deleteLater()
                        except Exception: pass
                        try: hdr._toolbar = None
                        except Exception: pass
                except Exception:
                    pass

            class _ToolbarHider(_QObjCH):
                def eventFilter(self, obj, ev):
                    t = ev.type()
                    if t == _QEvCH.Hide or t == _QEvCH.Close:
                        _hide_toolbar()
                    elif t == _QEvCH.WindowDeactivate:
                        # 다른 창으로 포커스 이동 시도 hide (사용자가 다른 위젯 클릭)
                        _hide_toolbar()
                    return False

            _hider = _ToolbarHider(widget)
            widget.installEventFilter(_hider)
            widget._toolbar_hider = _hider  # GC 방지 강한 레퍼런스
            try:
                widget.destroyed.connect(lambda *_: _kill_toolbar())
            except Exception:
                pass

            widget._clean_chrome_applied = True
        except Exception as _ex:
            print(f"[launcher] clean chrome 적용 실패: {_ex}", flush=True)

    try:
        from orangecanvas.scheme.widgetmanager import WidgetManager  # type: ignore
        from orangecanvas.canvas.view import CanvasView              # type: ignore
        _orig_activate = WidgetManager.activate_widget_for_node

        def _patched_activate(self, node, widget):
            # 위젯 실행(열람/사용) 로깅 — 사용자가 위젯을 열어 사용 (이용 패턴: 추가 vs 실행)
            try:
                import json as _oj
                _od = getattr(node, "description", None)
                _owid = (getattr(_od, "id", None)
                         or getattr(node, "qualified_name", None) or "?")
                with open("/config/.usage_widgets.jsonl", "a", encoding="utf-8") as _of:
                    _of.write(_oj.dumps(
                        {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "widget": _owid, "ev": "open"}, ensure_ascii=False) + "\n")
            except Exception:
                pass
            try:
                app_inst = QApplication.instance()
                view = None
                if app_inst is not None:
                    for w in app_inst.topLevelWidgets():
                        view = w.findChild(CanvasView)
                        if view is not None:
                            break
                if view is not None:
                    scene = view.scene()
                    item = scene.item_for_node(node) if hasattr(scene, "item_for_node") else None
                    if item is not None:
                        # 노드 bounding rect 좌하단 (scene 좌표)
                        rect = item.boundingRect()
                        bl_scene = item.mapToScene(rect.bottomLeft())
                        # scene → view → global screen
                        bl_view = view.mapFromScene(bl_scene)
                        bl_global = view.mapToGlobal(bl_view)
                        # 위젯 다이얼로그 좌상단 = 노드 좌하단 + (0, 20)
                        widget.move(bl_global.x(), bl_global.y() + 20)
                # 카드 chrome 적용 (이미지 2·3 분위기, windowwk.md 준수)
                # node 전달 → 색상 .ows 영구 저장/복원 가능
                _apply_clean_chrome(widget, node)
            except Exception as _ex:
                print(f"[launcher] widget positioning 오류: {_ex}", flush=True)
            return _orig_activate(self, node, widget)

        WidgetManager.activate_widget_for_node = _patched_activate
        print("[launcher] WidgetManager.activate_widget_for_node 패치 적용 (노드 좌하단 +20px + 카드 chrome)", flush=True)
    except Exception as _e:
        print(f"[launcher] WidgetManager 패치 실패: {_e}", flush=True)

    # ── 1.6. 캔버스 scene 크기 제한 + 시작 viewport 위치 (1920 × 1080 Full HD) ────
    # 기본은 무제한으로 자동 확장 — 사용자가 위젯을 무제한 배치 가능.
    # 환경변수로 덮어쓰기 가능: CANVAS_WIDTH, CANVAS_HEIGHT
    # CANVAS_VIEWPORT_X (0~1, 가로 비율, 0.5=중앙), CANVAS_VIEWPORT_Y (0~1, 세로 비율, 0.0=상단, 1.0=하단)
    _CANVAS_W = int(os.environ.get('CANVAS_WIDTH', '1920'))
    _CANVAS_H = int(os.environ.get('CANVAS_HEIGHT', '1080'))
    _CANVAS_VP_X = float(os.environ.get('CANVAS_VIEWPORT_X', '0.5'))   # 가로 중앙
    _CANVAS_VP_Y = float(os.environ.get('CANVAS_VIEWPORT_Y', '0.3'))   # 세로 상단 30% — 중앙보다 위
    _scene_rect_state = {"timer": None, "applied": False, "attempts": 0}

    def _apply_scene_rect():
        if _scene_rect_state["applied"]:
            return
        _scene_rect_state["attempts"] += 1
        try:
            from PyQt5.QtCore import QRectF                                   # type: ignore
            from PyQt5.QtWidgets import QApplication as _QAppSR               # type: ignore
            from orangecanvas.canvas.view import CanvasView as _CVSR          # type: ignore
            app_inst = _QAppSR.instance()
            if app_inst is None:
                return
            for w in app_inst.topLevelWidgets():
                v = w.findChild(_CVSR)
                if v is not None and v.isVisible():
                    sc = v.scene()
                    if sc is not None:
                        sc.setSceneRect(QRectF(0, 0, _CANVAS_W, _CANVAS_H))
                        # view viewport 배경도 흰색 강제 — sceneRect 바깥(어두운 기본)이
                        # 노출돼 경계가 검은 라인으로 보이던 문제 제거 (언어 변경 재시작 후
                        # sceneRect 재적용 시 특히 두드러짐, 2026-06-02)
                        try:
                            from PyQt5.QtGui import QBrush as _QBr, QColor as _QCl
                            v.setBackgroundBrush(_QBr(_QCl(255, 255, 255)))
                        except Exception:
                            pass
                        # 시작 viewport 위치 조정 — 빨간 박스 기준점:
                        # 가로 중앙 + 세로 상단(약 30%) 지점이 view 중심에 오도록
                        try:
                            v.centerOn(_CANVAS_W * _CANVAS_VP_X, _CANVAS_H * _CANVAS_VP_Y)
                        except Exception as _ce:
                            print(f"[launcher] centerOn 실패: {_ce}", flush=True)
                        _scene_rect_state["applied"] = True
                        if _scene_rect_state["timer"]:
                            _scene_rect_state["timer"].stop()
                        print(f"[launcher] 캔버스 sceneRect 적용 ({_CANVAS_W}×{_CANVAS_H}) "
                              f"+ viewport ({_CANVAS_VP_X*100:.0f}%, {_CANVAS_VP_Y*100:.0f}%)",
                              flush=True)
                        return
            # 30회(60초) 시도 후 포기 — 캔버스 창이 보이지 않는 환경
            if _scene_rect_state["attempts"] >= 30:
                if _scene_rect_state["timer"]:
                    _scene_rect_state["timer"].stop()
                print("[launcher] 캔버스 sceneRect 적용 실패 (30회 시도)", flush=True)
        except Exception as _ex:
            if _scene_rect_state["attempts"] >= 30:
                if _scene_rect_state["timer"]:
                    _scene_rect_state["timer"].stop()
                print(f"[launcher] 캔버스 sceneRect 오류: {_ex}", flush=True)

    _scene_rect_state["timer"] = _QTimerBoot()
    _scene_rect_state["timer"].timeout.connect(_apply_scene_rect)
    _scene_rect_state["timer"].start(2000)  # 2초마다 캔버스 확인

    # ── 2. Handler QObject — main thread 에서 생성 ───────────────────────────
    from PyQt5.QtCore import QObject, pyqtSignal, Qt, QTimer     # type: ignore

    class Handler(QObject):
        _open_sig     = pyqtSignal(str)
        _save_sig     = pyqtSignal()
        _examples_sig = pyqtSignal()
        _tool_sig     = pyqtSignal(str)
        _pan_sig      = pyqtSignal(int, int)    # 캔버스 패닝 (dx, dy)
        _restart_sig  = pyqtSignal()            # 언어 변경 재시작
        _wf_query_sig = pyqtSignal()            # Workflow Info 조회 (현재 title/desc → JSON 파일)
        _wf_update_sig = pyqtSignal(str)        # Workflow Info 업데이트 (JSON 페이로드 → scheme 적용)
        _wcatalog_sig = pyqtSignal()            # 위젯 카탈로그 dump 요청 (단계 1)
        _add_widget_sig = pyqtSignal(str)       # 위젯 추가 (단계 3B): JSON payload

        def __init__(self):
            super().__init__()
            self._open_sig.connect(self._do_open, Qt.QueuedConnection)
            self._save_sig.connect(self._do_save, Qt.QueuedConnection)
            self._examples_sig.connect(self._do_open_examples, Qt.QueuedConnection)
            self._tool_sig.connect(self._do_tool, Qt.QueuedConnection)
            self._pan_sig.connect(self._do_pan, Qt.QueuedConnection)
            self._restart_sig.connect(self._do_restart, Qt.QueuedConnection)
            self._wf_query_sig.connect(self._do_wf_query, Qt.QueuedConnection)
            self._wf_update_sig.connect(self._do_wf_update, Qt.QueuedConnection)
            self._wcatalog_sig.connect(self._do_dump_catalog, Qt.QueuedConnection)
            self._add_widget_sig.connect(self._do_add_widget, Qt.QueuedConnection)

        # ── 열기 ──────────────────────────────────────────────────────────────
        def request_open(self, path: str):
            self._open_sig.emit(path)

        def _do_open(self, path: str):
            app = QApplication.instance()
            if app is None:
                return
            # 크래시 복구 다이얼로그 방지: .swp.p 파일 삭제
            try:
                dirn = os.path.dirname(path)
                basen = os.path.basename(path)
                swp = os.path.join(dirn, '.' + basen + '.swp.p')
                if os.path.exists(swp):
                    os.remove(swp)
                    print(f"[launcher] swp 파일 삭제: {swp}", flush=True)
            except OSError:
                pass
            # scratch swp 파일도 삭제
            try:
                from orangecanvas.utils.pickle import glob_scratch_swps  # type: ignore
                for _swp in glob_scratch_swps():
                    try:
                        os.remove(_swp)
                    except OSError:
                        pass
            except Exception:
                pass
            for w in app.topLevelWidgets():
                if hasattr(w, "open_scheme_file") and w.isVisible():
                    try:
                        # open_scheme_file 은 is_transient()==False 이면 새 창을 생성함.
                        # 탭 전환마다 새 창이 쌓이는 것을 방지하기 위해
                        # __is_transient 를 True 로 강제하여 항상 현재 창을 재사용한다.
                        try:
                            w._CanvasMainWindow__is_transient = True
                        except Exception:
                            pass
                        w.open_scheme_file(path)
                        print(f"[launcher] 열기 완료: {path}", flush=True)
                        # 위젯이 좌측 도구 패널·탭바 아래에 가려지지 않도록 viewport 패닝.
                        # 두 차례 호출 (150ms, 600ms) — layout 안정화 타이밍 차이 보정.
                        try:
                            QTimer.singleShot(150, lambda _w=w: self._scroll_to_leftmost(_w))
                            QTimer.singleShot(600, lambda _w=w: self._scroll_to_leftmost(_w))
                        except Exception:
                            pass
                    except Exception as exc:
                        print(f"[launcher] open_scheme_file 오류: {exc}", flush=True)
                    return
            widgets = [type(w).__name__ for w in app.topLevelWidgets()]
            print(f"[launcher] 메인 윈도우 아직 없음 — 재시도 (현재: {widgets})", flush=True)
            QTimer.singleShot(1000, lambda: self._do_open(path))

        def _scroll_to_leftmost(self, w):
            """.ows 로드 후 가장 왼쪽/위 위젯이 좌측 도구 패널에 가려지지 않도록 스크롤.
            QDockWidget 은 LeftDockWidgetArea 에 배치되어 view 를 우측으로 밀기 때문에
            view 의 viewport 좌측에서 일정 픽셀 떨어진 위치에 leftmost 노드를 두면 충분.
            패널 expand/collapse 상태와 무관하게 동일한 viewport-relative 마진 사용.

            Qt transform 은 건드리지 않음 — zoom/위젯 크기는 그대로 유지."""
            try:
                from PyQt5.QtWidgets import QGraphicsView  # type: ignore
                doc = w.current_document()
                if doc is None:
                    return
                scheme = doc.scheme()
                if scheme is None or not getattr(scheme, "nodes", None):
                    return
                xs, ys = [], []
                for n in scheme.nodes:
                    pos = getattr(n, "position", None)
                    if pos and len(pos) >= 2:
                        try:
                            xs.append(float(pos[0]))
                            ys.append(float(pos[1]))
                        except (TypeError, ValueError):
                            continue
                if not xs:
                    return
                leftmost_x = min(xs)
                topmost_y = min(ys)
                view = doc.view() if hasattr(doc, "view") else None
                if view is None or not view.isVisible():
                    best_view, best_area = None, 0
                    for child in w.findChildren(QGraphicsView):
                        if not child.isVisible():
                            continue
                        area = child.width() * child.height()
                        if area > best_area:
                            best_area = area
                            best_view = child
                    view = best_view
                if view is None:
                    return
                # viewport 안에서 가장 왼쪽/위 위젯이 들어갈 위치 (사용자 지정 영역, 2026-05-28).
                # · MARGIN_X = 140: 좌측 도구 패널(아이콘바 ~25px) + 우측 여백 → 빨간 세로선 기준
                # · MARGIN_Y = 200: 상단 탭바·메뉴바 아래 충분한 여유 → 빨간 가로선 기준
                # 결과적으로 .ows 위젯이 view 의 좌상단 사용자 지정 영역(이미지 파란 박스)
                # 안에서 시작하도록 viewport 를 패닝.
                MARGIN_X = 140
                MARGIN_Y = 200
                t = view.transform()
                sx = t.m11() if abs(t.m11()) > 1e-6 else 1.0
                sy = t.m22() if abs(t.m22()) > 1e-6 else 1.0
                cur_rect = view.mapToScene(view.viewport().rect()).boundingRect()
                target_left = leftmost_x - (MARGIN_X / sx)
                target_top = topmost_y - (MARGIN_Y / sy)
                dx = target_left - cur_rect.left()
                dy = target_top - cur_rect.top()
                hbar = view.horizontalScrollBar()
                vbar = view.verticalScrollBar()
                hbar.setValue(int(hbar.value() + dx * sx))
                vbar.setValue(int(vbar.value() + dy * sy))
                print(f"[launcher] _scroll_to_leftmost: leftmost=({leftmost_x:.0f},{topmost_y:.0f}) zoom=({sx:.2f},{sy:.2f}) dpx=({dx*sx:.0f},{dy*sy:.0f})", flush=True)
            except Exception as exc:
                print(f"[launcher] _scroll_to_leftmost 오류: {exc}", flush=True)

        # ── 저장 ──────────────────────────────────────────────────────────────
        def request_save(self):
            self._save_sig.emit()

        def _do_save(self):
            app = QApplication.instance()
            if app is None:
                self._write_save_done("ERROR:no_app")
                return
            for w in app.topLevelWidgets():
                if hasattr(w, "save_scheme_to") and hasattr(w, "current_document") and w.isVisible():
                    try:
                        doc    = w.current_document()
                        scheme = doc.scheme()
                        title  = getattr(scheme, "title", "") or "workflow"
                        safe   = re.sub(r'[^\w\-_. ]', '_', title).strip() or "workflow"
                        path   = f"/tmp/_ows_{safe}.ows"
                        ok     = w.save_scheme_to(scheme, path)
                        if ok:
                            print(f"[launcher] 저장 완료: {path}", flush=True)
                            self._write_save_done(f"{path}|{title}")
                        else:
                            print("[launcher] save_scheme_to 실패", flush=True)
                            self._write_save_done("ERROR:save_failed")
                    except Exception as exc:
                        print(f"[launcher] 저장 오류: {exc}", flush=True)
                        self._write_save_done(f"ERROR:{exc}")
                    return
            widgets = [type(w).__name__ for w in app.topLevelWidgets()]
            print(f"[launcher] 저장: 메인 윈도우 없음 ({widgets})", flush=True)
            self._write_save_done("ERROR:no_window")

        # ── Example Workflows ─────────────────────────────────────────────────
        def request_open_examples(self):
            self._examples_sig.emit()

        def _do_open_examples(self):
            app = QApplication.instance()
            if app is None:
                return
            for w in app.topLevelWidgets():
                if hasattr(w, "welcome_dialog") and w.isVisible():
                    try:
                        w.examples_dialog()
                        print("[launcher] Example Workflows 다이얼로그 열기 완료", flush=True)
                    except Exception as exc:
                        print(f"[launcher] examples_dialog 오류: {exc}", flush=True)
                    return
            print("[launcher] welcome_dialog: 메인 윈도우 없음", flush=True)

        # ── 도구 활성화 ────────────────────────────────────────────────────────
        def request_tool(self, tool: str):
            self._tool_sig.emit(tool)

        def _do_tool(self, tool: str):
            from PyQt5.QtWidgets import QAction, QWidget  # type: ignore

            # text:NN 형식 → 텍스트 도구 + 폰트 크기 동시 적용
            font_size = None
            if tool.startswith("text:"):
                try:
                    font_size = int(tool.split(":", 1)[1])
                    tool = "text"
                except ValueError:
                    font_size = None

            # pen:<hex> 형식 → 화살표 도구 + 색상 동시 적용
            pen_color = None
            if tool.startswith("pen:"):
                hex_part = tool.split(":", 1)[1]
                # 3자 hex (#000) 또는 6자 hex (#C1272D) — Orange3가 5개 색상 등록
                if all(c in "0123456789abcdefABCDEF" for c in hex_part) and len(hex_part) in (3, 6):
                    pen_color = "#" + hex_part
                    tool = "pen"

            action_map = {
                "text":          "new-text-action",
                "pen":           "new-arrow-action",
                "delete":        "remove-selected",
                "pause":         "signal-freeze-action",
                "zoomin":        "action-zoom-in",
                "zoomout":       "action-zoom-out",
                "zoomreset":     "action-zoom-reset",
                "selectall":     "select-all-action",
                "workflow-info": "show-properties-action",  # Ctrl+I — Workflow Info 다이얼로그
                "undo":          "undo-action",              # Ctrl+Z — Undo (단계 3C)
                "redo":          "redo-action",              # Ctrl+Y / Ctrl+Shift+Z — Redo (단계 3C)
            }
            obj_name = action_map.get(tool)
            app = QApplication.instance()
            if app is None or obj_name is None:
                return

            # ── text:NN 직접 적용 경로 ───────────────────────────────────────────
            # Qt QActionGroup.triggered 시그널 체인에 의존하지 않고
            # SchemeEditWidget의 내부 상태(__fontActionGroup, __scene)에 직접 접근해
            # 다음 두 가지를 보장:
            #   (a) sub-action을 checked 상태로 만들어 다음 텍스트 모드 진입 시 사용
            #   (b) 텍스트 모드 active면 현재 handler.setFont를 즉시 호출
            if font_size is not None:
                target = f"{font_size}px"
                se_widget = None
                for w in app.topLevelWidgets():
                    for child in w.findChildren(QWidget):
                        if child.__class__.__name__ == 'SchemeEditWidget':
                            se_widget = child
                            break
                    if se_widget:
                        break

                if se_widget is not None:
                    fag  = getattr(se_widget, '_SchemeEditWidget__fontActionGroup', None)
                    txta = getattr(se_widget, '_SchemeEditWidget__newTextAnnotationAction', None)
                    scn  = getattr(se_widget, '_SchemeEditWidget__scene', None)

                    if fag is not None and txta is not None:
                        target_act = None
                        for fa in fag.actions():
                            if fa.text() == target:
                                target_act = fa
                                break

                        if target_act is not None:
                            # (1) 그룹에서 사이즈 액션을 checked로 (exclusive group이라 다른 건 자동 uncheck)
                            target_act.setChecked(True)

                            # (2) 현재 handler가 NewTextAnnotation이면 즉시 setFont
                            try:
                                from orangecanvas.document import interactions as _intr  # type: ignore
                                handler = scn.user_interaction_handler if scn is not None else None
                                if handler is not None and isinstance(handler, _intr.NewTextAnnotation):
                                    handler.setFont(target_act.font())
                                    print(f"[launcher] handler.setFont 직접 적용: {target}", flush=True)
                            except Exception as _se:
                                print(f"[launcher] setFont 직접 호출 실패: {_se}", flush=True)

                            # (3) 텍스트 모드가 OFF면 trigger해서 ON으로 전환
                            #     ON상태로 toggle → __toggleNewTextAnnotation이 checkedAction(=target_act)
                            #     의 폰트로 새 handler 생성
                            if not txta.isChecked():
                                txta.trigger()
                                print(f"[launcher] 텍스트 모드 활성화 + 폰트 {target}", flush=True)
                            else:
                                print(f"[launcher] 폰트 갱신: {target} (텍스트 모드 유지)", flush=True)
                            return
                        else:
                            print(f"[launcher] 폰트 액션 없음: {target}", flush=True)
                else:
                    print(f"[launcher] SchemeEditWidget 못 찾음 — 기본 텍스트 액션으로 fallback", flush=True)

            # ── pen:<color> 직접 적용 경로 ────────────────────────────────────────
            # Orange3 SchemeEditWidget의 __arrowColorActionGroup에서 일치하는 색상 액션을
            # checked로 만들고, handler.setColor 즉시 호출 + 화살표 모드 OFF면 trigger.
            if pen_color is not None:
                se_widget2 = None
                for w in app.topLevelWidgets():
                    for child in w.findChildren(QWidget):
                        if child.__class__.__name__ == 'SchemeEditWidget':
                            se_widget2 = child
                            break
                    if se_widget2:
                        break
                if se_widget2 is not None:
                    ag2  = getattr(se_widget2, '_SchemeEditWidget__arrowColorActionGroup', None)
                    arra = getattr(se_widget2, '_SchemeEditWidget__newArrowAnnotationAction', None)
                    scn2 = getattr(se_widget2, '_SchemeEditWidget__scene', None)
                    if ag2 is not None and arra is not None:
                        target_pen = None
                        # action.data()는 등록 시 사용된 정확한 hex 문자열 ("#000", "#C1272D" 등)
                        want = pen_color.lower()
                        for fa in ag2.actions():
                            d = fa.data()
                            if isinstance(d, str) and d.lower() == want:
                                target_pen = fa
                                break
                        if target_pen is not None:
                            target_pen.setChecked(True)
                            try:
                                from orangecanvas.document import interactions as _intr  # type: ignore
                                handler = scn2.user_interaction_handler if scn2 is not None else None
                                if handler is not None and isinstance(handler, _intr.NewArrowAnnotation):
                                    handler.setColor(target_pen.data())
                                    print(f"[launcher] handler.setColor 직접 적용: {pen_color}", flush=True)
                            except Exception as _ce:
                                print(f"[launcher] setColor 직접 호출 실패: {_ce}", flush=True)
                            if not arra.isChecked():
                                arra.trigger()
                                print(f"[launcher] 화살표 모드 활성화 + 색상 {pen_color}", flush=True)
                            else:
                                print(f"[launcher] 화살표 색상 갱신: {pen_color} (모드 유지)", flush=True)
                            return
                        else:
                            print(f"[launcher] 색상 액션 없음: {pen_color} — 기본 화살표로 fallback", flush=True)

            # ── workflow-info: 이미 다이얼로그 열려있으면 건너뜀 ──────────────────
            # SchemeInfoDialog는 modal이라 exec()로 main thread를 블록. 사용자가 ⓘ를
            # 여러 번 클릭하면 신호가 watcher → main loop 큐에 쌓여 닫을 때마다 또 열림.
            # 가드: visible한 SchemeInfoDialog 인스턴스가 있으면 추가 trigger 무시.
            if obj_name == "show-properties-action":
                try:
                    from orangecanvas.application.schemeinfo import SchemeInfoDialog  # type: ignore
                    for w in app.topLevelWidgets():
                        if isinstance(w, SchemeInfoDialog) and w.isVisible():
                            print("[launcher] Workflow Info 이미 표시 중 — 추가 트리거 무시", flush=True)
                            return
                except Exception as _se:
                    print(f"[launcher] SchemeInfoDialog 체크 실패: {_se}", flush=True)

            # ── 일반 도구 경로 (text 단독 포함) ──────────────────────────────────
            # Phase 3D-3 fix v7 (2026-05-23): action.isEnabled() 체크 추가.
            # `remove-selected` 등 일부 액션은 기본 enabled=False — selection 없으면
            # trigger() 호출되어도 handler 실행 안 됨. enabled 면 trigger,
            # 그렇지 않으면 SchemeEditWidget 메서드 fallback 으로 진입.
            for w in app.topLevelWidgets():
                action = w.findChild(QAction, obj_name)
                if action:
                    en = action.isEnabled()
                    print(f"[launcher] action {obj_name} found, enabled={en}", flush=True)
                    if en:
                        action.trigger()
                        print(f"[launcher] 도구 활성화: {tool} ({obj_name})", flush=True)
                        return
                    break   # 비활성 → fallback 으로

            # ── Fallback (2026-05-23 Phase 3D-3): orangecanvas SchemeEditWidget 의
            # 일부 액션은 setObjectName() 이 호출되지 않아 findChild(QAction, name) 가
            # 매칭하지 못한다. 메인 캔버스의 SchemeEditWidget 을 찾아 동일 기능을
            # 메서드로 직접 호출 → action.trigger() 와 동일 효과.
            _SCHEME_METHODS = {
                "delete":    "removeSelected",
                "selectall": "selectAll",
                "undo":      "undoStack",        # 특수 처리 (아래)
                "redo":      "undoStack",
            }
            method_name = _SCHEME_METHODS.get(tool)
            if method_name:
                from PyQt5.QtWidgets import QWidget  # type: ignore
                for w in app.topLevelWidgets():
                    for ch in w.findChildren(QWidget):
                        if ch.__class__.__name__ != 'SchemeEditWidget':
                            continue
                        # undo/redo: undoStack().undo() / .redo() 호출
                        if tool in ("undo", "redo"):
                            stack = ch.undoStack() if hasattr(ch, 'undoStack') else None
                            if stack and getattr(stack, tool, None):
                                getattr(stack, tool)()
                                print(f"[launcher] 도구 활성화 fallback: {tool} via undoStack().{tool}()", flush=True)
                                return
                        else:
                            fn = getattr(ch, method_name, None)
                            if fn:
                                fn()
                                print(f"[launcher] 도구 활성화 fallback: {tool} via SchemeEditWidget.{method_name}()", flush=True)
                                return
            print(f"[launcher] 도구 액션 없음: {obj_name}", flush=True)

        # ── 캔버스 패닝 (Hand 도구 드래그) ────────────────────────────────────
        def request_pan(self, dx: int, dy: int):
            self._pan_sig.emit(dx, dy)

        def _do_pan(self, dx: int, dy: int):
            """QGraphicsView 의 scrollbar 를 직접 조정해 픽셀 정확한 패닝 수행.
            scene이 viewport에 맞으면 scrollbar range=0 → setValue가 무시됨 (자연스럽게 비활성)."""
            from PyQt5.QtWidgets import QGraphicsView  # type: ignore
            app = QApplication.instance()
            if app is None:
                return
            # 메인 캔버스 view 찾기 — 면적이 가장 큰 QGraphicsView
            best_view = None
            best_area = 0
            for w in app.topLevelWidgets():
                for v in w.findChildren(QGraphicsView):
                    if not v.isVisible():
                        continue
                    area = v.width() * v.height()
                    if area > best_area:
                        best_area = area
                        best_view = v
            if best_view is None:
                return
            hbar = best_view.horizontalScrollBar()
            vbar = best_view.verticalScrollBar()
            hbar.setValue(hbar.value() + int(dx))
            vbar.setValue(vbar.value() + int(dy))

        # ── 언어 변경 재시작 ──────────────────────────────────────────────────
        def request_restart(self):
            self._restart_sig.emit()

        def _do_restart(self):
            print("[launcher] 언어 변경 재시작 (exit 96)", flush=True)
            import os as _os
            _os._exit(96)  # os._exit: Python cleanup 우회 → shell이 96을 확실히 수신

        # ── Workflow Info: 조회/업데이트 ──────────────────────────────────────
        def _find_canvas_window(self):
            """현재 활성 CanvasMainWindow 반환 (없으면 None)."""
            from PyQt5.QtWidgets import QApplication  # type: ignore
            from orangecanvas.application.canvasmain import CanvasMainWindow  # type: ignore
            a = QApplication.instance()
            if a is None:
                return None
            for w in a.topLevelWidgets():
                if isinstance(w, CanvasMainWindow):
                    return w
            return None

        def request_wf_query(self):
            self._wf_query_sig.emit()

        def _do_wf_query(self):
            """현재 scheme의 title/description을 JSON으로 응답 파일에 작성."""
            import json as _json
            try:
                cmw = self._find_canvas_window()
                title = ""
                desc = ""
                show_on_new = False
                if cmw is not None:
                    try:
                        doc = cmw.current_document()
                        scheme = doc.scheme() if doc else None
                        if scheme is not None:
                            title = scheme.title or ""
                            desc = scheme.description or ""
                    except Exception as _de:
                        print(f"[launcher] wf_query scheme 조회 실패: {_de}", flush=True)
                    # QSettings에서 show-at-new-scheme 값 조회
                    try:
                        from PyQt5.QtCore import QSettings  # type: ignore
                        s = QSettings()
                        show_on_new = bool(s.value("schemeinfo/show-at-new-scheme", False, type=bool))
                    except Exception:
                        pass
                payload = {"title": title, "description": desc, "showAtNewScheme": show_on_new}
                with open(WF_INFO_RESPONSE, "w", encoding="utf-8") as f:
                    _json.dump(payload, f, ensure_ascii=False)
                print(f"[launcher] wf_query 응답: title={title!r}", flush=True)
            except Exception as e:
                print(f"[launcher] wf_query 처리 실패: {e}", flush=True)

        def request_wf_update(self, payload_json: str):
            self._wf_update_sig.emit(payload_json)

        def _do_wf_update(self, payload_json: str):
            """JSON 페이로드로 scheme의 title/description 갱신 (undo stack에 기록)."""
            import json as _json
            try:
                data = _json.loads(payload_json)
            except Exception as e:
                print(f"[launcher] wf_update JSON 파싱 실패: {e}", flush=True)
                return
            title = data.get("title", "")
            desc = data.get("description", "")
            show_on_new = bool(data.get("showAtNewScheme", False))
            try:
                cmw = self._find_canvas_window()
                if cmw is None:
                    print("[launcher] wf_update: CanvasMainWindow 없음", flush=True)
                    return
                doc = cmw.current_document()
                # show_scheme_properties 흐름 모방 — undo macro로 묶기
                try:
                    stack = doc.undoStack()
                    stack.beginMacro("Change Info")
                    doc.setTitle(title)
                    doc.setDescription(desc)
                    stack.endMacro()
                except Exception as _ue:
                    # undo 실패 시 직접 set (최후 fallback)
                    print(f"[launcher] wf_update undo 매크로 실패 → 직접 set: {_ue}", flush=True)
                    try:
                        doc.setTitle(title)
                        doc.setDescription(desc)
                    except Exception as _se:
                        print(f"[launcher] wf_update 직접 set 실패: {_se}", flush=True)
                # show-at-new-scheme 설정 저장
                try:
                    from PyQt5.QtCore import QSettings  # type: ignore
                    QSettings().setValue("schemeinfo/show-at-new-scheme", show_on_new)
                except Exception:
                    pass
                print(f"[launcher] wf_update 적용: title={title!r}", flush=True)
            except Exception as e:
                print(f"[launcher] wf_update 처리 실패: {e}", flush=True)

        # ── 위젯 카탈로그 dump (단계 1) ──────────────────────────────────────
        def request_dump_catalog(self):
            print("[launcher] request_dump_catalog → emit signal", flush=True)
            self._wcatalog_sig.emit()
            print("[launcher] request_dump_catalog emit 완료", flush=True)

        def _do_dump_catalog(self):
            """signal-slot 엔트리 — retry 0으로 헬퍼 호출 (PyQt signal-slot에서 default arg 사용 시
            method binding 문제로 호출 자체가 안 되는 케이스 회피)."""
            print("[launcher] _do_dump_catalog 슬롯 진입 (signal received)", flush=True)
            self._do_dump_catalog_with_retry(0)

        def _do_dump_catalog_with_retry(self, _retry: int):
            """현재 활성 WidgetRegistry를 순회하여 메타데이터 JSON으로 저장.

            출력 스키마: { "language": "ko", "categories": [{name, color, priority,
            widgets: [{qualified_name, name, description, icon_b64, priority, keywords}]}] }
            아이콘은 base64 PNG (32x32) — HTML img src에 직접 사용 가능.

            registry 준비되지 않으면 0.8s 간격 최대 8회 retry (Orange3 부팅 중일 수 있음).
            """
            import json as _json
            import base64 as _b64
            import importlib as _imp
            try:
                from PyQt5.QtCore import QBuffer, QByteArray, QIODevice  # type: ignore
                from PyQt5.QtGui import QPixmap                          # type: ignore
                from PyQt5.QtWidgets import QApplication as _QAppC       # type: ignore
            except Exception as _ie:
                print(f"[launcher] catalog: PyQt5 import 실패: {_ie}", flush=True)
                return

            print(f"[launcher] _do_dump_catalog 진입 (retry={_retry})", flush=True)
            # widget_registry 속성을 가진 top-level widget 검색
            # (isinstance(CanvasMainWindow) 대신 — Orange3는 OWCanvasMainWindow 서브클래스 사용)
            cmw = None
            app = _QAppC.instance()
            if app is not None:
                tlws = app.topLevelWidgets()
                print(f"[launcher] catalog: topLevelWidgets {len(tlws)}개", flush=True)
                for w in tlws:
                    has_reg = hasattr(w, 'widget_registry')
                    reg_val = getattr(w, 'widget_registry', None) if has_reg else None
                    print(f"[launcher]   - {w.__class__.__name__} widget_registry={'있음' if reg_val is not None else '없음'}", flush=True)
                    if reg_val is not None:
                        cmw = w
                        break
            if cmw is None:
                if _retry < 8:
                    print(f"[launcher] catalog: 윈도우 없음 → 800ms 후 재시도", flush=True)
                    QTimer.singleShot(800, lambda r=_retry + 1: self._do_dump_catalog_with_retry(r))
                else:
                    print("[launcher] catalog: widget_registry 가진 윈도우 없음 (8회 시도 실패)", flush=True)
                return
            reg = cmw.widget_registry
            print(f"[launcher] catalog: widget_registry 발견 ({cmw.__class__.__name__})", flush=True)

            def _encode_icon_b64(icon_path: str, package: str) -> str:
                """위젯 패키지 디렉토리 기준 상대 경로의 아이콘 파일 → PNG base64."""
                if not icon_path:
                    return ""
                try:
                    mod = _imp.import_module(package)
                    mod_dir = os.path.dirname(mod.__file__ or "")
                    if not mod_dir:
                        return ""
                    full = os.path.join(mod_dir, icon_path)
                    if not os.path.isfile(full):
                        return ""
                    pix = QPixmap(full)
                    if pix.isNull():
                        return ""
                    # 32x32로 리사이즈 (HTML 사이드바 표시 크기)
                    pix = pix.scaled(32, 32, transformMode=1)  # Qt.SmoothTransformation = 1
                    buf = QByteArray()
                    qbuf = QBuffer(buf)
                    qbuf.open(QIODevice.WriteOnly)
                    pix.save(qbuf, "PNG")
                    return _b64.b64encode(bytes(buf)).decode("ascii")
                except Exception:
                    return ""

            # Orange3 실제 적용 언어를 QSettings(application/language)에서 읽음.
            # LANG env는 컨테이너에서 항상 C.UTF-8 고정이라 부적합.
            # 응답에는 ISO code (en/ko/sl 등)로 변환해서 반환.
            try:
                from PyQt5.QtCore import QSettings  # type: ignore
                _q = QSettings()
                _orange_lang = _q.value("application/language", "English")
                _lang_map = {"English": "en", "Korean": "ko", "Slovenian": "sl"}
                lang = _lang_map.get(_orange_lang, (str(_orange_lang)[:2] or "en").lower())
            except Exception:
                lang = (os.environ.get("LANG", "en").split("_")[0].split(".")[0] or "en")
            catalog = {"language": lang, "categories": []}

            try:
                # reg.registry: [(CategoryDescription, [WidgetDescription, ...]), ...]
                for cat_desc, widgets in reg.registry:
                    cat_data = {
                        "name": getattr(cat_desc, 'name', '') or '',
                        "color": getattr(cat_desc, 'background', None) or "#cccccc",
                        "priority": int(getattr(cat_desc, 'priority', 0) or 0),
                        "widgets": [],
                    }
                    for wd in widgets:
                        try:
                            pkg = getattr(wd, 'package', '') or ''
                            icon_rel = getattr(wd, 'icon', '') or ''
                            icon_b64 = _encode_icon_b64(icon_rel, pkg) if pkg else ""
                            # inputs/outputs (Phase 5, 2026-05-24) — 풍부한 툴팁용.
                            # 각 신호: {name, type} — type 은 qualified type str.
                            # s.type 이 tuple/list (다중 타입 지원) 인 경우
                            # 재귀로 unpacking 해 "A, B" 형식으로 합침. 단순
                            # str(tuple) 사용 시 tuple repr 가 그대로 노출되어
                            # "(('Orange.data.table.Table',))" 형식으로 깨짐.
                            def _type_name(t):
                                if t is None or t == '':
                                    return ''
                                if isinstance(t, str):
                                    return t
                                if isinstance(t, (tuple, list)):
                                    return ", ".join(_type_name(x) for x in t if x is not None)
                                try:
                                    mod = getattr(t, '__module__', '')
                                    nm = getattr(t, '__name__', '') or getattr(t, '__qualname__', '')
                                    return f"{mod}.{nm}" if mod and nm else (nm or str(t))
                                except Exception:
                                    return str(t)
                            def _sig(s):
                                return {"name": getattr(s, 'name', '') or '',
                                        "type": _type_name(getattr(s, 'type', ''))}
                            inputs = [_sig(s) for s in (getattr(wd, 'inputs', []) or [])]
                            outputs = [_sig(s) for s in (getattr(wd, 'outputs', []) or [])]
                            # package: Orange.widgets.data → "Orange3", 외부 addon 은
                            # 첫 토큰 캡쳐 (orangecontrib.text → "Orange3-Text" 매핑).
                            pkg_top = (pkg.split('.')[0] if pkg else '') or ''
                            cat_data["widgets"].append({
                                "qualified_name": getattr(wd, 'qualified_name', ''),
                                "name": getattr(wd, 'name', '') or '',
                                "description": (getattr(wd, 'description', '') or '')[:300],
                                "icon_b64": icon_b64,
                                "priority": int(getattr(wd, 'priority', 0) or 0),
                                "keywords": list(getattr(wd, 'keywords', []) or []),
                                "package": pkg_top,
                                "inputs": inputs,
                                "outputs": outputs,
                            })
                        except Exception as _we:
                            print(f"[launcher] catalog: widget skip: {_we}", flush=True)
                    cat_data["widgets"].sort(key=lambda x: x["priority"])
                    catalog["categories"].append(cat_data)
                catalog["categories"].sort(key=lambda x: x["priority"])

                # 원자적 쓰기 (2026-05-26): .tmp 에 쓰고 rename — session-manager 가
                # 폴링 중 partial JSON 읽어 500 으로 떨어지는 race 방지.
                _tmp_path = WIDGET_CATALOG_RESPONSE + ".tmp"
                with open(_tmp_path, "w", encoding="utf-8") as f:
                    _json.dump(catalog, f, ensure_ascii=False)
                import os as _os_atomic
                _os_atomic.replace(_tmp_path, WIDGET_CATALOG_RESPONSE)
                n_cat = len(catalog["categories"])
                n_widgets = sum(len(c["widgets"]) for c in catalog["categories"])
                print(f"[launcher] widget_catalog dump 완료: {n_cat} 카테고리, {n_widgets} 위젯", flush=True)
            except Exception as e:
                print(f"[launcher] widget_catalog dump 실패: {e}", flush=True)

        # ── 위젯 추가 (단계 3B) ──────────────────────────────────────────────
        def request_add_widget(self, payload_json: str):
            self._add_widget_sig.emit(payload_json)

        def _do_add_widget(self, payload_json: str):
            """JSON 페이로드로 캔버스에 위젯 노드 추가 — 단계 3A `/add-widget` endpoint와 짝.

            payload: {"qualified_name": "...", "x": float, "y": float}

            동작: WidgetRegistry에서 qualified_name → WidgetDescription 찾기 →
                  doc.createNewNode(desc, position=(x,y)) 호출.
                  (createNewNode → addNode → AddNodeCommand가 undoStack에 자동 push됨)
            """
            import json as _json
            try:
                data = _json.loads(payload_json)
            except Exception as e:
                print(f"[launcher] add_widget JSON 파싱 실패: {e}", flush=True)
                return
            qname = str(data.get("qualified_name", ""))
            if not qname:
                print("[launcher] add_widget: qualified_name 비어있음", flush=True)
                return
            try:
                x = float(data.get("x", 0))
                y = float(data.get("y", 0))
            except (TypeError, ValueError):
                print("[launcher] add_widget: x/y 형식 오류", flush=True)
                return

            cmw = self._find_canvas_window()
            if cmw is None:
                print("[launcher] add_widget: CanvasMainWindow 없음", flush=True)
                return
            reg = getattr(cmw, 'widget_registry', None)
            if reg is None:
                print("[launcher] add_widget: widget_registry 없음", flush=True)
                return

            # qualified_name → WidgetDescription 검색
            widget_desc = None
            try:
                for cat_desc, widgets in reg.registry:
                    for wd in widgets:
                        if getattr(wd, 'qualified_name', '') == qname:
                            widget_desc = wd
                            break
                    if widget_desc is not None:
                        break
            except Exception as e:
                print(f"[launcher] add_widget: registry 순회 실패: {e}", flush=True)
                return
            if widget_desc is None:
                print(f"[launcher] add_widget: qname not in registry: {qname}", flush=True)
                return

            # createNewNode → addNode → AddNodeCommand (Undo 한 단계로 처리)
            try:
                doc = cmw.current_document()
                if doc is None:
                    print("[launcher] add_widget: current_document 없음", flush=True)
                    return

                # auto_place=True면 마지막 노드 옆에 자동 배치.
                # 단, scheme이 비어있을 때 Orange3 기본은 (150,150)인데 우리 캔버스는
                # 1920×1080 sceneRect + viewport(50%,30%) 라서 (150,150)이 보이는 영역
                # 바깥 좌상단에 위치 → 노드가 추가되지만 사용자 화면에 안 보임.
                # → 비어있으면 viewport center 로 대체, 있으면 nextPosition 동작 그대로.
                auto_place = bool(data.get("auto_place", False))
                if auto_place:
                    try:
                        scheme = doc.scheme() if hasattr(doc, 'scheme') else None
                        nodes = list(scheme.nodes) if scheme is not None and hasattr(scheme, 'nodes') else []
                    except Exception:
                        nodes = []
                    if nodes:
                        # Orange3 nextPosition 동작 — 마지막 노드 +150 오른쪽
                        last_x, last_y = nodes[-1].position
                        ap_pos = (last_x + 150, last_y)
                    else:
                        # 빈 scheme — 현재 viewport 중앙을 scene 좌표로 변환
                        try:
                            view = doc.view()
                            if view is not None:
                                vp_rect = view.viewport().rect()
                                center_scene = view.mapToScene(vp_rect.center())
                                ap_pos = (center_scene.x(), center_scene.y())
                            else:
                                ap_pos = (150, 150)
                        except Exception as _ve:
                            print(f"[launcher] add_widget viewport center 계산 실패: {_ve}", flush=True)
                            ap_pos = (150, 150)
                    doc.createNewNode(widget_desc, title=None, position=ap_pos)
                    print(f"[launcher] add_widget 성공 (auto_place): {widget_desc.name} @ ({ap_pos[0]:.1f},{ap_pos[1]:.1f})", flush=True)
                    return

                # screen_coords=True면 (x,y)는 iframe(=X11 framebuffer) 좌표 → 씬 좌표로 변환
                # iframe top-left은 X11 (0,0)이고, 화면 안의 위치가 곧 X11 global 좌표가 됨
                # (Orange3 창은 전체 화면이라 화면 좌표 = X11 framebuffer 좌표)
                use_screen_coords = bool(data.get("screen_coords", False))
                if use_screen_coords:
                    try:
                        from PyQt5.QtCore import QPoint  # type: ignore
                        view = doc.view()
                        if view is not None:
                            local_pt = view.mapFromGlobal(QPoint(int(x), int(y)))
                            scene_pt = view.mapToScene(local_pt)
                            sx, sy = scene_pt.x(), scene_pt.y()
                            print(f"[launcher] add_widget 좌표변환: screen({x:.0f},{y:.0f}) → scene({sx:.1f},{sy:.1f})", flush=True)
                            x, y = sx, sy
                        else:
                            print("[launcher] add_widget: view 없음 → screen_coords 무시", flush=True)
                    except Exception as _me:
                        print(f"[launcher] add_widget 좌표변환 실패 → raw 사용: {_me}", flush=True)

                doc.createNewNode(widget_desc, title=None, position=(x, y))
                print(f"[launcher] add_widget 성공: {widget_desc.name} @ ({x:.1f},{y:.1f})", flush=True)
                # 추가된 위젯이 viewport 안에 보이도록 자동 스크롤 (2026-05-26).
                # 화면 밖 좌표에 추가되면 사용자가 노드가 추가됐는지 못 보는 케이스 방지.
                # use_screen_coords 케이스는 클릭 위치에 추가 → 이미 보임 (스킵).
                if not use_screen_coords:
                    try:
                        from PyQt5.QtCore import QPointF as _QPF_AW  # type: ignore
                        view = doc.view()
                        if view is not None:
                            view.centerOn(_QPF_AW(float(x), float(y)))
                            print(f"[launcher] add_widget 뷰 자동 이동 → ({x:.1f},{y:.1f})", flush=True)
                    except Exception as _ve:
                        print(f"[launcher] add_widget centerOn 실패: {_ve}", flush=True)
            except Exception as e:
                print(f"[launcher] add_widget 실패: {e}", flush=True)

        @staticmethod
        def _write_save_done(content: str):
            try:
                with open(SAVE_DONE, "w") as f:
                    f.write(content)
            except OSError as e:
                print(f"[launcher] save_done 기록 실패: {e}", flush=True)

    handler = Handler()

    # ── 3. 백그라운드 감시 스레드 ────────────────────────────────────────────
    def _watcher():
        print("[launcher] 신호 파일 감시 시작", flush=True)
        while True:
            # 800ms → 200ms (2026-05-27) — 더블클릭 위젯 추가 응답 지연 단축.
            # CPU idle 시 추가 부하 미미 (file stat 7회 × 5/초 = 35 stat/초).
            time.sleep(0.2)

            # 열기 신호
            if os.path.exists(OPEN_SIGNAL):
                try:
                    path = open(OPEN_SIGNAL).read().strip()
                    os.remove(OPEN_SIGNAL)
                except OSError:
                    pass
                else:
                    if path and os.path.isfile(path):
                        print(f"[launcher] 열기 신호: {path}", flush=True)
                        handler.request_open(path)
                    elif path:
                        print(f"[launcher] 파일 없음: {path}", flush=True)

            # 저장 신호
            if os.path.exists(SAVE_SIGNAL):
                try:
                    os.remove(SAVE_SIGNAL)
                except OSError:
                    pass
                print("[launcher] 저장 신호 감지", flush=True)
                handler.request_save()

            # Example Workflows 신호
            if os.path.exists(EXAMPLES_SIGNAL):
                try:
                    os.remove(EXAMPLES_SIGNAL)
                except OSError:
                    pass
                print("[launcher] Example Workflows 신호 감지", flush=True)
                handler.request_open_examples()

            # 도구 활성화 신호 (특수: "pan:dx,dy" → 캔버스 패닝)
            if os.path.exists(TOOL_SIGNAL):
                try:
                    tool = open(TOOL_SIGNAL).read().strip()
                    os.remove(TOOL_SIGNAL)
                except OSError:
                    pass
                else:
                    if tool.startswith("pan:"):
                        try:
                            dx_s, dy_s = tool[4:].split(",", 1)
                            handler.request_pan(int(dx_s), int(dy_s))
                        except (ValueError, IndexError):
                            print(f"[launcher] pan 신호 파싱 실패: {tool}", flush=True)
                    elif tool:
                        print(f"[launcher] 도구 신호: {tool}", flush=True)
                        handler.request_tool(tool)

            # 언어 변경 재시작 신호
            if os.path.exists(RESTART_SIGNAL):
                try:
                    os.remove(RESTART_SIGNAL)
                except OSError:
                    pass
                print("[launcher] 언어 변경 재시작 신호 감지", flush=True)
                handler.request_restart()

            # Workflow Info: 조회 신호 (ⓘ 클릭 시 backend가 작성)
            if os.path.exists(WF_INFO_QUERY):
                try:
                    os.remove(WF_INFO_QUERY)
                except OSError:
                    pass
                handler.request_wf_query()

            # Workflow Info: 업데이트 신호 (모달 확인 클릭 시 backend가 작성)
            if os.path.exists(WF_INFO_UPDATE):
                try:
                    with open(WF_INFO_UPDATE, "r", encoding="utf-8") as _wf_f:
                        _wf_payload = _wf_f.read()
                    os.remove(WF_INFO_UPDATE)
                except OSError as _we:
                    print(f"[launcher] wf_update 파일 읽기 실패: {_we}", flush=True)
                    _wf_payload = None
                if _wf_payload:
                    handler.request_wf_update(_wf_payload)

            # 단계 1: 위젯 카탈로그 dump 신호 (frontend가 /widget-catalog 호출 시 backend가 작성)
            if os.path.exists(WIDGET_CATALOG_QUERY):
                print("[launcher] widget_catalog_query 신호 감지 → dump 요청", flush=True)
                try:
                    os.remove(WIDGET_CATALOG_QUERY)
                except OSError:
                    pass
                handler.request_dump_catalog()

            # 단계 3B: 위젯 추가 신호 (frontend POST /add-widget 호출 시 backend가 작성)
            if os.path.exists(ADD_WIDGET_SIGNAL):
                try:
                    with open(ADD_WIDGET_SIGNAL, "r", encoding="utf-8") as _aw_f:
                        _aw_payload = _aw_f.read()
                    os.remove(ADD_WIDGET_SIGNAL)
                except OSError as _aw_e:
                    print(f"[launcher] add_widget 파일 읽기 실패: {_aw_e}", flush=True)
                    _aw_payload = None
                if _aw_payload:
                    print(f"[launcher] add_widget 신호 감지 → handler", flush=True)
                    handler.request_add_widget(_aw_payload)

    threading.Thread(target=_watcher, daemon=True).start()

    # ── 4. 크래시 복구 다이얼로그 완전 비활성화 ─────────────────────────────
    try:
        from orangecanvas.application.canvasmain import CanvasMainWindow as _CMW  # type: ignore
        _CMW.ask_load_swp_if_exists = lambda self: False
        _CMW.ask_load_swp = lambda self: False
        print("[launcher] 크래시 복구 다이얼로그 비활성화 완료", flush=True)
    except Exception as _e:
        print(f"[launcher] 크래시 복구 패치 실패: {_e}", flush=True)

    # ── 4-a1. 위젯 사용 로깅 (이용 패턴 2단계, 2026-06-09) ──────────────────────
    # Scheme.add_node 를 후킹해 위젯 추가 시 /config/.usage_widgets.jsonl 에 한 줄
    # 기록(위젯 qualified id + 시각). session-manager 가 세션 종료 시 이 파일을
    # 수확해 usage 로그(widget.add)로 집계 → Top 위젯·구성 시퀀스 분석.
    # 데이터 내용은 기록 안 함(위젯 식별자만). 실패해도 캔버스 동작엔 영향 없음.
    try:
        from orangecanvas.scheme.scheme import Scheme as _UScheme   # type: ignore
        import json as _ujson
        _u_orig_add_node = _UScheme.add_node
        def _u_patched_add_node(self, node, *a, **k):
            r = _u_orig_add_node(self, node, *a, **k)
            try:
                _desc = getattr(node, "description", None)
                _wid = (getattr(_desc, "id", None)
                        or getattr(node, "qualified_name", None) or "?")
                with open("/config/.usage_widgets.jsonl", "a", encoding="utf-8") as _wf:
                    _wf.write(_ujson.dumps(
                        {"ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                         "widget": _wid, "ev": "add"}, ensure_ascii=False) + "\n")
            except Exception:
                pass
            return r
        _UScheme.add_node = _u_patched_add_node
        print("[launcher] 위젯 사용 로깅 패치 적용", flush=True)
    except Exception as _e:
        print(f"[launcher] 위젯 사용 로깅 패치 실패: {_e}", flush=True)

    # ── 4-a2. Edit Links 다이얼로그 카드 chrome (wiget_card_26_work.md §3 스펙) ──
    # EditLinksDialog(QDialog)는 OWWidget 이 아니라 _apply_clean_chrome 미적용 대상.
    # 동일 시각 스펙만 자족적으로 적용: 점(●)+제목+× 헤더, 헤더 #fafafa·상단 8px 둥글게,
    # 하단 1px #d0d0d0 라인, 다이얼로그 흰 배경+1px 테두리+8px 둥근 모서리, 헤더 드래그 이동.
    # windowwk.md 준수: windowFlags() 보존하며 FramelessWindowHint 만 추가(=Qt.Dialog 유지).
    # OWWidget 전용 기능(색상 피커/노드색/statusbar)은 제외.
    try:
        from orangecanvas.document.editlinksdialog import EditLinksDialog as _ELD   # type: ignore
        from PyQt5.QtCore import Qt as _ELQt, QTimer as _ELTimer                    # type: ignore
        from PyQt5.QtWidgets import (QWidget as _ELW, QHBoxLayout as _ELHB,         # type: ignore
                                      QLabel as _ELLbl, QPushButton as _ELBtn,
                                      QFrame as _ELFrame)

        def _editlinks_round_mask(dlg):
            try:
                from PyQt5.QtGui import QPainterPath, QRegion                       # type: ignore
                from PyQt5.QtCore import QRectF                                     # type: ignore
                p = QPainterPath()
                p.addRoundedRect(QRectF(0, 0, dlg.width(), dlg.height()), 8, 8)
                dlg.setMask(QRegion(p.toFillPolygon().toPolygon()))
            except Exception:
                pass

        class _ELHdr(_ELW):
            def __init__(self, parent, title_text):
                super().__init__(parent)
                self._t = parent
                self._press = None
                self._off = None
                self._drag = False
                self.setObjectName('__cleanHdr')
                self.setFixedHeight(34)
                self.setAttribute(_ELQt.WA_StyledBackground, True)
                self.setStyleSheet(
                    'QWidget#__cleanHdr{background-color:#fafafa;'
                    'border-top-left-radius:8px;border-top-right-radius:8px;}'
                    'QLabel#__cleanTitle{color:#222;font-size:13px;font-weight:500;}'
                    'QLabel#__cleanDot{color:#bdbdbd;font-size:12px;}'
                    'QPushButton#__cleanClose{background:#ffffff;border:1px solid #f0f0f0;'
                    'border-radius:7px;color:#9ca3af;font-size:14px;font-weight:400;padding:0px;}'
                    'QPushButton#__cleanClose:hover{background:#f8f8fa;'
                    'border-color:#e0e0e0;color:#374151;}'
                )
                lay = _ELHB(self)
                lay.setContentsMargins(12, 0, 6, 0)
                lay.setSpacing(8)
                dot = _ELLbl('●'); dot.setObjectName('__cleanDot')
                ttl = _ELLbl(title_text); ttl.setObjectName('__cleanTitle')
                btn = _ELBtn('×'); btn.setObjectName('__cleanClose')
                btn.setFixedSize(26, 26)
                btn.setCursor(_ELQt.PointingHandCursor)
                btn.clicked.connect(parent.reject)   # × = Cancel (링크 편집 취소)
                lay.addWidget(dot); lay.addWidget(ttl); lay.addStretch(); lay.addWidget(btn)
                # 하단 1px 구분 라인 (border-bottom 보다 신뢰성↑ — md §3.2)
                self._line = _ELFrame(self)
                self._line.setStyleSheet('background-color:#d0d0d0;border:none;')
                self._line.setFixedHeight(1)
                self._line.setGeometry(0, 33, max(200, parent.width()), 1)
                self._line.raise_()

            def resizeEvent(self, ev):
                super().resizeEvent(ev)
                try:
                    self._line.setGeometry(0, self.height() - 1, self.width(), 1)
                    self._line.raise_()
                except Exception:
                    pass

            def mousePressEvent(self, ev):
                if ev.button() == _ELQt.LeftButton:
                    self._press = ev.pos(); self._drag = False
                    self._off = ev.globalPos() - self._t.frameGeometry().topLeft()
                    ev.accept()

            def mouseMoveEvent(self, ev):
                if self._press is not None and \
                        (ev.pos() - self._press).manhattanLength() > 4:
                    self._drag = True
                    self._t.move(ev.globalPos() - self._off)
                    ev.accept()

            def mouseReleaseEvent(self, ev):
                self._press = None; self._off = None; self._drag = False

        def _editlinks_chrome(dlg):
            if getattr(dlg, '_clean_chrome_applied', False):
                return
            dlg._clean_chrome_applied = True
            # 1) OS 타이틀바 제거 (windowFlags 보존)
            dlg.setWindowFlags(dlg.windowFlags() | _ELQt.FramelessWindowHint)
            # 2) 다이얼로그 카드 외형 — 흰 배경 + 1px 테두리 + 8px 둥근 모서리
            _base = dlg.styleSheet() or ''
            dlg.setProperty('cleanRoot', True)
            dlg.setStyleSheet(
                _base +
                'QDialog[cleanRoot="true"]{background-color:#ffffff;'
                'border:1px solid #d0d0d0;border-radius:8px;}'
            )
            # 3) 헤더 생성/표시
            title_text = dlg.windowTitle() or 'Edit Links'
            if ' — ' in title_text:
                title_text = title_text.split(' — ', 1)[0]
            hdr = _ELHdr(dlg, title_text)
            hdr.setGeometry(0, 0, max(200, dlg.width()), 34)
            hdr.show(); hdr.raise_()
            dlg._clean_hdr = hdr
            # 4) 본문이 헤더와 겹치지 않게 layout top margin +34
            try:
                _lay = dlg.layout()
                if _lay is not None:
                    _m = _lay.contentsMargins()
                    _lay.setContentsMargins(_m.left(), _m.top() + 34,
                                            _m.right(), _m.bottom())
            except Exception:
                pass
            # 5) resize/show 시 헤더 폭 + 둥근 모서리 마스크 갱신
            _orig_resize = dlg.resizeEvent
            def _new_resize(ev):
                try:
                    hdr.setGeometry(0, 0, dlg.width(), 34)
                    hdr.raise_()
                    _editlinks_round_mask(dlg)
                except Exception:
                    pass
                if callable(_orig_resize):
                    _orig_resize(ev)
            dlg.resizeEvent = _new_resize
            # 초기 1회 (레이아웃 확정 후) — 모달 exec 직후 적용
            _ELTimer.singleShot(0, lambda: (
                hdr.setGeometry(0, 0, dlg.width(), 34),
                hdr.raise_(), _editlinks_round_mask(dlg)))

        _orig_eld_init = _ELD.__init__
        def _patched_eld_init(self, *a, **k):
            _orig_eld_init(self, *a, **k)
            try:
                _editlinks_chrome(self)
            except Exception as _ce:
                print(f"[launcher] Edit Links chrome 적용 실패: {_ce}", flush=True)
        _ELD.__init__ = _patched_eld_init
        print("[launcher] Edit Links 카드 chrome 패치 적용", flush=True)
    except Exception as _e:
        print(f"[launcher] Edit Links chrome 패치 실패: {_e}", flush=True)

    # ── 4-b. NewArrow/NewTextAnnotation mouseMoveEvent AssertionError 방어 ──
    # Orange3 버그: 다른 위젯(예: 드롭다운, 툴바)에서 마우스를 누르고 캔버스로
    # 진입하면 mousePress 없이 mouseMove가 fire되어 `assert self.down_pos is not None`
    # 실패 (interactions.py:1378 NewArrowAnnotation, :1509 NewTextAnnotation).
    # down_pos 가 None 이면 단순히 무시하도록 safe wrapper로 교체.
    try:
        from orangecanvas.document import interactions as _intr  # type: ignore

        def _make_safe_mousemove(orig):
            def _safe(self, event):
                if getattr(self, "down_pos", None) is None:
                    # mousePress 누락 — 단순히 부모 핸들러로 위임
                    try:
                        from orangecanvas.document.interactions import UserInteraction as _UI
                        return _UI.mouseMoveEvent(self, event)
                    except Exception:
                        return False
                return orig(self, event)
            return _safe

        _intr.NewArrowAnnotation.mouseMoveEvent = _make_safe_mousemove(
            _intr.NewArrowAnnotation.mouseMoveEvent
        )
        _intr.NewTextAnnotation.mouseMoveEvent = _make_safe_mousemove(
            _intr.NewTextAnnotation.mouseMoveEvent
        )
        print("[launcher] mouseMoveEvent AssertionError 방어 패치 적용", flush=True)
    except Exception as _e:
        print(f"[launcher] mouseMoveEvent 패치 실패: {_e}", flush=True)

    # ── 5-pre: 카테고리명 한글화 (2026-05-28) ─────────────────────────────────
    # Orange3 i18n JSON 에 누락된 외부 애드온 카테고리 12개 한글 번역.
    # CategoryDescription.__init__ wrap 으로 name 인자를 한글로 치환.
    #
    # ⚠️ 2026-05-28 비활성화: Orange3 내장 카테고리 (Data, Transform, Visualize 등)는
    # 영어로 표시되는데 애드온 카테고리만 한글로 표시되어 부조화 발생.
    # 일관성 위해 애드온 카테고리도 영어 원문 유지 (사이드바 통일감 우선).
    # 매핑 테이블은 향후 내장 카테고리까지 한글화하기로 결정 시 재활성용으로 보존.
    _CATEGORY_KO = {
        "Single Cell":        "단일 세포",
        "Spectroscopy":       "분광학",
        "Bioinformatics":     "생물정보학",
        "Survival Analysis":  "생존 분석",
        "Fairness":           "공정성",
        "Explain":            "설명",
        "Educational":        "교육",
        "Associate":          "연관 규칙",
        "Textable":           "텍스트 처리",
        "Pumice":             "Pumice",
        "World Happiness":    "세계 행복지수",
        "SNOM":               "SNOM",
    }
    _ENABLE_CATEGORY_KO_PATCH = False  # ← True 로 바꾸면 한글화 패치 재활성
    if _ENABLE_CATEGORY_KO_PATCH:
        try:
            from orangecanvas.registry.description import CategoryDescription as _CDPre  # type: ignore
            _orig_cd_init = _CDPre.__init__
            def _patched_cd_init(self, *args, **kwargs):
                # name 은 positional 또는 keyword 양쪽 가능 — 둘 다 처리.
                if 'name' in kwargs:
                    kwargs['name'] = _CATEGORY_KO.get(kwargs['name'], kwargs['name'])
                elif args:
                    _name = args[0]
                    if _name in _CATEGORY_KO:
                        args = (_CATEGORY_KO[_name],) + args[1:]
                return _orig_cd_init(self, *args, **kwargs)
            _CDPre.__init__ = _patched_cd_init
            # 이미 등록된 WidgetRegistry 의 카테고리/위젯 description 도 사후 한글화.
            try:
                from orangecanvas.registry.base import WidgetRegistry as _WRpre  # type: ignore
                if hasattr(_WRpre, 'register_widget'):
                    _orig_reg_w = _WRpre.register_widget
                    def _patched_reg_w(self, desc):
                        try:
                            if hasattr(desc, 'category') and desc.category in _CATEGORY_KO:
                                desc.category = _CATEGORY_KO[desc.category]
                        except Exception:
                            pass
                        return _orig_reg_w(self, desc)
                    _WRpre.register_widget = _patched_reg_w
                if hasattr(_WRpre, 'register_category'):
                    _orig_reg_c = _WRpre.register_category
                    def _patched_reg_c(self, desc):
                        try:
                            if hasattr(desc, 'name') and desc.name in _CATEGORY_KO:
                                desc.name = _CATEGORY_KO[desc.name]
                        except Exception:
                            pass
                        return _orig_reg_c(self, desc)
                    _WRpre.register_category = _patched_reg_c
            except Exception:
                pass
            print(f"[launcher] 카테고리명 한글화 패치 적용 ({len(_CATEGORY_KO)}개)", flush=True)
        except Exception as _cat_ko_err:
            print(f"[launcher] 카테고리 한글화 패치 실패: {_cat_ko_err}", flush=True)
    else:
        print("[launcher] 카테고리명 한글화 패치 비활성 (영어 원문 유지)", flush=True)

    # ── 5. WidgetRegistry.category() 방어 패치 ──────────────────────────────
    # 언어 변경 후 캐시 불일치로 인해 위젯 설명의 카테고리명(예: '데이터')이
    # 레지스트리에 없을 때 KeyError 가 발생하는 것을 방지
    try:
        import bisect as _bisect
        from orangecanvas.registry.base import WidgetRegistry as _WR         # type: ignore
        from orangecanvas.registry.description import CategoryDescription as _CD  # type: ignore

        _orig_category = _WR.category

        def _safe_category(self, name):
            try:
                return _orig_category(self, name)
            except KeyError:
                print(f"[launcher] 카테고리 없음: {name!r} — 임시 생성", flush=True)
                desc = _CD(name=name)
                # registry 리스트와 _categories_dict 모두 직접 삽입 (일관성 보장)
                item = (desc, [])
                priorities = [c.priority for c, _ in self.registry]
                idx = _bisect.bisect_right(priorities, desc.priority)
                self.registry.insert(idx, item)
                self._categories_dict[name] = item
                return desc

        _WR.category = _safe_category
        print("[launcher] WidgetRegistry.category 방어 패치 적용", flush=True)
    except Exception as _patch_err:
        print(f"[launcher] category 패치 실패: {_patch_err}", flush=True)

    # ── Phase 5 (2026-05-24): SchemeEditWidget 의 캔버스 scene background 흰색 강제 ──
    # Orange3 default 는 어두운 회색 — Xpra 환경에서 사용자가 검은 배경으로 인식.
    # SchemeEditWidget.__init__ wrap → 생성 직후 scene().setBackgroundBrush(white).
    try:
        from orangecanvas.document.schemeedit import SchemeEditWidget as _SEW  # type: ignore
        from PyQt5.QtGui import QBrush as _QBrush, QColor as _QColor  # type: ignore
        _orig_sew_init = _SEW.__init__
        def _sew_init(self, *args, **kwargs):
            _orig_sew_init(self, *args, **kwargs)
            try:
                sc = self.scene()
                if sc is not None:
                    sc.setBackgroundBrush(_QBrush(_QColor(255, 255, 255)))
            except Exception:
                pass
        _SEW.__init__ = _sew_init
        print("[launcher] SchemeEditWidget scene background 흰색 패치 적용", flush=True)
    except Exception as _bg_err2:
        print(f"[launcher] scene background 패치 실패: {_bg_err2}", flush=True)

    # ── Orange3 splash screen 메시지 — 첫 2줄까지만 표시 (2026-05-25) ──────────
    # 부팅 시 add-on 리스트가 누적되어 17줄 이상 길게 표시되는 문제.
    # SplashScreen.showMessage 를 monkey-patch — message 가 multi-line 일 경우
    # 첫 2줄만 보이게 truncate.
    try:
        from orangecanvas.gui.splashscreen import SplashScreen as _SplashScr   # type: ignore
        _orig_show_msg = _SplashScr.showMessage

        def _patched_show_msg(self, message, *a, **kw):
            try:
                if isinstance(message, str) and "\n" in message:
                    lines = message.split("\n")
                    if len(lines) > 2:
                        message = "\n".join(lines[:2])
            except Exception:
                pass
            return _orig_show_msg(self, message, *a, **kw)

        _SplashScr.showMessage = _patched_show_msg
        print("[launcher] SplashScreen.showMessage 2줄 제한 패치 적용", flush=True)

        # drawContents 패치 (2026-05-25 v5): pixmap 다시 그린 후 message 를
        # splash 좌하단 영역에 manual paint. 고정 영역(상단 3줄) + 순환 영역(하단 2줄)
        # 으로 메시지를 분리하여 표시.
        from PyQt5.QtCore import QRect as _QRectMsg
        from PyQt5.QtGui import QColor as _QColMsg, QFont as _QFontMsg

        def _patched_draw(self, painter):
            try:
                pm = self.pixmap()
                if pm and not pm.isNull():
                    painter.drawPixmap(0, 0, pm)
                # message 표시 — 파란색 영역 (좌하단 좁은 박스)
                msg = ""
                try:
                    msg = self.message() if hasattr(self, "message") else ""
                except Exception:
                    pass
                if msg:
                    w, h = self.width(), self.height()
                    # 파란 영역: 좌측 20px, 하단 영역 2줄(1 고정 + 1 순환) 만 노출
                    rect = _QRectMsg(20, int(h * 0.80), w - 40, int(h * 0.16))
                    painter.setPen(_QColMsg("#FFFFFF"))
                    f = painter.font()
                    f.setPointSize(9)
                    painter.setFont(f)
                    painter.drawText(rect, 0, msg)
            except Exception:
                pass

        _SplashScr.drawContents = _patched_draw

        # showMessage 패치 (2026-05-25 v7): 1줄 고정 + 그 아래 1줄 rolling update.
        # 첫 1개 메시지(예: "Orange 3.39.0") 는 상단에 고정 표시.
        # 이후 모든 메시지("Add-ons" 헤더·각 add-on)는 두 번째 줄에서 매번 덮어씀.
        # → 리스트가 위로 스크롤하지 않고 같은 자리에서만 갱신.
        _fixed_lines: list[str] = []      # 상단 1줄 고정 (버전)
        _rolling_line: list[str] = [""]   # 그 아래 1줄 — 매번 새 메시지로 교체
        _orig_show_msg2 = _SplashScr.showMessage

        def _patched_show_msg2(self, message, *a, **kw):
            try:
                if isinstance(message, str) and message.strip():
                    if "\n" in message:
                        lines = [ln for ln in message.split("\n") if ln.strip()]
                        display = "\n".join(lines[:2])
                    else:
                        if len(_fixed_lines) < 1:
                            _fixed_lines.append(message)
                            _rolling_line[0] = ""
                        else:
                            # 두 번째 줄을 그대로 덮어씀 (스크롤 아닌 in-place 갱신)
                            _rolling_line[0] = message
                        display = _fixed_lines[0]
                        if _rolling_line[0]:
                            display += "\n" + _rolling_line[0]
                    return _orig_show_msg2(self, display, *a, **kw)
            except Exception:
                pass
            return _orig_show_msg2(self, message, *a, **kw)

        _SplashScr.showMessage = _patched_show_msg2
        print("[launcher] SplashScreen 고정1+순환1 in-place 패치 적용", flush=True)
    except Exception as _bg_err:
        print(f"[launcher] scene background 패치 실패: {_bg_err}", flush=True)

    # ── 캔버스 노드 툴팁을 사이드바 패널 위젯 툴팁과 동일하게 통일 (2026-05-24) ──
    # 사이드바 _hwdBuildRichTip 형식 매칭:
    #   <b>name</b> <span pkg>(from project)</span>
    #   <div desc>설명</div>
    #   Inputs: <ul><li>name <span type>(type)</span></li></ul>   ← 있을 때만
    #   Outputs: <ul>...</ul>                                       ← 있을 때만
    # 차이점 (기존 tooltip_helper 와 비교):
    #   - <hr/> 가로선 제거 (이미지2 깔끔한 룩)
    #   - "No inputs" / "No outputs" 라벨 제거 (비어있으면 섹션 자체 생략)
    #   - inline style 사용 (Qt QToolTip 은 CSS class 지원 제한적)
    try:
        from orangecanvas.canvas.items import nodeitem as _ni        # type: ignore
        from orangecanvas.registry.qt import type_str as _type_str    # type: ignore
        from html import escape as _html_escape

        def _build_sidebar_style_tooltip(desc):
            name = _html_escape(getattr(desc, "name", "") or "")
            project = getattr(desc, "project_name", "") or ""
            description = getattr(desc, "description", "") or ""
            parts = []
            title = f'<b>{name}</b>'
            if project:
                title += (' <span style="color:#9ca3af;font-weight:500;">'
                          f'(from {_html_escape(project)})</span>')
            parts.append(f'<div style="margin-bottom:6px;">{title}</div>')
            if description:
                parts.append(
                    '<div style="color:#374151;margin-bottom:8px;line-height:1.45;">'
                    f'{_html_escape(description)}</div>'
                )
            def _sig_html(items):
                # bullet "•" 직접 prefix — text-indent 트릭 제거 (bullet 안 보이는 버그 fix).
                # 단순 padding-left 만 사용. bullet 이 항상 텍스트 앞에 표시됨.
                rows = []
                for it in items:
                    nm = _html_escape(getattr(it, "name", "") or "")
                    try:
                        tp = _type_str(getattr(it, "types", ()) or ())
                    except Exception:
                        tp = ""
                    if tp:
                        rows.append(
                            f'<div style="font-weight:normal;padding-left:8px;">'
                            f'• {nm} <span style="color:#9ca3af;">'
                            f'({_html_escape(tp)})</span></div>'
                        )
                    else:
                        rows.append(
                            f'<div style="font-weight:normal;padding-left:8px;">'
                            f'• {nm}</div>'
                        )
                return "".join(rows)
            inputs = getattr(desc, "inputs", None) or []
            if inputs:
                parts.append(
                    '<div style="margin-top:4px;"><b>Inputs:</b></div>'
                    + _sig_html(inputs)
                )
            outputs = getattr(desc, "outputs", None) or []
            if outputs:
                parts.append(
                    '<div style="margin-top:4px;"><b>Outputs:</b></div>'
                    + _sig_html(outputs)
                )
            return ('<html><body style="font-family:\'Segoe UI\',\'Malgun Gothic\','
                    '\'맑은 고딕\',sans-serif;'
                    'font-size:10px;font-weight:normal;color:#1a1a1c;line-height:1.45;">'
                    + "".join(parts) + '</body></html>')

        def _patched_node_tooltip(node, links_in=None, links_out=None):
            try:
                return _build_sidebar_style_tooltip(node.widget_description)
            except Exception:
                return _orig_node_tooltip(node, links_in or [], links_out or [])

        _orig_node_tooltip = _ni.NodeItem_toolTipHelper
        _ni.NodeItem_toolTipHelper = _patched_node_tooltip
        print("[launcher] NodeItem 툴팁 → 사이드바 위젯 패널 포맷 (no hr, no empty sections)", flush=True)
    except Exception as _tt_err:
        print(f"[launcher] NodeItem 툴팁 통일 패치 실패: {_tt_err}", flush=True)

    # ── 캔버스 노드 풍선 툴팁 위젯 — 사이드바 #hwd-tip 과 동일한 좌측 tail (2026-05-25) ──
    # Qt QToolTip 은 ::before / pseudo-element 미지원이라 stylesheet 만으로는 풍선 꼬리
    # (이미지 2 모양) 가 불가능. NodeItem.hoverEnterEvent / hoverLeaveEvent 를 hook 하여
    # 풍선 모양을 직접 QPainter 로 그리는 커스텀 QFrame 을 표시한다.
    #   - 좌측 tail 12px, body radius 18px, padding 12px
    #   - background:#fff, border:1px #e5e7eb, soft shadow (다층 stroke)
    # 일반 위젯 다이얼로그 내 hover 는 기존 QToolTip 그대로 유지 (스코프 한정).
    try:
        from orangecanvas.canvas.items.nodeitem import NodeItem as _NI2  # type: ignore
        from PyQt5.QtCore import Qt as _Qt, QPoint as _QPoint, QRectF as _QRectF, QPointF as _QPF
        from PyQt5.QtGui import (QPainter as _QP, QPainterPath as _QPath,
                                  QColor as _QCol, QPen as _QPen, QBrush as _QBr)
        from PyQt5.QtWidgets import (QFrame as _QFrame, QLabel as _QLbl,
                                      QVBoxLayout as _QVBox)

        class _BalloonTip(_QFrame):
            def __init__(self):
                super().__init__(None,
                    _Qt.ToolTip | _Qt.FramelessWindowHint | _Qt.NoDropShadowWindowHint)
                # xpra HTML5 는 ARGB transparent 미지원 → opaque 흰 배경 강제.
                # 캔버스 scene 배경도 흰색(SchemeEditWidget patch) 이므로 widget
                # 사각형 외곽이 캔버스에 자연스럽게 녹아들어 안 보임.
                self.setAttribute(_Qt.WA_ShowWithoutActivating)
                self.setAutoFillBackground(True)
                self.setStyleSheet("QFrame{background:#ffffff;border:none;}")
                # 컴팩트 사이즈 — tail 을 상단 (좌측 부근) 으로 (2026-05-27 v4)
                # 풍선은 위젯 우측-아래 방향에 배치 → tail 이 상단 좌측에서 위젯을 가리킴.
                self._tail_w = 14   # tail 밑변 (가로)
                self._tail_h = 10   # tail 돌출 (세로)
                self._radius = 10
                self._pad_x = 12
                self._pad_y = 8
                self._shadow = 0
                # tail 의 가로 위치 보정 — 0 = 중앙, 음수 = 좌, 양수 = 우.
                self._tail_x_offset = 0
                self._label = _QLbl(self)
                self._label.setTextFormat(_Qt.RichText)
                self._label.setWordWrap(True)
                self._label.setStyleSheet(
                    "color:#1a1a1c;"
                    " font-family:'Segoe UI','Malgun Gothic','맑은 고딕',sans-serif;"
                    " font-size:10px; font-weight:normal;"
                    " background:transparent;"
                )
                lay = _QVBox(self)
                # margins: 상단에 tail 영역 확보, 좌/우/하는 일반 padding
                lay.setContentsMargins(
                    self._pad_x + self._shadow,
                    self._tail_h + self._pad_y,         # 상: tail+padding
                    self._pad_x + self._shadow,
                    self._pad_y + self._shadow,
                )
                lay.setSpacing(0)
                lay.addWidget(self._label)
                # 너비 확장 (2026-05-25) — "Data Subset (Orange.data.table.Table)"
                # 같은 줄이 두 줄로 wrap 되지 않도록 380px 까지.
                self._label.setMaximumWidth(380)
                self._label.setMinimumWidth(240)

            def setText(self, html: str):
                self._label.setText(html or "")
                # label content 기반 size 재계산 — Qt 의 layout 재실행 강제
                self._label.adjustSize()
                self.layout().activate()
                self.adjustSize()
                # 풍선이 너무 작거나 너무 크지 않도록 최소/최대 size 강제
                w = max(self.width(), 220)
                h = max(self.height(), 60)
                self.resize(w, h)
                self.update()  # paintEvent 재호출 보장

            def paintEvent(self, event):
                p = _QP(self)
                p.setRenderHint(_QP.Antialiasing)
                # body 영역 — 상단에 tail 영역 확보, body 는 그 아래.
                s = self._shadow
                body = _QRectF(
                    s, self._tail_h,
                    self.width() - 2 * s,
                    self.height() - s - self._tail_h,
                )
                # tail (상단, 위쪽 삼각형) — _tail_x_offset 으로 가로 위치 조정
                tail_cx = body.center().x() + getattr(self, "_tail_x_offset", 0)
                _min_cx = body.x() + self._radius + self._tail_w / 2
                _max_cx = body.right() - self._radius - self._tail_w / 2
                if tail_cx < _min_cx: tail_cx = _min_cx
                if tail_cx > _max_cx: tail_cx = _max_cx

                path = _QPath()
                # 좌상단 corner 시작
                path.moveTo(body.x() + self._radius, body.y())
                # 상단 라인 → tail 왼쪽 baseline → tail 뾰족점 → tail 오른쪽 baseline → 상단 우측
                path.lineTo(tail_cx - self._tail_w / 2, body.y())
                path.lineTo(tail_cx, body.y() - self._tail_h)
                path.lineTo(tail_cx + self._tail_w / 2, body.y())
                path.lineTo(body.right() - self._radius, body.y())
                # 우상단 corner → 우측 → 우하단 corner
                path.quadTo(body.right(), body.y(), body.right(), body.y() + self._radius)
                path.lineTo(body.right(), body.bottom() - self._radius)
                path.quadTo(body.right(), body.bottom(), body.right() - self._radius, body.bottom())
                # 하단 → 좌하단 corner → 좌측 → 좌상단 corner
                path.lineTo(body.x() + self._radius, body.bottom())
                path.quadTo(body.x(), body.bottom(), body.x(), body.bottom() - self._radius)
                path.lineTo(body.x(), body.y() + self._radius)
                path.quadTo(body.x(), body.y(), body.x() + self._radius, body.y())
                path.closeSubpath()
                p.setBrush(_QBr(_QCol(255, 255, 255)))
                p.setPen(_QPen(_QCol(190, 195, 205), 1.2))
                p.drawPath(path)

        _balloon_holder = {"tip": None}

        # NodeItem.setToolTip 가로채기 — HTML 은 node._balloon_html 에 저장,
        # 진짜 Qt toolTip 은 빈 문자열로 set → Qt 기본 QToolTip 표시 안 됨.
        # (사용자가 노드 hover 시 두 개의 풍선이 동시에 뜨는 문제 해결)
        _orig_set_tt = _NI2.setToolTip
        def _patched_set_tt(self, text):
            try:
                self._balloon_html = text or ""
            except Exception:
                pass
            return _orig_set_tt(self, "")
        _NI2.setToolTip = _patched_set_tt

        # 풍선 기준점: 노드 라벨 위치 (2026-05-25 v4)
        # sceneBoundingRect 의 bottom 근처(라벨 영역) 를 기준으로 함.
        # 풍선 중심이 라벨 y 좌표에 위치 → offset 0, tail 중앙.
        _BALLOON_Y_OFFSET = 0
        try:
            _balloon_holder.get("tip")  # noqa
        except Exception:
            pass

        def _show_balloon(node, evt):
            try:
                html = getattr(node, "_balloon_html", None)
                if not html:
                    html = node.toolTip() or ""
                if not html:
                    return
                tip = _balloon_holder["tip"]
                if tip is None:
                    tip = _BalloonTip()
                    _balloon_holder["tip"] = tip
                tip.setText(html)
                # 위젯 정중앙 아래 배치 (2026-05-27 v5) — tail 중앙 정렬.
                # 풍선 가로 중심을 위젯 라벨 중심 X 에 일치 → tail 뾰족점이
                # 위젯 정중앙 위쪽을 가리킴.
                scene = node.scene()
                views = scene.views() if scene else []
                if views:
                    view = views[0]
                    sb = node.sceneBoundingRect()
                    # 노드 가운데 X + label bottom 의 글로벌 좌표
                    pt_center_bottom = view.mapFromScene(_QPF(sb.center().x(), sb.bottom()))
                    g_cb = view.viewport().mapToGlobal(pt_center_bottom)
                    # tail 중앙 정렬 → 풍선 좌상단 X = 위젯 center - 풍선 가로 / 2
                    tip._tail_x_offset = 0
                    x = g_cb.x() - tip.width() // 2
                    y = g_cb.y() + 4
                    tip.move(x, y)
                else:
                    tip._tail_x_offset = 0
                    tip.move(0, 0)
                tip.show()
                tip.raise_()
            except Exception:
                pass

        def _hide_balloon():
            try:
                tip = _balloon_holder.get("tip")
                if tip is not None:
                    tip.hide()
            except Exception:
                pass

        _orig_hover_enter = _NI2.hoverEnterEvent
        _orig_hover_leave = _NI2.hoverLeaveEvent
        _orig_ni_init = _NI2.__init__

        # hover 지연 상태 (2026-05-26) — 풍선이 즉시 뜨면 지저분해 보임. 2초간
        # hover 유지된 경우에만 표시. leave 시 타이머 취소.
        from PyQt5.QtCore import QTimer as _QTimerBalloon  # type: ignore
        _hover_state: dict = {"timer": None, "node": None}
        _HOVER_DELAY_MS = 2000

        def _patched_init(self, *a, **kw):
            _orig_ni_init(self, *a, **kw)
            try:
                # hoverEnterEvent 가 호출되려면 반드시 hover 이벤트 수용 필요
                self.setAcceptHoverEvents(True)
            except Exception:
                pass

        def _patched_enter(self, event):
            try:
                # 기존 타이머 취소 (다른 노드 hover 중인 경우)
                _prev_t = _hover_state.get("timer")
                if _prev_t is not None:
                    try: _prev_t.stop()
                    except Exception: pass
                _hover_state["node"] = self
                # 2초 후 풍선 표시 — 그때까지 같은 노드 hover 중이어야 함
                _node_ref = self
                _ev_ref = event
                def _delayed_show():
                    try:
                        if _hover_state.get("node") is _node_ref:
                            _show_balloon(_node_ref, _ev_ref)
                    except Exception:
                        pass
                _new_t = _QTimerBalloon()
                _new_t.setSingleShot(True)
                _new_t.timeout.connect(_delayed_show)
                _new_t.start(_HOVER_DELAY_MS)
                _hover_state["timer"] = _new_t
            except Exception as _ee:
                print(f"[launcher] balloon timer err: {_ee}", flush=True)
            return _orig_hover_enter(self, event)

        def _patched_leave(self, event):
            try:
                # 타이머 취소 → 풍선 표시 자체를 막음
                _t = _hover_state.get("timer")
                if _t is not None:
                    try: _t.stop()
                    except Exception: pass
                    _hover_state["timer"] = None
                _hover_state["node"] = None
                _hide_balloon()
            except Exception:
                pass
            return _orig_hover_leave(self, event)

        _NI2.__init__ = _patched_init
        _NI2.hoverEnterEvent = _patched_enter
        _NI2.hoverLeaveEvent = _patched_leave
        print("[launcher] NodeItem 풍선(tail) 툴팁 위젯 적용 + setAcceptHoverEvents 보장", flush=True)

        # 전역 ToolTip 가로채기 제거 (2026-05-25) — QComboBox/버튼 등 위젯
        # 다이얼로그 안 hover 시 파일 경로 같은 plain text 가 풍선으로 표시되는
        # 불필요한 노출 차단. 캔버스 NodeItem hover 만 _BalloonTip 사용, 그 외엔
        # Qt 기본 QToolTip (사이드바 톤 흰 박스 스타일) 으로 표시.
        print("[launcher] 풍선 툴팁: 캔버스 NodeItem 한정 (위젯 다이얼로그는 Qt 기본)", flush=True)

        # QComboBox ToolTip 차단 (2026-05-25) — File 위젯의 datasets 선택 콤보가
        # 현재 선택된 파일의 전체 경로(`/usr/local/.../iris.tab`)를 Qt 기본 툴팁
        # 으로 표시하는 것을 막음. eventFilter 로 QComboBox 및 그 자식의 ToolTip
        # 이벤트만 가로채서 차단.
        from PyQt5.QtCore import QObject as _QObj2, QEvent as _QEv2
        from PyQt5.QtWidgets import QComboBox as _QComboBoxCls

        class _ComboTipBlocker(_QObj2):
            def eventFilter(self, obj, event):
                try:
                    if event.type() == _QEv2.ToolTip:
                        w = obj
                        for _ in range(6):  # 자식 → 부모 6단계까지 검색
                            if isinstance(w, _QComboBoxCls):
                                return True  # ToolTip 이벤트 차단
                            if w is None or not hasattr(w, "parent"):
                                break
                            w = w.parent()
                except Exception:
                    pass
                return False

        _combo_blk = _ComboTipBlocker()
        QApplication.instance().installEventFilter(_combo_blk)
        globals()["_combo_tip_blocker_instance"] = _combo_blk  # GC 방지
        print("[launcher] QComboBox 툴팁 차단 적용", flush=True)
    except Exception as _bt_err:
        import traceback as _tb_bt
        print(f"[launcher] NodeItem 풍선 툴팁 패치 실패: {_bt_err}", flush=True)
        _tb_bt.print_exc()

    # ── 6. 메뉴바 + 왼쪽 위젯 독 영구 숨기기 (단계 4: HTML 사이드바가 대체) ──
    # UserAdviceMessages 전역 무력화 (2026-05-28 v2) — 모든 위젯의 안내 팝업 차단
    # canvas 는 위젯 클래스의 UserAdviceMessages 속성을 직접 조회 → 클래스 자체를 비워야 함.
    # 추가로 인스턴스에도 빈 목록 강제 + insert_message 메서드도 no-op 패치.
    try:
        from orangewidget.widget import OWBaseWidget as _OWB  # type: ignore
        # 1) 부모 클래스의 클래스 속성 비움
        try:
            _OWB.UserAdviceMessages = []
        except Exception:
            pass
        # 2) 모든 기존 서브클래스 (위젯들) 의 클래스 속성도 비움 — 부모 변경이
        #    이미 자체 정의한 서브클래스에는 영향 안 가므로 강제 순회.
        def _clear_all_subclass_advice(cls):
            try:
                cls.UserAdviceMessages = []
            except Exception:
                pass
            for sub in cls.__subclasses__():
                _clear_all_subclass_advice(sub)
        _clear_all_subclass_advice(_OWB)
        # 3) __init__ 도 패치하여 향후 동적 정의 위젯에도 적용
        _orig_init = _OWB.__init__
        def _patched_init(self, *args, **kwargs):
            # 인스턴스 생성 직전 클래스 속성도 한 번 더 클리어 (혹시 모를 늦은 정의 대응)
            try:
                type(self).UserAdviceMessages = []
            except Exception:
                pass
            result = _orig_init(self, *args, **kwargs)
            try:
                self.UserAdviceMessages = []
            except Exception:
                pass
            return result
        _OWB.__init__ = _patched_init
        # 4) __quicktipOnce + __quicktip 자체를 no-op 으로 — 최종 안전망.
        # name-mangling 때문에 _OWBaseWidget__quicktipOnce 등으로 접근해야 함.
        for _attr in ('_OWBaseWidget__quicktipOnce', '_OWBaseWidget__quicktip',
                      '_OWBaseWidget__showMessage'):
            if hasattr(_OWB, _attr):
                try:
                    setattr(_OWB, _attr, lambda *a, **kw: None)
                except Exception:
                    pass
        print("[launcher] UserAdviceMessages 전역 무력화 v2 적용", flush=True)
    except Exception as _e:
        print(f"[launcher] UserAdviceMessages 패치 실패: {_e}", flush=True)

    # 방법 A: CanvasMainWindow.setup_ui 패치 — 창 생성 시점에 즉시 숨김
    try:
        from orangecanvas.application.canvasmain import CanvasMainWindow as _CMW2  # type: ignore

        if hasattr(_CMW2, 'setup_ui'):
            _orig_su = _CMW2.setup_ui

            def _su_patched(self):
                _orig_su(self)
                # 상단 메뉴바 숨김
                try:
                    mb = self.menuBar()
                    mb.setMaximumHeight(0)
                    mb.hide()
                except Exception:
                    pass
                # 단계 4: 왼쪽 위젯 독 (CollapsibleDockWidget) 숨김
                try:
                    dw = getattr(self, 'dock_widget', None)
                    if dw is not None:
                        dw.setVisible(False)
                        dw.setMaximumWidth(0)
                except Exception:
                    pass

            _CMW2.setup_ui = _su_patched
            print("[launcher] CanvasMainWindow.setup_ui 메뉴바+위젯독 숨김 패치 적용", flush=True)
    except Exception as _pe:
        print(f"[launcher] 메뉴바 클래스 패치 실패: {_pe}", flush=True)

    # 방법 B: 이벤트 루프에서 2초마다 지속 확인 — 메뉴바·위젯독 재노출 즉시 재숨김
    def _try_hide_ui():
        from PyQt5.QtWidgets import QApplication as _QApp  # type: ignore
        app = _QApp.instance()
        if app is not None:
            for w in app.topLevelWidgets():
                if not w.isVisible():
                    continue
                # 메뉴바
                if hasattr(w, 'menuBar'):
                    try:
                        mb = w.menuBar()  # type: ignore[union-attr]
                        if mb.isVisible() or mb.maximumHeight() > 0:
                            mb.setMaximumHeight(0)
                            mb.hide()
                            print("[launcher] 메뉴바 숨김", flush=True)
                    except Exception:
                        pass
                # 위젯 독 (dock_widget)
                dw = getattr(w, 'dock_widget', None)
                if dw is not None:
                    try:
                        if dw.isVisible() or dw.maximumWidth() > 0:
                            dw.setVisible(False)
                            dw.setMaximumWidth(0)
                            print("[launcher] 위젯 독 숨김", flush=True)
                    except Exception:
                        pass
        QTimer.singleShot(2000, _try_hide_ui)

    QTimer.singleShot(1000, _try_hide_ui)

    # ── 7. Orange3 실행 (기존 CanvasApplication 재사용) ──────────────────────
    # Splash screen 비노출 — wrapper(/session-manager) 가 좌하단 텍스트로 로딩
    # 상태를 자체 표시. 콜드스타트 시 Orange 캐릭터 splash 이미지가 새 탭에
    # 노출되던 케이스(가끔) 차단 (Phase 5, 2026-05-24).
    if "--no-splash" not in sys.argv:
        sys.argv.append("--no-splash")
    from Orange.canvas.__main__ import main as orange_main       # type: ignore
    rv = orange_main()
    # exit code 96 을 startapp.sh 루프에 올바르게 전달 (반환값 무시 시 0으로 종료되어 루프 break)
    sys.exit(rv if rv is not None else 0)


if __name__ == "__main__":
    main()
