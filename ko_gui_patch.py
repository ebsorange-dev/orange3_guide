"""
Korean GUI label patch for orange3-text and orange3-timeseries add-on packages.

Intercepts orangewidget.gui function calls and translates string labels
when the application language is set to Korean.

This module must be imported before Orange3 starts (in orange3_launcher.py).
"""
import os
import configparser

# ── 언어 확인 ──────────────────────────────────────────────────────────────
def _get_language():
    xdg = os.environ.get('XDG_CONFIG_HOME', os.path.expanduser('~/.config'))
    ini = os.path.join(xdg, 'biolab.si', 'Orange.ini')
    cfg = configparser.ConfigParser()
    cfg.read(ini)
    return cfg.get('application', 'language', fallback='English')


# ── 한국어 번역 사전 ────────────────────────────────────────────────────────
# 텍스트 마이닝 + 시계열 + 공통 위젯 UI 문자열
_KO = {
    # ── 공통 ────────────────────────────────────────────────────────────────
    "Apply": "적용",
    "Cancel": "취소",
    "Commit": "확정",
    "Send": "전송",
    "Send data": "데이터 전송",
    "OK": "확인",
    "Settings": "설정",
    "Info": "정보",
    "Input": "입력",
    "Output": "출력",
    "Output:": "출력:",
    "Start": "시작",
    "Stop": "정지",
    "Filter": "필터",
    "Filtering": "필터링",
    "Method": "방법",
    "Parameters": "매개변수",
    "Display": "표시",
    "Preview": "미리 보기",
    "Search": "검색",
    "Source": "소스",
    "Language": "언어",
    "Language:": "언어:",
    "Pattern": "패턴",
    "Pattern:": "패턴:",
    "Feature": "속성",
    "Attribute:": "속성:",
    "Relevance": "관련성",
    "Threshold": "임계값",
    "Threshold:": "임계값:",
    "Frequency": "빈도",
    "Distance threshold": "거리 임계값",
    "Distances": "거리",
    "Library": "라이브러리",
    "Auto commit is on": "자동 확정 켜짐",
    "Auto send is on": "자동 전송 켜짐",

    # ── 텍스트 마이닝 ────────────────────────────────────────────────────────
    "Abstract": "초록",
    "Add a new word list to the library": "라이브러리에 새 단어 목록 추가",
    "Add document": "문서 추가",
    "Aggregation": "집계",
    "Aggregator:": "집계기:",
    "Annotation": "주석",
    "Article API Key": "기사 API 키",
    "Article title": "기사 제목",
    "Articles per query:": "쿼리당 기사 수:",
    "Author:": "저자:",
    "Authors": "저자",
    "Axes": "축",
    "Axis x:": "X 축:",
    "Axis y:": "Y 축:",
    "Bearer Token": "Bearer 토큰",
    "Browse documentation corpora": "문서 말뭉치 탐색",
    "Cloud preferences": "클라우드 설정",
    "Color points by cluster": "클러스터별 색상 표시",
    "Color words": "단어 색상",
    "Compute for": "계산 대상",
    "Conllu import options": "CoNLL-U 가져오기 옵션",
    "Copy word list from library": "라이브러리에서 단어 목록 복사",
    "Corpus file": "말뭉치 파일",
    "Corpus settings": "말뭉치 설정",
    "Display features": "표시 속성",
    "Document Frequency:": "문서 빈도:",
    "Document text": "문서 텍스트",
    "Document title": "문서 제목",
    "Email": "이메일",
    "Emotions:": "감정:",
    "FDR": "FDR",
    "FDR threshold:": "FDR 임계값:",
    "Filter by word FDR": "단어 FDR로 필터",
    "Filter by word p-value": "단어 p값으로 필터",
    "Find records": "레코드 찾기",
    "Frequency Threshold": "빈도 임계값",
    "From:": "시작:",
    "Ignored text features": "무시된 텍스트 속성",
    "Include selected words into the ontology": "선택한 단어를 온톨로지에 추가",
    "Include subtree": "하위 트리 포함",
    "Lemma": "표제어",
    "Linkage": "연결 방법",
    "Map type:": "지도 유형:",
    "Max p-value for word": "단어 최대 p값",
    "Mesh headings": "MeSH 표제어",
    "NER": "개체명 인식",
    "Negative:": "부정:",
    "Node type": "노드 유형",
    "Number of words:": "단어 수:",
    "Ontology info": "온톨로지 정보",
    "POS tags": "품사 태그",
    "Performs a search for articles that fit the specified parameters.":
        "지정한 매개변수에 맞는 기사를 검색합니다.",
    "Positive:": "긍정:",
    "Query": "쿼리",
    "Query word list:": "쿼리 단어 목록:",
    "Query:": "쿼리:",
    "RegExp Filter:": "정규식 필터:",
    "Region attribute:": "지역 속성:",
    "Regularization:": "정규화:",
    "Remove word list from library": "라이브러리에서 단어 목록 제거",
    "Restore Original Order": "원래 순서로 복원",
    "Retrieve": "검색",
    "Retrieve records": "레코드 검색",
    "Retrieves the specified documents.": "지정된 문서를 검색합니다.",
    "Save changes in the editor to library": "편집기 변경사항을 라이브러리에 저장",
    "Scoring Method": "점수화 방법",
    "Scoring Methods": "점수화 방법들",
    "Search features": "검색 속성",
    "Select Documents": "문서 선택",
    "Select Words": "단어 선택",
    "Set the API key for this widget.": "이 위젯의 API 키를 설정하세요.",
    "Show Tokens && Tags": "토큰 && 태그 표시",
    "Show cluster hull": "클러스터 외곽 표시",
    "Show rows in the original order": "행을 원래 순서로 표시",
    "Sort words alphabetically": "단어 알파벳순 정렬",
    "Stop retrieving": "검색 정지",
    "Term Frequency:": "용어 빈도:",
    "Text includes": "텍스트 포함",
    "The Guardian API Key": "가디언 API 키",
    "Title variable": "제목 변수",
    "Topic evaluation": "주제 평가",
    "Twitter API Key": "트위터 API 키",
    "URL": "URL",
    "URL:": "URL:",
    "Used text features": "사용된 텍스트 속성",
    "Window size": "창 크기",
    "Word Scoring Methods": "단어 점수화 방법",
    "Word variable:": "단어 변수:",
    "Words && weights": "단어 && 가중치",
    "Words displayed: 0": "표시된 단어: 0",
    # format templates
    "Articles: %(output_info)s": "기사: %(output_info)s",
    "Documents: %(n_documents)s": "문서: %(n_documents)s",
    "Matching documents: %(n_matching)s": "일치 문서: %(n_matching)s",
    "Matching: %(n_matching)s": "일치: %(n_matching)s",
    "Matches: %(n_matches)s": "일치: %(n_matches)s",
    "Tokens: %(n_tokens)s": "토큰: %(n_tokens)s",
    "Types: %(n_types)s": "유형: %(n_types)s",
    "Topic coherence: %(coherence)s": "주제 응집도: %(coherence)s",
    "Log perplexity: %(perplexity)s": "로그 복잡도: %(perplexity)s",
    "Number of records found: /": "발견된 레코드 수: /",
    "Number of records retrieved: /": "검색된 레코드 수: /",
    "◦ duplicates: %(n_duplicates)s": "◦ 중복: %(n_duplicates)s",
    "◦ unique: %(n_unique)s": "◦ 고유: %(n_unique)s",

    # ── 시계열 ──────────────────────────────────────────────────────────────
    "&Apply": "&적용",
    "&Test": "&검정",
    "Add plot": "플롯 추가",
    "Aggregation Type": "집계 유형",
    "Assume zeros before start": "시작 전 0 가정",
    "Block width:": "블록 너비:",
    "Color": "색상",
    "Compute partial auto-correlation": "편자기상관 계산",
    "Confidence:": "신뢰도:",
    "Custom step size:": "사용자 정의 간격:",
    "Download": "다운로드",
    "Evaluation Parameters": "평가 매개변수",
    "Forecast steps:": "예측 단계:",
    "Granger Test": "그레인저 검정",
    "Hide inner labels": "내부 레이블 숨기기",
    "If not chosen, the active interval moves forward (backward), stepping in increments of its own size.":
        "선택 안 하면 활성 구간이 자체 크기 단위로 앞(뒤)으로 이동합니다.",
    "In milliseconds, set the delay for playback and for sending data upon manually moving the interval.":
        "재생 지연과 수동 구간 이동 시 데이터 전송 지연을 밀리초 단위로 설정합니다.",
    "Invert differencing direction": "차분 방향 반전",
    "Loop playback": "반복 재생",
    "Max lag:": "최대 시차:",
    "Maximum auto-regression order:": "최대 자기회귀 차수:",
    "Multi-variate interpolation": "다변량 보간",
    "Number of folds:": "폴드 수:",
    "Operation": "연산",
    "Playback/Tracking interval": "재생/추적 간격",
    "Plot 95% significance interval": "95% 유의구간 표시",
    "Radial": "방사형",
    "Select a Time Range": "시간 범위 선택",
    "Sets the distance between points; 1 for consecutive points":
        "점 간격 설정; 1은 연속 점",
    "Shift:": "이동:",
    "Show only numeric variables": "수치 변수만 표시",
    "Start:": "시작:",
    "Step/Play Through": "단계/연속 재생",
    "Step:": "단계:",
    "Test": "검정",
    "The expected length of full cycle. E.g., if you have monthly data and the apparent season repeats every year, you put in 12.":
        "전체 주기의 예상 길이. 예: 월별 데이터에서 계절이 매년 반복되면 12를 입력합니다.",
    "Time Period": "시간 주기",
    "Type:": "유형:",
    "Variable:": "변수:",
    "Window width:": "창 너비:",
}


def _tr(s):
    """Translate a string if Korean, otherwise return as-is."""
    if isinstance(s, str):
        return _KO.get(s, s)
    return s


def _tr_list(items):
    """Translate a list/tuple of strings."""
    if isinstance(items, (list, tuple)):
        return type(items)(_tr(i) if isinstance(i, str) else i for i in items)
    return items


def install_korean_patches():
    """Patch orangewidget.gui functions to translate labels for Korean."""
    if _get_language() != 'Korean':
        return

    try:
        import orangewidget.gui as gui
    except ImportError:
        return

    # ── checkBox(widget, master, value, label, box, callback, ...) ───────
    _orig_checkBox = gui.checkBox
    def _checkBox(widget, master, value, label='', box=None, *args, **kw):
        return _orig_checkBox(widget, master, value, _tr(label), box, *args, **kw)
    gui.checkBox = _checkBox

    # ── button(widget, master, label, ...) ───────────────────────────────
    _orig_button = gui.button
    def _button(widget, master, label='', *args, **kw):
        return _orig_button(widget, master, _tr(label), *args, **kw)
    gui.button = _button

    # ── label(widget, master, label, ...) ────────────────────────────────
    _orig_label = gui.label
    def _label(widget, master, label='', *args, **kw):
        return _orig_label(widget, master, _tr(label), *args, **kw)
    gui.label = _label

    # ── widgetLabel(widget, label, labelWidth, ...) ───────────────────────
    _orig_widgetLabel = gui.widgetLabel
    def _widgetLabel(widget, label='', *args, **kw):
        return _orig_widgetLabel(widget, _tr(label), *args, **kw)
    gui.widgetLabel = _widgetLabel

    # ── spin(widget, master, value, minv, maxv, step, box, label, ...) ───
    _orig_spin = gui.spin
    def _spin(widget, master, value, minv, maxv, step=1, box=None, label=None, *args, **kw):
        return _orig_spin(widget, master, value, minv, maxv, step, box, _tr(label) if label else label, *args, **kw)
    gui.spin = _spin

    # ── doubleSpin ───────────────────────────────────────────────────────
    _orig_doubleSpin = gui.doubleSpin
    def _doubleSpin(widget, master, value, minv, maxv, step=1, box=None, label=None, *args, **kw):
        return _orig_doubleSpin(widget, master, value, minv, maxv, step, box, _tr(label) if label else label, *args, **kw)
    gui.doubleSpin = _doubleSpin

    # ── comboBox(widget, master, value, box, label, labelWidth, ...) ─────
    _orig_comboBox = gui.comboBox
    def _comboBox(widget, master, value, box=None, label=None, *args, **kw):
        # translate items list if present as keyword
        items = kw.pop('items', None)
        if items is not None:
            kw['items'] = _tr_list(items)
        return _orig_comboBox(widget, master, value, box, _tr(label) if label else label, *args, **kw)
    gui.comboBox = _comboBox

    # ── radioButtonsInBox(widget, master, value, btnLabels, ...) ─────────
    _orig_radioButtonsInBox = gui.radioButtonsInBox
    def _radioButtonsInBox(widget, master, value, btnLabels=(), tooltips=None,
                           box=None, label=None, *args, **kw):
        return _orig_radioButtonsInBox(
            widget, master, value, _tr_list(btnLabels), tooltips,
            box, _tr(label) if label else label, *args, **kw)
    gui.radioButtonsInBox = _radioButtonsInBox

    # ── lineEdit(widget, master, value, label, ...) ───────────────────────
    _orig_lineEdit = gui.lineEdit
    def _lineEdit(widget, master, value, label=None, *args, **kw):
        return _orig_lineEdit(widget, master, value, _tr(label) if label else label, *args, **kw)
    gui.lineEdit = _lineEdit

    # ── auto_commit(widget, master, value, label, auto_label, ...) ────────
    _orig_auto_commit = gui.auto_commit
    def _auto_commit(widget, master, value, label, auto_label=None, *args, **kw):
        return _orig_auto_commit(widget, master, value, _tr(label),
                                 _tr(auto_label) if auto_label else auto_label, *args, **kw)
    gui.auto_commit = _auto_commit

    print("[ko_gui_patch] 한국어 GUI 레이블 패치 적용 완료", flush=True)
