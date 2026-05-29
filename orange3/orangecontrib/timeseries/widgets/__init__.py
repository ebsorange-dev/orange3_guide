from orangecanvas.utils.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.timeseries", "biolab.si", "Orange")
del Translator
# Category metadata.

NAME = _tr.m[2, "Time Series"]

# Category icon show in the menu
ICON = "icons/LineChart.svg"

# Background color for category background in menu
# and widget icon background in workflow.
BACKGROUND = "#33aaff"

# Location of widget help files.
WIDGET_HELP_PATH = (
    ("{DEVELOP_ROOT}/doc/_build/html/index.html", None),
    ("http://orange3-timeseries.readthedocs.io/en/latest/", ""),
)

# Korean widget name translations
_WIDGET_NAMES_KO = {
    "ARIMA Model": "ARIMA 모델",
    "Correlogram": "상관도",
    "Difference": "차분",
    "Granger Causality": "그레인저 인과관계",
    "Interpolate": "보간",
    "Line Chart": "선 그래프",
    "Model Evaluation": "모델 평가",
    "Moving Transform": "이동 변환",
    "Periodogram": "주기도",
    "Seasonal Adjustment": "계절 조정",
    "Spiralogram": "나선도",
    "Form Timeseries": "시계열 만들기",
    "Time Slice": "시간 슬라이스",
    "VAR Model": "VAR 모델",
    "Yahoo Finance": "야후 파이낸스",
}

# Korean widget description (tooltip) translations — 2026-05-21 추가
_WIDGET_DESC_KO = {
    "ARIMA Model": "ARMA, ARIMA 또는 ARIMAX로 시계열을 모델링합니다.",
    "Correlogram": "변수의 자기상관을 시각화합니다.",
    "Difference": "값에 대한 1차 또는 2차 이산 차분으로 대체하여 시계열을 정상화합니다.",
    "Granger Causality": "한 시계열이 다른 시계열을 그레인저 인과하는지(지표가 될 수 있는지) 검정합니다.",
    "Interpolate": "시계열의 결측값을 보간합니다.",
    "Line Chart": "시계열의 순서와 진행을 시각화합니다.",
    "Model Evaluation": "여러 시계열 모델을 오차 기준(RMSE·MAE·MAPE·POCID·결정계수 R²·AIC·BIC)으로 평가합니다.",
    "Moving Transform": "시계열에 이동 윈도우 함수를 적용합니다.",
    "Periodogram": "시계열의 주기·계절성·주기성 및 가장 유의미한 주파수를 시각화합니다.",
    "Seasonal Adjustment": "계절 패턴을 보이는 시계열의 계절 성분을 제거합니다.",
    "Spiralogram": "시계열의 주기성을 나선형 히트맵으로 시각화합니다.",
    "Form Timeseries": "데이터 테이블을 시계열로 재해석합니다.",
    "Time Slice": "시간 구간의 측정값 일부를 선택합니다.",
    "VAR Model": "벡터 자기회귀(VAR)로 시계열을 모델링합니다.",
    "Yahoo Finance": "야후 파이낸스 주식 시장 데이터로 시계열을 생성합니다.",
}


def widget_discovery(discovery):
    from orangecanvas.registry.utils import category_from_package_globals
    from PyQt5.QtCore import QSettings
    import orangecontrib.timeseries.widgets as _pkg

    # Read current language
    s = QSettings(QSettings.IniFormat, QSettings.UserScope, "biolab.si", "Orange")
    lang = s.value("application/language", "English")

    # Register category with translated name
    cat_desc = category_from_package_globals(_pkg)
    discovery.handle_category(cat_desc)

    # Iterate widget descriptions and translate name + description for Korean
    for desc in discovery.iter_widget_descriptions(_pkg, category_name=cat_desc.name):
        if lang == "Korean":
            orig_name = desc.name   # desc.name 갱신 전 원본 키 확보
            ko_name = _WIDGET_NAMES_KO.get(orig_name)
            if ko_name:
                desc.name = ko_name
            ko_desc = _WIDGET_DESC_KO.get(orig_name)
            if ko_desc:
                desc.description = ko_desc
        discovery.handle_widget(desc)
