from orangecanvas.utils.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.text", "biolab.si", "Orange")
del Translator
# Category metadata.

import sysconfig

NAME = _tr.m[2, "Text Mining"]

# Category icon show in the menu
ICON = "icons/category.svg"

# Background color for category background in menu
# and widget icon background in workflow.
BACKGROUND = "light-blue"

# Location of widget help files.
WIDGET_HELP_PATH = (
    ("{DEVELOP_ROOT}/doc/_build/html/index.html", None),
    ("{}/help/orange3-text/index.html".format(sysconfig.get_path("data")), None),
    ("https://orange3-text.readthedocs.io/en/latest/", ""),
)

# Korean widget name translations
_WIDGET_NAMES_KO = {
    "Annotated Corpus Map": "주석 말뭉치 지도",
    "Bag of Words": "단어 가방",
    "Collocations": "연어",
    "Concordance": "용례 색인",
    "Corpus": "말뭉치",
    "Corpus to Network": "말뭉치를 네트워크로",
    "Corpus Viewer": "말뭉치 뷰어",
    "Create Corpus": "말뭉치 만들기",
    "Document Map": "문서 지도",
    "Document Embedding": "문서 임베딩",
    "Duplicate Detection": "중복 감지",
    "The Guardian": "가디언",
    "Import Documents": "문서 가져오기",
    "Extract Keywords": "키워드 추출",
    "LDAvis": "LDA 시각화",
    "NY Times": "뉴욕 타임즈",
    "Ontology": "온톨로지",
    "Preprocess Text": "텍스트 전처리",
    "Pubmed": "PubMed",
    "Score Documents": "문서 점수화",
    "Semantic Viewer": "의미 뷰어",
    "Sentiment Analysis": "감성 분석",
    "Similarity Hashing": "유사도 해싱",
    "Statistics": "통계",
    "Topic Modelling": "주제 모델링",
    "Tweet Profiler": "트윗 프로파일러",
    "Twitter": "트위터",
    "Wikipedia": "위키피디아",
    "Word Cloud": "워드 클라우드",
    "Word Enrichment": "단어 풍부화",
    "Word List": "단어 목록",
}

# Korean widget description (tooltip) translations — 2026-05-21 추가
# 키는 원본(영문) 위젯 이름. widget_discovery 에서 desc.description 으로 적용.
_WIDGET_DESC_KO = {
    "Annotated Corpus Map": "투영 클러스터에 주석을 답니다.",
    "Bag of Words": "입력 말뭉치로부터 단어 가방을 생성합니다.",
    "Collocations": "유의미한 2-gram·3-gram을 계산합니다.",
    "Concordance": "단어의 문맥을 표시합니다.",
    "Corpus": "텍스트 문서 말뭉치를 불러옵니다.",
    "Corpus to Network": "주어진 말뭉치로부터 네트워크를 구성합니다.",
    "Corpus Viewer": "말뭉치 내용을 표시합니다.",
    "Create Corpus": "문서를 입력·붙여넣어 말뭉치를 만듭니다.",
    "Document Embedding": "사전 학습 모델을 사용한 문서 임베딩.",
    "Duplicate Detection": "말뭉치에서 중복을 감지하고 제거합니다.",
    "The Guardian": "The Guardian API에서 기사를 가져옵니다.",
    "Import Documents": "폴더에서 텍스트 문서를 가져옵니다.",
    "Extract Keywords": "입력 말뭉치에서 특징적인 단어를 추론합니다.",
    "LDAvis": "LDA 주제를 대화식으로 탐색합니다.",
    "NY Times": "뉴욕 타임즈 검색 API에서 기사를 가져옵니다.",
    "Preprocess Text": "텍스트 전처리 파이프라인을 구성합니다.",
    "Pubmed": "PubMed에서 데이터를 가져옵니다.",
    "Semantic Viewer": "입력 단어와 의미적으로 유사한 문서 및 문서 일부를 찾습니다.",
    "Sentiment Analysis": "텍스트로부터 감성을 계산합니다.",
    "Similarity Hashing": "문서 해시를 계산합니다.",
    "Statistics": "문서에 대한 새 통계 변수를 만듭니다.",
    "Topic Modelling": "말뭉치에 숨겨진 주제 구조를 발견합니다.",
    "Tweet Profiler": "트윗에서 Ekman·Plutchik·기분 상태 프로파일(POMS) 감정을 감지합니다.",
    "Twitter": "Twitter API에서 트윗을 불러옵니다.",
    "Word Enrichment": "선택한 문서에 대한 단어 풍부화 분석.",
    "Word List": "단어 목록을 만듭니다.",
}


def widget_discovery(discovery):
    from orangecanvas.registry.utils import category_from_package_globals
    from PyQt5.QtCore import QSettings
    import orangecontrib.text.widgets as _pkg

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
