from orangecontrib.text.widgets._ko_trans import _t  # i18n (2026-05-21)
import hashlib
import os
from typing import List

import numpy as np
from AnyQt.QtCore import Qt, QSize
from AnyQt.QtWidgets import QSizeGrip, QStyle
from Orange.data import Table, StringVariable, Variable
from Orange.data.io import FileFormat
from Orange.widgets import gui
from Orange.widgets.utils.itemmodels import VariableListModel, DomainModel
from Orange.widgets.data.owselectcolumns import VariablesListItemView
from Orange.widgets.settings import Setting, ContextSetting,\
    DomainContextHandler
from Orange.widgets.widget import OWWidget, Msg, Input, Output
from Orange.widgets.utils.concurrent import TaskState, ConcurrentWidgetMixin
from orangecanvas.gui.utils import disconnected
from orangewidget.settings import ContextHandler

from orangecontrib.text.corpus import Corpus, get_sample_corpora_dir
from orangecontrib.text.language import (
    detect_language,
    LanguageModel,
    LANG2ISO,
    migrate_language_name,
)
from orangecontrib.text.widgets.utils import widgets


class CorpusContextHandler(DomainContextHandler):
    """
    Since Corpus enable language selection and language is not domain dependent
    but documents dependent setting specific handler is required. It will mathc
    contexts when selected attributes are the same, hash of the documents
    is the same and corpus's input language is the same.

    Note: With this modification context matching is stricter. It was discussed
    that in this case there would be two contexts required one for attributes
    and one for language. Idea is that in the feature we implement context handlers
    such that specific matcher can be set for a specific setting (e.g. language).
    """

    def open_context(self, widget, corpus):
        """
        Modifying open_context such that it propagates complete corpus not only
        domain - required for hash computation
        """
        if corpus is None:
            return
        ContextHandler.open_context(
            self, widget, corpus, *self.encode_domain(corpus.domain)
        )

    def new_context(self, corpus, attributes, metas):
        """Adding hash of documents to the context"""
        context = super().new_context(corpus, attributes, metas)
        context.documents_hash = self.__compute_hash(corpus.documents)
        context.language = corpus.language
        return context

    def match(self, context, corpus, attrs, metas):
        """
        For a match documents in the corpus must have same hash value and
        attributes should mathc
        """
        if (
            hasattr(context, "documents_hash")
            and context.documents_hash != self.__compute_hash(corpus.documents)
            or hasattr(context, "language")
            and context.language != corpus.language
        ):
            return self.NO_MATCH
        return super().match(context, corpus.domain, attrs, metas)

    def decode_setting(self, setting, value, corpus=None, *args):
        """Modifying decode setting to work with Corpus instead of domain"""
        return super().decode_setting(setting, value, corpus.domain, *args)

    @staticmethod
    def __compute_hash(texts: List[str]) -> int:
        texts = " ".join(texts)
        return int(hashlib.md5(texts.encode("utf-8")).hexdigest(), 16)


class OWCorpus(OWWidget, ConcurrentWidgetMixin):
    name = "Corpus"
    description = "Load a corpus of text documents."
    icon = "icons/TextFile.svg"
    priority = 100
    keywords = "corpus, text"
    replaces = ["orangecontrib.text.widgets.owloadcorpus.OWLoadCorpus"]

    class Inputs:
        data = Input('Data', Table)

    class Outputs:
        corpus = Output('Corpus', Corpus)

    want_main_area = False
    resizing_enabled = True

    dlgFormats = (
        _t("All readable files ({});;").format(
            '*' + ' *'.join(FileFormat.readers.keys())) +
        ";;".join("{} (*{})".format(f.DESCRIPTION, ' *'.join(f.EXTENSIONS))
                  for f in sorted(set(FileFormat.readers.values()),
                                  key=list(FileFormat.readers.values()).index)))

    settingsHandler = CorpusContextHandler()
    settings_version = 2

    recent_files = Setting([
        "book-excerpts.tab",
        "grimm-tales-selected.tab",
        "election-tweets-2016.tab",
        "friends-transcripts.tab",
        "andersen.tab",
    ])
    used_attrs = ContextSetting([])
    title_variable = ContextSetting("")
    language: str = ContextSetting("en")

    class Error(OWWidget.Error):
        read_file = Msg(_t("Can't read file ({})"))
        no_text_features_used = Msg(_t("At least one text feature must be used."))
        corpus_without_text_features = Msg(_t("Corpus doesn't have any textual features."))

    def sizeHint(self):
        return QSize(450, 530)

    def __init__(self):
        OWWidget.__init__(self)
        # Qt.Window(NORMAL) → Qt.Dialog(DIALOG) 타입으로 변경
        # Openbox 전체창 규칙 적용 방지, 크기 조절 및 최대화 버튼 유지
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.Window) | Qt.Dialog | Qt.WindowMaximizeButtonHint
        )
        # 이전 세션에서 전체화면 크기로 저장된 geometry 초기화
        # OWWidget.__init__ 내부에서 savedWidgetGeometry를 복원하므로 여기서 리셋
        self.savedWidgetGeometry = None
        ConcurrentWidgetMixin.__init__(self)

        self.corpus = None

        # --- 상단: Corpus file 선택 (Data Sampler 스타일 vBox) ---
        file_box = gui.vBox(self.controlArea, _t("Corpus File"))
        self.file_widget = widgets.FileWidget(
            recent_files=self.recent_files, icon_size=(16, 16),
            on_open=self.open_file, dialog_format=self.dlgFormats,
            dialog_title=_t('Open Orange Document Corpus'),
            reload_label=_t('Reload'), browse_label=_t('Browse'),
            allow_empty=False, minimal_width=250,
        )
        file_box.layout().addWidget(self.file_widget)

        # --- Corpus settings ---
        self.title_model = DomainModel(
            valid_types=(StringVariable,), placeholder=_t("(no title)"))
        settings_box = gui.vBox(self.controlArea, _t("Corpus Settings"))
        common_settings = dict(
            labelWidth=100,
            searchable=True,
            orientation=Qt.Horizontal,
            callback=self.update_feature_selection,
        )
        gui.comboBox(
            settings_box,
            self,
            "title_variable",
            label=_t("Title variable"),
            model=self.title_model,
            **common_settings
        )
        gui.comboBox(
            settings_box,
            self,
            "language",
            label=_t("Language"),
            model=LanguageModel(include_none=True),
            sendSelectedValue=True,
            **common_settings
        )

        # --- Text Features (Used / Ignored 나란히) ---
        features_row = gui.widgetBox(self.controlArea, orientation=0)

        ubox = gui.vBox(features_row, _t("Used Text Features"))
        self.used_attrs_model = VariableListModel(enable_dnd=True)
        self.used_attrs_view = VariablesListItemView()
        self.used_attrs_view.setModel(self.used_attrs_model)
        ubox.layout().addWidget(self.used_attrs_view)

        aa = self.used_attrs_model
        aa.dataChanged.connect(self.update_feature_selection)
        aa.rowsInserted.connect(self.update_feature_selection)
        aa.rowsRemoved.connect(self.update_feature_selection)

        ibox = gui.vBox(features_row, _t("Ignored Text Features"))
        self.unused_attrs_model = VariableListModel(enable_dnd=True)
        self.unused_attrs_view = VariablesListItemView()
        self.unused_attrs_view.setModel(self.unused_attrs_model)
        ibox.layout().addWidget(self.unused_attrs_view)

        # --- 하단 버튼 영역 ---
        btn_box = gui.hBox(self.controlArea)

        self.browse_documentation = gui.button(
            btn_box, self, _t("Browse Documentation Corpora"),
            # 하단 버튼도 PC 탐색창으로 통합 (상단 Browse 버튼과 동일 동작)
            callback=lambda: self._request_pc_corpus_upload(),
            autoDefault=False,
        )

        # 전체 확대 토글 버튼
        self._maximize_btn = gui.button(
            btn_box, self, "",
            callback=self._toggle_maximize,
            autoDefault=False,
        )
        self._maximize_btn.setFixedSize(28, 28)
        self._maximize_btn.setToolTip("최대화")
        self._maximize_btn.setIcon(
            self.style().standardIcon(QStyle.SP_TitleBarMaxButton)
        )

        # 우하단 리사이즈 그립 (마우스 크기 조절 시각 가이드)
        grip_box = gui.hBox(self.controlArea)
        grip_box.layout().addStretch()
        self._size_grip = QSizeGrip(self)
        grip_box.layout().addWidget(self._size_grip)

        # ── PC 탐색창 통합 ────────────────────────────────────────────────
        # FileWidget 내장 Browse 버튼은 컨테이너 측 QFileDialog 를 띄움 →
        # PC 측 탐색창으로 교체하여 사용자 PC 파일을 직접 업로드.
        # 기존 callback(self.file_widget.browse) 을 disconnect 하고
        # /config/.upload_request_corpus 신호 작성으로 교체.
        # 브라우저 폴링 → corpus-file-input 클릭 → PC 탐색창 → 업로드
        # → /config/.upload_path_corpus → 1초 폴링이 self.open_file 호출.
        try:
            self.file_widget.browse_button.clicked.disconnect()
        except Exception:
            pass
        self.file_widget.browse_button.clicked.connect(self._request_pc_corpus_upload)

        # ── Dataset 버튼 추가 (텍스트 카테고리 카탈로그 직접 호출) ──
        # File 위젯의 Dataset 버튼과 동일한 동작 — 다만 클릭 시 텍스트 탭으로 진입
        from AnyQt.QtWidgets import QPushButton
        from AnyQt.QtGui import QIcon, QPixmap
        from AnyQt.QtCore import QByteArray
        self.dataset_button = QPushButton(_t("Dataset"))
        self.dataset_button.setFocusPolicy(Qt.NoFocus)
        # 데이터베이스(원통 3단) 아이콘 — File 위젯 owfile.py 와 동일 SVG
        _svg = (
            b'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" '
            b'fill="none" stroke="currentColor" stroke-width="2" '
            b'stroke-linecap="round" stroke-linejoin="round">'
            b'<ellipse cx="12" cy="5" rx="9" ry="3"/>'
            b'<path d="M3 5v6c0 1.66 4.03 3 9 3s9-1.34 9-3V5"/>'
            b'<path d="M3 11v6c0 1.66 4.03 3 9 3s9-1.34 9-3v-6"/>'
            b'</svg>'
        )
        _pix = QPixmap()
        _pix.loadFromData(QByteArray(_svg), "SVG")
        self.dataset_button.setIcon(QIcon(_pix))
        self.dataset_button.setToolTip("텍스트 데이터셋 카탈로그 열기")
        self.dataset_button.clicked.connect(self._request_pc_corpus_dataset_catalog)
        # FileWidget 의 layout = QHBoxLayout 이므로 reload_button 직전(index=2)에 삽입
        # → 표시 순서: [combo] [Browse] [Dataset] [Reload]
        try:
            self.file_widget.layout().insertWidget(2, self.dataset_button)
        except Exception:
            # 폴백 — 그냥 추가
            self.file_widget.layout().addWidget(self.dataset_button)

        # 업로드 결과 폴링 (1초)
        from AnyQt.QtCore import QTimer as _QTimer
        self.__pc_corpus_timer = _QTimer(self)
        self.__pc_corpus_timer.timeout.connect(self.__pc_corpus_check)
        self.__pc_corpus_timer.start(1000)

        # load first file
        self.file_widget.select(0)

    def _request_pc_corpus_upload(self):
        """Browse 버튼 클릭 — PC 측 탐색창 호출 신호 작성."""
        import os, time
        try:
            with open("/config/.upload_request_corpus", "w") as _f:
                _f.write(str(time.time()))
        except OSError:
            # 신호 작성 실패 시 원본 동작(서버측 다이얼로그) 폴백
            try:
                self.file_widget.browse()
            except Exception:
                pass

    def _request_pc_corpus_dataset_catalog(self):
        """Dataset 버튼 클릭 — 텍스트 카테고리로 카탈로그 모달 호출.
        세션 매니저가 /dataset-poll 로 감지 후 ?cat=text 파라미터로 모달을 열어
        텍스트 마이닝 탭이 미리 선택된 채로 표시된다. 사용자가 항목 선택 시
        기존 dataset-select 흐름이 /config/.upload_path 에 경로 기록 →
        그러나 Corpus 는 .upload_path_corpus 를 듣고 있으므로, 추가로 별도 폴링
        (.upload_path 도 함께 감시) 또는 dataset-select 응답을 corpus 로 전환하는
        후속 단계 필요. 우선은 카탈로그 표시까지 동작."""
        import time
        try:
            with open("/config/.dataset_request", "w", encoding="utf-8") as _f:
                _f.write("cat=text")
        except OSError:
            from AnyQt.QtWidgets import QMessageBox
            QMessageBox.warning(self, _t("Dataset"), "카탈로그 호출 신호 작성 실패")

    def __pc_corpus_check(self):
        """1초 주기 폴링 — 업로드 완료 신호 감지 후 FileWidget.browse() 와
        동일한 흐름으로 처리:
          1) recent_files 에 경로 삽입 → 콤보박스 갱신
          2) FileWidget.open_file(path) → on_open 시그널 발사
          3) on_open 이 OWCorpus.open_file 호출 → _load_corpus → on_done →
             used_attrs_model / unused_attrs_model 채워짐 → Used/Ignored 표시 갱신
        """
        import os
        signal = "/config/.upload_path_corpus"
        if not os.path.isfile(signal):
            return
        try:
            with open(signal, "r") as _f:
                path = _f.read().strip()
            os.remove(signal)
        except OSError:
            return
        if not (path and os.path.isfile(path)):
            return
        # FileWidget.browse() 와 동일한 시퀀스 — 콤보박스 + on_open
        try:
            if self.file_widget.recent_files is not None:
                if path in self.file_widget.recent_files:
                    self.file_widget.recent_files.remove(path)
                self.file_widget.recent_files.insert(0, path)
                self.file_widget.update_combo()
            self.file_widget.open_file(path)
        except Exception:
            # 폴백 — 직접 OWCorpus.open_file 호출
            try:
                self.open_file(path)
            except Exception:
                pass

    def _toggle_maximize(self):
        if self.isMaximized():
            self.showNormal()
            self._maximize_btn.setIcon(
                self.style().standardIcon(QStyle.SP_TitleBarMaxButton)
            )
            self._maximize_btn.setToolTip("최대화")
        else:
            self.showMaximized()
            self._maximize_btn.setIcon(
                self.style().standardIcon(QStyle.SP_TitleBarNormalButton)
            )
            self._maximize_btn.setToolTip("원래 크기")

    @Inputs.data
    def set_data(self, data):
        have_data = data is not None

        # Enable/Disable command when data from input
        self.file_widget.setEnabled(not have_data)
        self.browse_documentation.setEnabled(not have_data)

        if have_data:
            self.open_file(data=data)
        else:
            self.file_widget.reload()

    @staticmethod
    def _load_corpus(path: str, data: Table, state: TaskState) -> Corpus:
        state.set_status(_t("Loading"))
        corpus = None
        if data:
            corpus = Corpus.from_table(data.domain, data)
        elif path:
            corpus = Corpus.from_file(path)
            if not hasattr(corpus, "name") or not corpus.name:
                corpus.name = os.path.splitext(os.path.basename(path))[0]
        return corpus

    def open_file(self, path=None, data=None):
        self.closeContext()
        self.Error.clear()
        self.cancel()
        self.unused_attrs_model[:] = []
        with disconnected(
            self.used_attrs_model.rowsRemoved, self.update_feature_selection
        ):
            self.used_attrs_model[:] = []
        self.start(self._load_corpus, path, data)

    def on_done(self, corpus: Corpus) -> None:
        self.corpus = corpus
        if corpus is None:
            return

        self._setup_title_dropdown()
        self.used_attrs = list(self.corpus.text_features)
        all_str_features = [f for f in self.corpus.domain.metas if f.is_string]
        if not all_str_features:
            self.Error.corpus_without_text_features()
            self.Outputs.corpus.send(None)
            return
        # set language on Corpus's language (when corpus with already defined
        # language opened) or guess language
        self.language = corpus.language or detect_language(corpus)
        self.openContext(self.corpus)
        self.used_attrs_model.extend(self.used_attrs)
        self.unused_attrs_model.extend(
            [f for f in self.corpus.domain.metas
             if f.is_string and f not in self.used_attrs_model]
        )

    def on_exception(self, ex: Exception) -> None:
        if isinstance(ex, BaseException):
            self.Error.read_file(str(ex))
        else:
            raise ex

    def _setup_title_dropdown(self):
        self.title_model.set_domain(self.corpus.domain)

        # if title variable is already marked in a dataset set it as a title
        # variable
        title_var = list(filter(
            lambda x: x.attributes.get("title", False),
            self.corpus.domain.metas))
        if title_var:
            self.title_variable = title_var[0]
            return

        # if not title attribute use heuristic for selecting it
        v_len = np.vectorize(len)
        first_selection = (None, 0)  # value, uniqueness
        second_selection = (None, 100)  # value, avg text length

        variables = [v for v in self.title_model
                     if v is not None and isinstance(v, Variable)]

        for variable in sorted(
                variables, key=lambda var: var.name, reverse=True):
            # if there is title, heading, or filename attribute in corpus
            # heuristic should select them -
            # in order title > heading > filename - this is why we use sort
            if str(variable).lower() in ('title', 'heading', 'filename'):
                first_selection = (variable, 0)
                break

            # otherwise uniqueness and length counts
            column_values = self.corpus.get_column(variable)
            average_text_length = v_len(column_values).mean()
            uniqueness = len(np.unique(column_values))

            # if the variable is short enough to be a title select one with
            # the highest number of unique values
            if uniqueness > first_selection[1] and average_text_length <= 30:
                first_selection = (variable, uniqueness)
            # else select the variable with shortest average text that is
            # shorter than 100 (if all longer than 100 leave empty)
            elif average_text_length < second_selection[1]:
                second_selection = (variable, average_text_length)

        if first_selection[0] is not None:
            self.title_variable = first_selection[0]
        elif second_selection[0] is not None:
            self.title_variable = second_selection[0]
        else:
            self.title_variable = None

    def update_feature_selection(self):
        self.Error.no_text_features_used.clear()

        # duplicated data when reordering inside a single window
        def remove_duplicates(l):
            unique = []
            for i in l:
                if i not in unique:
                    unique.append(i)
            return unique

        if self.corpus is not None:
            # corpus must be copied that original properties are preserved
            # example: if user selects different text features set_text_features
            # would reset preprocessing inplace but when user select initial
            # features again we want to have preprocessing preserved
            corpus = self.corpus.copy()
            corpus.set_text_features(remove_duplicates(self.used_attrs_model))
            self.used_attrs = list(self.used_attrs_model)

            if len(self.unused_attrs_model) > 0 and not corpus.text_features:
                self.Error.no_text_features_used()

            corpus.set_title_variable(self.title_variable)
            corpus.attributes["language"] = self.language
            # prevent sending "empty" corpora
            dom = corpus.domain
            empty = (
                not (dom.variables or dom.metas)
                or len(corpus) == 0
                or not corpus.text_features
            )
            self.Outputs.corpus.send(corpus if not empty else None)

    def send_report(self):
        def describe(features):
            if len(features):
                return ', '.join([f.name for f in features])
            else:
                return _t('(none)')

        if self.corpus is not None:
            domain = self.corpus.domain
            self.report_items('Corpus', (
                (_t("File"), self.file_widget.get_selected_filename()),
                (_t("Documents"), len(self.corpus)),
                (_t("Used text features"), describe(self.used_attrs_model)),
                (_t("Ignored text features"), describe(self.unused_attrs_model)),
                (_t('Other features'), describe(domain.attributes)),
                (_t('Target'), describe(domain.class_vars)),
            ))

    @classmethod
    def migrate_context(cls, context, version):
        if version < 2:
            if "language" in context.values:
                language, type_ = context.values["language"]
                language = LANG2ISO[migrate_language_name(language)]
                context.values["language"] = (language, type_)


if __name__ == '__main__':
    from orangewidget.utils.widgetpreview import WidgetPreview
    WidgetPreview(OWCorpus).run()
