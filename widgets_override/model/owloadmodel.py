"""
Load Model — PC 탐색창에서 모델 파일 선택

원본은 컨테이너 안의 QFileDialog 를 띄워 *서버* 파일시스템을 보여준다.
File 위젯(OWFile)이 사용하는 `.upload_request` / `.upload_path` 신호 파일
패턴을 모델 전용으로 평행하게 적용한다(서로 충돌하지 않게 별도 파일명 사용):

  1) `...` 버튼 클릭 → /config/.upload_request_model 작성
  2) 브라우저(session-manager wrapper page) 가 폴링하다가 발견 시
     <input type="file" accept=".pkcls"> 트리거 → 사용자 PC 탐색창
  3) 사용자가 .pkcls 선택 → POST /upload?sid=...&kind=model 으로 업로드
  4) session-manager 가 컨테이너 /tmp/<name>.pkcls 로 복사하고
     /config/.upload_path_model 에 경로를 기록
  5) 본 위젯이 1.5s 폴링으로 그 경로를 소비 → add_path(path) → open_file()
     → 기존 pickle.load 로직으로 로딩 (이외 기능은 원본과 동일)
"""
import os
import pickle
import time
from typing import Any, Dict

from AnyQt.QtWidgets import QSizePolicy, QStyle, QFileDialog
from AnyQt.QtCore import QTimer, QUrl

from orangewidget.workflow.drophandler import SingleFileDropHandler

from Orange.base import Model
from Orange.widgets import widget, gui
from Orange.widgets.model import owsavemodel
from Orange.widgets.utils.filedialogs import RecentPathsWComboMixin, RecentPath, \
    stored_recent_paths_prepend, OWUrlDropBase
from Orange.widgets.utils import stdpaths
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import Msg, Output


class OWLoadModel(OWUrlDropBase, RecentPathsWComboMixin):
    name = "Load Model"
    description = "Load a model from an input file."
    priority = 3050
    replaces = ["Orange.widgets.classify.owloadclassifier.OWLoadClassifier"]
    icon = "icons/LoadModel.svg"
    keywords = "load model, file, open, model"

    class Outputs:
        model = Output("Model", Model)

    class Error(widget.OWWidget.Error):
        load_error = Msg("An error occured while reading '{}'")

    FILTER = ";;".join(owsavemodel.OWSaveModel.filters)

    want_main_area = False
    buttons_area_orientation = None
    resizing_enabled = False

    # PC 업로드 신호 파일 (File 위젯과 충돌하지 않도록 _model 접미사)
    _UPLOAD_REQUEST = "/config/.upload_request_model"
    _UPLOAD_PATH    = "/config/.upload_path_model"

    def __init__(self):
        super().__init__()
        RecentPathsWComboMixin.__init__(self)
        self.loaded_file = ""

        vbox = gui.vBox(self.controlArea, "File")
        box = gui.hBox(vbox)
        self.file_combo.setMinimumWidth(300)
        box.layout().addWidget(self.file_combo)
        self.file_combo.activated[int].connect(self.select_file)

        button = gui.button(box, self, '...', callback=self.browse_file)
        button.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        button.setSizePolicy(
            QSizePolicy.Maximum, QSizePolicy.Fixed)

        button = gui.button(
            box, self, "Reload", callback=self.reload, default=True)
        button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        self.set_file_list()
        QTimer.singleShot(0, self.open_file)

        # PC 업로드 결과 폴링 타이머 (File 위젯 _poll_uploads 패턴)
        self._upload_poll_timer = QTimer(self)
        self._upload_poll_timer.setInterval(1500)  # 1.5초 주기
        self._upload_poll_timer.timeout.connect(self._poll_model_upload)
        self._upload_poll_timer.start()

    def browse_file(self):
        """`...` 버튼 — PC 탐색창 호출 요청 신호 파일을 작성.
        실제 파일 선택과 업로드는 브라우저가 처리하고, 결과 경로는
        _poll_model_upload() 가 1.5초 주기로 받아 처리한다."""
        try:
            with open(self._UPLOAD_REQUEST, "w") as f:
                f.write(str(time.time()))
        except OSError:
            # 신호 파일 작성 실패 시 원본 동작(서버 다이얼로그)으로 폴백
            start_file = self.last_path() or stdpaths.Documents
            filename, _ = QFileDialog.getOpenFileName(
                self, 'Open Model File', start_file, self.FILTER)
            if not filename:
                return
            self.add_path(filename)
            self.open_file()

    def _poll_model_upload(self):
        """1.5초 주기 — session-manager 가 작성한 .upload_path_model 신호 소비."""
        if not os.path.isfile(self._UPLOAD_PATH):
            return
        try:
            with open(self._UPLOAD_PATH) as f:
                path = f.read().strip()
            os.remove(self._UPLOAD_PATH)
        except OSError:
            return
        if not path or not os.path.isfile(path):
            return
        self.add_path(path)
        self.open_file()

    def select_file(self, n):
        super().select_file(n)
        self.open_file()

    def reload(self):
        self.open_file()

    def open_file(self):
        self.clear_messages()
        fn = self.last_path()
        if not fn:
            return
        try:
            with open(fn, "rb") as f:
                model = pickle.load(f)
        except (pickle.UnpicklingError, OSError, EOFError):
            self.Error.load_error(os.path.split(fn)[-1])
            self.Outputs.model.send(None)
        else:
            self.Outputs.model.send(model)

    def canDropUrl(self, url: QUrl) -> bool:
        if url.isLocalFile():
            return OWLoadModelDropHandler().canDropFile(url.toLocalFile())
        else:
            return False

    def handleDroppedUrl(self, url: QUrl) -> None:
        if url.isLocalFile():
            self.add_path(url.toLocalFile())
            self.open_file()


class OWLoadModelDropHandler(SingleFileDropHandler):
    WIDGET = OWLoadModel

    def canDropFile(self, path: str) -> bool:
        return path.endswith(".pkcls")

    def parametersFromFile(self, path: str) -> Dict[str, Any]:
        r = RecentPath(os.path.abspath(path), None, None,
                       os.path.basename(path))
        return {"recent_paths": stored_recent_paths_prepend(self.WIDGET, r)}


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWLoadModel).run()
