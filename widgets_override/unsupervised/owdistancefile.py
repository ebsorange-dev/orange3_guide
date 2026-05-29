from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator
import os

import numpy as np

from AnyQt.QtWidgets import QSizePolicy, QStyle, QMessageBox, QFileDialog
from AnyQt.QtCore import QTimer, QUrl

from orangewidget.settings import Setting
from orangewidget.widget import Msg
from orangewidget.workflow.drophandler import SingleFileDropHandler

from Orange.misc import DistMatrix
from Orange.widgets import widget, gui
from Orange.data import get_sample_datasets_dir
from Orange.widgets.utils.filedialogs import RecentPathsWComboMixin, RecentPath, \
    stored_recent_paths_prepend, OWUrlDropBase
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import Output


class OWDistanceFile(OWUrlDropBase, RecentPathsWComboMixin):
    name = _tr.m[2620, "Distance File"]
    id = "orange.widgets.unsupervised.distancefile"
    description = _tr.m[2621, "Read distances from a file."]
    icon = "icons/DistanceFile.svg"
    priority = 10
    keywords = _tr.m[2622, "distance file, load, read, open"]

    class Outputs:
        distances = Output(_tr.m[2623, "Distances"], DistMatrix, dynamic=False)

    class Error(widget.OWWidget.Error):
        invalid_file = Msg(_tr.m[2624, "Data was not loaded:{}"])
        non_square_matrix = Msg(
            (_tr.m[2625, "Matrix is not square. "] + _tr.m[2626, "Reformat the file and use the File widget to read it."]))

    want_main_area = False
    resizing_enabled = False

    auto_symmetric = Setting(True)

    def __init__(self):
        super().__init__()
        RecentPathsWComboMixin.__init__(self)
        self.distances = None

        vbox = gui.vBox(self.controlArea, _tr.m[2627, "Distance File"])
        box = gui.hBox(vbox)
        self.file_combo.setMinimumWidth(300)
        box.layout().addWidget(self.file_combo)
        self.file_combo.activated[int].connect(self.select_file)

        button = gui.button(box, self, '...', callback=self.browse_file)
        button.setIcon(self.style().standardIcon(QStyle.SP_DirOpenIcon))
        button.setSizePolicy(
            QSizePolicy.Maximum, QSizePolicy.Fixed)

        button = gui.button(
            box, self, _tr.m[2628, "Reload"], callback=self.reload, default=True)
        button.setIcon(self.style().standardIcon(QStyle.SP_BrowserReload))
        button.setSizePolicy(QSizePolicy.Fixed, QSizePolicy.Fixed)

        vbox = gui.vBox(self.controlArea, _tr.m[2629, "Options"])
        gui.checkBox(
            vbox, self, "auto_symmetric",
            _tr.m[2630, "Treat triangular matrices as symmetric"],
            tooltip=(_tr.m[2631, "If matrix is triangular, this will copy the data to the "] + _tr.m[2632, "other triangle"]),
            callback=self.commit
        )

        gui.rubber(self.buttonsArea)
        gui.button(
            self.buttonsArea, self, _tr.m[2633, "Browse documentation datasets"],
            callback=lambda: self.browse_file(True), autoDefault=False)
        gui.rubber(self.buttonsArea)

        self.set_file_list()
        QTimer.singleShot(0, self.open_file)

        # ── PC 파일 업로드 결과 폴링 (브라우저가 .dst/.xlsx 업로드 후
        #     /config/.upload_path_distance 에 파일 경로 기록 → 자동 로드) ──
        self.__pc_dist_timer = QTimer(self)
        self.__pc_dist_timer.timeout.connect(self.__pc_dist_check)
        self.__pc_dist_timer.start(1000)

    def reload(self):
        return self.open_file()

    def select_file(self, n):
        super().select_file(n)
        self.set_file_list()
        self.open_file()

    def browse_file(self, in_demos=False):
        """원본 동작(서버측 QFileDialog) 을 PC 측 탐색창 호출 신호 작성으로 교체.
        in_demos 인자는 원본 호환을 위해 받지만, PC 모드에서는 폴더 구분 없이
        사용자 PC 의 어디서든 .dst/.xlsx 파일을 선택할 수 있다."""
        import time as _time
        try:
            with open("/config/.upload_request_distance", "w") as _f:
                _f.write(str(_time.time()))
        except OSError:
            # 신호 작성 실패 시 원본 동작으로 폴백
            if in_demos:
                start_file = get_sample_datasets_dir()
                if not os.path.exists(start_file):
                    QMessageBox.information(
                        None, _tr.m[2634, "File"],
                        _tr.m[2635, "Cannot find the directory with documentation datasets"])
                    return
            else:
                start_file = self.last_path() or os.path.expanduser("~/")
            filename, _ext = QFileDialog.getOpenFileName(
                self, _tr.m[2636, 'Open Distance File'], start_file,
                _tr.m[2637, "Excel File (*.xlsx);;Distance File (*.dst)"])
            if not filename:
                return
            self.add_path(filename)
            self.open_file()

    def __pc_dist_check(self):
        """1초 폴링 — 브라우저 업로드 완료 시 /config/.upload_path_distance 에
        파일 경로가 기록됨. 감지하면 add_path + open_file 호출."""
        signal = "/config/.upload_path_distance"
        if not os.path.isfile(signal):
            return
        try:
            with open(signal, "r") as _f:
                path = _f.read().strip()
            os.remove(signal)
        except OSError:
            return
        if path and os.path.isfile(path):
            try:
                self.add_path(path)
                self.set_file_list()
                self.open_file()
            except Exception:
                pass

    def open_file(self):
        self.Error.clear()
        self.distances = None
        fn = self.last_path()
        if fn and not os.path.exists(fn):
            dir_name, basename = os.path.split(fn)
            if os.path.exists(os.path.join(".", basename)):
                fn = os.path.join(".", basename)
        if fn and fn != _tr.m[2638, "(none)"]:
            try:
                distances = DistMatrix.from_file(fn)
            except Exception as exc:
                err = str(exc)
                self.Error.invalid_file(" \n"[len(err) > 40] + err)
            else:
                if distances.shape[0] != distances.shape[1]:
                    self.Error.non_square_matrix()
                else:
                    np.nan_to_num(distances)
                    self.distances = distances
                    _, filename = os.path.split(fn)
                    self.distances.name, _ = os.path.splitext(filename)
        self.commit()

    def commit(self):
        distances = self.distances
        if distances is not None:
            if self.auto_symmetric:
                distances = distances.auto_symmetricized()
            if np.any(np.isnan(distances)):
                distances = np.nan_to_num(distances)
        self.Outputs.distances.send(distances)

    def send_report(self):
        if not self.distances:
            self.report_paragraph(_tr.m[2639, "No data was loaded."])
        else:
            self.report_items([(_tr.m[2640, "File name"], self.distances.name)])

    def canDropUrl(self, url: QUrl) -> bool:
        if url.isLocalFile():
            return OWDistanceFileDropHandler().canDropFile(url.toLocalFile())
        else:
            return False

    def handleDroppedUrl(self, url: QUrl) -> None:
        if url.isLocalFile():
            self.add_path(url.toLocalFile())
            self.open_file()


class OWDistanceFileDropHandler(SingleFileDropHandler):
    WIDGET = OWDistanceFile

    def parametersFromFile(self, path):
        r = RecentPath(os.path.abspath(path), None, None,
                       os.path.basename(path))
        return {"recent_paths": stored_recent_paths_prepend(self.WIDGET, r)}

    def canDropFile(self, path: str) -> bool:
        return os.path.splitext(path)[1].lower() in (".dst", ".xlsx")


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWDistanceFile).run()
