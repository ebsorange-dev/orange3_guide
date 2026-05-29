from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.network", "biolab.si", "Orange")
del Translator
from operator import itemgetter
from os import path
from itertools import product
from traceback import format_exception_only

import numpy as np

from AnyQt.QtCore import Qt, QEvent
from AnyQt.QtWidgets import QStyle, QSizePolicy, QFileDialog

from Orange.util import get_entry_point
from Orange.data import Table, Domain, StringVariable
from Orange.data.util import get_unique_names
from Orange.widgets import gui, settings
from Orange.widgets.settings import ContextHandler
from Orange.widgets.utils.itemmodels import VariableListModel
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import OWWidget, Msg, Input, Output
from orangecontrib.network.network import Network
from orangecontrib.network.network.readwrite import read_pajek


class NxFileContextHandler(ContextHandler):
    def new_context(self, useful_vars):
        context = super().new_context()
        context.useful_vars = {var.name for var in useful_vars}
        context.label_variable = None
        return context

    # noinspection PyMethodOverriding
    def match(self, context, useful_vars):
        useful_vars = {var.name for var in useful_vars}
        if context.useful_vars == useful_vars:
            return self.PERFECT_MATCH
        # context.label_variable can also be None; this would always match,
        # so ignore it
        elif context.label_variable in useful_vars:
            return self.MATCH
        else:
            return self.NO_MATCH

    def settings_from_widget(self, widget, *_):
        context = widget.current_context
        if context is not None:
            context.label_variable = \
                widget.label_variable and widget.label_variable.name

    def settings_to_widget(self, widget, useful_vars):
        context = widget.current_context
        widget.label_variable = None
        if context.label_variable is not None:
            for var in useful_vars:
                if var.name == context.label_variable:
                    widget.label_variable = var
                    break


demos_path = next(
    get_entry_point("Orange3-Network", "orange.data.io.search_paths", "network")
    ())[1]


class OWNxFile(OWWidget):
    name = _tr.m[133, "Network File"]
    description = _tr.m[134, "Read network graph file"]
    icon = "icons/NetworkFile.svg"
    priority = 6410

    # ── wiget_card_26_work.md §2 / windowwk.md 유형 A 패턴 ────────────────────
    # launcher 의 카드 chrome (_apply_clean_chrome) 은 widget.windowFlags() 를
    # 보존하면서 FramelessWindowHint 만 추가하는 방식.
    # 따라서 위젯 자체가 Qt.Dialog 타입이어야 Openbox 의
    # <application type="normal"><maximized>true</maximized> 자동 최대화를 회피.
    # resizing_enabled=False → get_flags() 가 Qt.Dialog 반환 → DIALOG 타입 유지.
    resizing_enabled = False

    class Inputs:
        items = Input(_tr.m[135, "Items"], Table, id="Items")

    class Outputs:
        network = Output(_tr.m[136, "Network"], Network, id="Network")
        items = Output(_tr.m[137, "Items"], Table, id="Items")

    settingsHandler = NxFileContextHandler()
    label_variable: StringVariable = settings.ContextSetting(None)
    recentFiles = settings.Setting([])

    # ── 외부 클릭 시 자동 hide (windowwk.md 유형 A 표준) ────────────────────
    def closeEvent(self, event):
        super().closeEvent(event)
        self.hide()
        event.accept()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.ActivationChange and not self.isActiveWindow():
            # wiget_card_26_work.md §12 gotcha: 카드 chrome 의 toolbar/picker 가
            # 활성화될 때 self 가 inactive → 자동 hide 되면 사용자가 색상 변경 도중
            # 위젯이 사라지는 버그 발생. activeWindow 의 parent 체인에 self 가 있으면
            # (즉 toolbar/picker 가 self 를 Qt parent 로 지정한 child popup 이면) hide 스킵.
            from AnyQt.QtWidgets import QApplication as _QApp
            _active = _QApp.activeWindow()
            _w = _active
            while _w is not None:
                if _w is self:
                    return  # 카드 chrome popup 이 active → hide 안 함
                _w = _w.parent()
            self.hide()

    class Information(OWWidget.Information):
        auto_annotation = Msg(
            _tr.m[138, 'Nodes annotated with data from file with the same name'])
        suggest_annotation = Msg(
            _tr.m[139, 'Add optional data input to annotate nodes'])

    class Error(OWWidget.Error):
        io_error = Msg(_tr.m[140, 'Error reading file "{}"\n{}'])
        error_parsing_file = Msg(_tr.m[141, 'Error reading file "{}"'])
        auto_data_failed = Msg(
            (_tr.m[142, "Attempt to read {} failed\n"] + (_tr.m[143, "The widget tried to annotated nodes with data from\n"] + _tr.m[144, "a file with the same name."])))
        mismatched_lengths = Msg(
            (_tr.m[145, "Data size does not match the number of nodes.\n"] + (_tr.m[146, "Select a data column whose values can be matched with network "] + _tr.m[147, "labels"])))

    want_main_area = False
    mainArea_width_height_ratio = None

    def __init__(self):
        super().__init__()

        self.network = None
        self.auto_data = None
        self.original_nodes = None
        self.data = None
        self.net_index = 0

        hb = gui.widgetBox(self.controlArea, orientation=Qt.Horizontal)
        self.filecombo = gui.comboBox(
            hb, self, "net_index", callback=self.select_net_file,
            minimumWidth=250)
        gui.button(
            hb, self, '...', callback=self.browse_net_file, disabled=0,
            icon=self.style().standardIcon(QStyle.SP_DirOpenIcon),
            sizePolicy=(QSizePolicy.Maximum, QSizePolicy.Fixed))
        gui.button(
            hb, self, _tr.m[148, 'Reload'], callback=self.reload,
            icon=self.style().standardIcon(QStyle.SP_BrowserReload),
            sizePolicy=(QSizePolicy.Maximum, QSizePolicy.Fixed))

        self.label_model = VariableListModel(placeholder=_tr.m[149, "(Match by rows)"])
        self.label_model[:] = [None]
        gui.comboBox(
            self.controlArea, self, "label_variable", box=True,
            label=_tr.m[150, "Match node labels to data column: "], orientation=Qt.Horizontal,
            model=self.label_model, callback=self.label_changed)

        self.populate_comboboxes()
        self.setFixedHeight(self.sizeHint().height())
        self.reload()

        # ── PC 파일 업로드 결과 폴링 (브라우저가 .net/.pajek 업로드 후
        #     /config/.upload_path_network 에 파일 경로 기록 → 자동 로드) ──
        from AnyQt.QtCore import QTimer as _QTimer
        self.__pc_net_timer = _QTimer(self)
        self.__pc_net_timer.timeout.connect(self.__pc_net_check)
        self.__pc_net_timer.start(1000)

    @Inputs.items
    def set_data(self, data):
        self.data = data
        self.update_label_combo()
        self.send_output()

    def populate_comboboxes(self):
        self.filecombo.clear()
        for file in self.recentFiles or (_tr.m[151, "(None)"],):
            self.filecombo.addItem(path.basename(file))
        self.filecombo.addItem(_tr.m[152, "Browse documentation networks..."])
        self.filecombo.updateGeometry()

    def browse_net_file(self, browse_demos=False):
        """user pressed the '...' button to manually select a file to load.
        원본 동작(서버측 QFileDialog) 을 PC 측 탐색창 호출 신호 작성으로 교체.
        browse_demos 인자는 원본 호환을 위해 받지만, PC 모드에서는 폴더 구분 없이
        사용자 PC 의 어디서든 .net/.pajek 파일을 선택할 수 있다."""
        import time as _time
        try:
            with open("/config/.upload_request_network", "w") as _f:
                _f.write(str(_time.time()))
            return True
        except OSError:
            # 신호 작성 실패 시 원본 동작으로 폴백
            if browse_demos:
                startfile = demos_path
            else:
                startfile = self.recentFiles[0] if self.recentFiles else '.'
            filename, _ext = QFileDialog.getOpenFileName(
                self, _tr.m[153, 'Open a Network File'], startfile,
                ';;'.join(("Pajek files (*.net *.pajek)",)))
            if not filename:
                return False
            if filename in self.recentFiles:
                self.recentFiles.remove(filename)
            self.recentFiles.insert(0, filename)
            self.populate_comboboxes()
            self.net_index = 0
            self.select_net_file()
            return True

    def __pc_net_check(self):
        """1초 폴링 — 브라우저 업로드 완료 시 /config/.upload_path_network 에
        파일 경로가 기록됨. 감지하면 recentFiles 에 추가 후 select_net_file 호출."""
        from os import path as _osp
        import os as _os
        signal = "/config/.upload_path_network"
        if not _osp.isfile(signal):
            return
        try:
            with open(signal, "r") as _f:
                file_path = _f.read().strip()
            _os.remove(signal)
        except OSError:
            return
        if not (file_path and _osp.isfile(file_path)):
            return
        # 원본 browse_net_file 의 성공 흐름과 동일하게 처리
        try:
            if file_path in self.recentFiles:
                self.recentFiles.remove(file_path)
            self.recentFiles.insert(0, file_path)
            self.populate_comboboxes()
            self.net_index = 0
            self.select_net_file()
        except Exception:
            pass

    def reload(self):
        if self.recentFiles:
            self.select_net_file()

    def select_net_file(self):
        """user selected a graph file from the combo box"""
        if self.net_index > len(self.recentFiles) - 1:
            if not self.browse_net_file(True):
                return  # Cancelled
        elif self.net_index:
            self.recentFiles.insert(0, self.recentFiles.pop(self.net_index))
            self.net_index = 0
            self.populate_comboboxes()
        if self.recentFiles:
            self.open_net_file(self.recentFiles[0])

    def open_net_file(self, filename):
        """Read network from file."""
        self.Error.clear()
        self.Warning.clear()
        self.Information.clear()
        self.network = None
        self.original_nodes = None
        try:
            self.network = read_pajek(filename)
        except OSError as err:
            self.Error.io_error(
                filename,
                "".join(format_exception_only(type(err), err)).rstrip())
        except Exception:  # pylint: disable=broad-except
            self.Error.error_parsing_file(filename)
        else:
            self.original_nodes = self.network.nodes
            self.read_auto_data(filename)
        self.update_label_combo()
        self.send_output()

    def read_auto_data(self, filename):
        self.Error.auto_data_failed.clear()

        self.auto_data = None
        errored_file = None
        basenames = (filename,
                     path.splitext(filename)[0],
                     path.splitext(filename)[0] + '_items')
        for basename, ext in product(basenames, ('.tab', '.tsv', '.csv')):
            filename = basename + ext
            if path.exists(filename):
                try:
                    self.auto_data = Table.from_file(filename)
                    break
                except Exception:  # pylint: disable=broad-except
                    errored_file = filename
        else:
            if errored_file:
                self.Error.auto_data_failed(errored_file)

    def update_label_combo(self):
        self.closeContext()
        data = self.data if self.data is not None else self.auto_data
        if self.network is None or data is None:
            self.label_model[:] = [None]
        else:
            best_var, useful_vars = self._vars_for_label(data)
            self.label_model[:] = [None] + useful_vars
            self.label_variable = best_var
            self.openContext(useful_vars)
        self.set_network_nodes()

    def _vars_for_label(self, data: Table):
        vars_and_overs = []
        original_nodes = set(self.original_nodes)
        for var in data.domain.metas:
            if not isinstance(var, StringVariable):
                continue
            values= data.get_column(var)
            values = values[values != ""]
            set_values = set(values)
            # values have to be unique, and have to include all labels
            if len(values) != len(set_values) \
                    or not original_nodes <= set_values:
                continue
            vars_and_overs.append((len(set_values), var))
        if not vars_and_overs:
            return None, []
        # Prefer variables with less extra values
        _, best_var = min(vars_and_overs, key=itemgetter(0))
        useful_string_vars = [var for _, var in vars_and_overs]
        return best_var, useful_string_vars

    def label_changed(self):
        self.set_network_nodes()
        self.send_output()

    def send_output(self):
        if self.network is None:
            self.Outputs.network.send(None)
            self.Outputs.items.send(None)
        else:
            self.Outputs.network.send(self.network)
            self.Outputs.items.send(self.network.nodes)

    def set_network_nodes(self):
        self.Error.mismatched_lengths.clear()
        self.Information.auto_annotation.clear()
        self.Information.suggest_annotation.clear()
        if self.network is None:
            return

        data = self.data if self.data is not None else self.auto_data
        if data is None:
            self.Information.suggest_annotation()
        elif self.label_variable is None \
                and len(data) != self.network.number_of_nodes():
            self.Error.mismatched_lengths()
            data = None

        if data is None:
            self.network.nodes = self._label_to_tabel()
        elif self.label_variable is None:
            self.network.nodes = self._combined_data(data)
        else:
            self.network.nodes = self._data_by_labels(data)

    def _data_by_labels(self, data):
            data_col = data.get_column(self.label_variable)
            data_rows = {label: row for row, label in enumerate(data_col)}
            indices = [data_rows[label] for label in self.original_nodes]
            return data[indices]

    def _combined_data(self, source):
        nodes = np.array(self.original_nodes, dtype=str)
        if nodes.ndim != 1:
            return source
        try:
            nums = np.sort(np.array([int(x) for x in nodes]))
        except ValueError:
            pass
        else:
            if np.all(nums[1:] - nums[:-1] == 1):
                return source

        src_dom = source.domain
        label_attr = StringVariable(get_unique_names(src_dom, "node_label"))
        domain = Domain(src_dom.attributes, src_dom.class_vars,
                        src_dom.metas + (label_attr, ))
        data = source.transform(domain)
        with data.unlocked(data.metas):
            data.metas[:, -1] = nodes
        return data

    def _label_to_tabel(self):
        domain = Domain([], [], [StringVariable("node_label")])
        n = len(self.original_nodes)
        data = Table.from_numpy(
            domain, np.empty((n, 0)), np.empty((n, 0)),
            np.array(self.original_nodes, dtype=str).reshape(-1, 1))
        return data


    def send_report(self):
        if not self.network:
            return

        self.report_items(
            _tr.m[154, "Network file"],
            [(_tr.m[155, "File name"], self.filecombo.currentText()),
             (_tr.m[156, "Vertices"], self.network.number_of_nodes()),
             (_tr.m[157, "Directed"], [_tr.m[158, "No"], _tr.m[159, "Yes"]][self.network.edges[0].directed])
             ])


if __name__ == "__main__":
    WidgetPreview(OWNxFile).run()
