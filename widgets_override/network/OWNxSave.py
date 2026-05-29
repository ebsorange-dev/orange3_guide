"""
Save Network — 내 PC 저장 (브라우저 showSaveFilePicker)

OWSaveBase 기본 동작은 컨테이너 안의 QFileDialog 를 띄워 *서버*의 파일시스템을
보여주므로, 사용자 PC 의 탐색창을 띄울 수 없다. 본 override 는 Save Distance Matrix /
Save Model 과 동일한 PC 저장 인프라를 그대로 사용한다:

  1) Pajek 포맷으로 컨테이너의 /config/.pc_download/<name>.net 으로 기록
  2) /config/.pc_download_ready 에 JSON 신호(basename + files + force_new + widget_id)
  3) 브라우저(session-manager 의 wrapper page) 가 1.5s 주기로 폴링하다가
     window.showSaveFilePicker() 로 *사용자 PC* 의 네이티브 저장 다이얼로그를
     띄우고, /pc_download/get 로 파일을 받아 사용자가 고른 핸들에 기록.
  4) 저장 완료 후 /pc_download/notify_saved → /config/.pc_save_name 에 파일명이
     남고, 본 위젯이 1s 폴링으로 bt_save 텍스트를 'Save as <name>' 로 갱신.

같은 widget_id 의 두 번째 클릭부터는 캐시된 핸들로 silent 저장.
위젯 삭제 + 재추가 시 새 widget_id 발급되어 picker 가 다시 호출됨.
"""
from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.network", "biolab.si", "Orange")
del Translator

import os
import json
import uuid

from Orange.data import StringVariable, Table
from Orange.widgets import gui
from Orange.widgets.settings import DomainContextHandler, ContextSetting
from Orange.widgets.utils.itemmodels import DomainModel
from Orange.widgets.widget import Input, Msg

from Orange.widgets.data.owsave import OWSaveBase
from orangecontrib.network.network import readwrite
from orangecontrib.network.network.base import Network
from orangecontrib.network.network.readwrite import PajekReader
from orangewidget.utils.widgetpreview import WidgetPreview


class OWNxSave(OWSaveBase):
    name = _tr.m[273, "Save Network"]
    description = _tr.m[274, "Save network to an output file."]
    icon = "icons/NetworkSave.svg"

    writers = [PajekReader]
    filters = {f"{w.DESCRIPTION} (*{w.EXTENSIONS[0]})": w
               for w in writers}

    class Inputs:
        network = Input(_tr.m[275, "Network"], Network, default=True, id="Network")

    class Error(OWSaveBase.Error):
        multiple_edge_types = Msg(_tr.m[276, "Can't save network with multiple edge types"])

    settingsHandler = DomainContextHandler()
    label_variable = ContextSetting(None)

    def __init__(self):
        super().__init__(2)
        # 첫 PC 저장 후 True → auto_save 가 PC 저장을 호출
        self._pc_save_active = False
        # 위젯 인스턴스 고유 ID — 브라우저가 위젯별로 파일 핸들을 분리 캐시.
        # 매 인스턴스마다 새 UUID → 위젯 삭제+재추가 시 새 widget_id → picker 재호출.
        self._widget_id = f"savenetwork-{uuid.uuid4().hex[:8]}"

        self.label_model = DomainModel(
            placeholder=_tr.m[277, "(None)"], valid_types=(StringVariable, ))
        box = gui.hBox(None)
        gui.widgetLabel(box, _tr.m[278, "Node label: "])
        gui.comboBox(
            box, self, "label_variable",
            tooltip=_tr.m[279, "Choose the variables that will be used as a label"],
            model=self.label_model),

        self.grid.addWidget(box, 0, 0, 1, 2)
        self.grid.setRowMinimumHeight(1, 8)

        # OWSaveBase 가 만든 Save / Save as ... 버튼 callback 을 PC 저장으로 교체
        try:
            self.bt_save.clicked.disconnect()
        except Exception:
            pass
        self.bt_save.clicked.connect(lambda: self._save_to_pc(force_new=False))
        from AnyQt.QtWidgets import QPushButton
        for btn in self.buttonsArea.findChildren(QPushButton):
            if btn is not self.bt_save:
                try:
                    btn.clicked.disconnect()
                except Exception:
                    pass
                btn.clicked.connect(lambda: self._save_to_pc(force_new=True))
                break
        # 브라우저가 저장 완료 후 /config/.pc_save_name 에 남기는 파일명을 폴링
        from AnyQt.QtCore import QTimer
        self._pc_name_timer = QTimer(self)
        self._pc_name_timer.timeout.connect(self._poll_pc_saved_name)
        self._pc_name_timer.start(1000)

        self.adjustSize()

    @Inputs.network
    def set_network(self, network):
        self.closeContext()

        self.data = network
        if network is None:
            return
        if len(network.edges) > 1:
            self.Error.multiple_edge_types()
            self.data = None
            return
        self.Error.multiple_edge_types.clear()

        if isinstance(network.nodes, Table):
            self.controls.label_variable.setEnabled(True)
            domain = network.nodes.domain
            self.label_model.set_domain(domain)
            for attr in domain.metas:
                if attr.name == "node_label":
                    self.label_variable = attr
                    break
            self.openContext(domain)
        else:
            self.label_model.set_domain(None)
            self.label_variable = None
            self.controls.label_variable.setEnabled(False)

        self.on_new_input()

    # ── PC 저장 ────────────────────────────────────────────────────────────
    def _save_to_pc(self, force_new=False):
        from AnyQt.QtWidgets import QMessageBox
        # Network 미입력 상태여도 PC 탐색창은 동일하게 호출 (Save Model 과 동일 정책).
        # self.data 가 None 이면 빈 placeholder 파일을 기록하여 사용자가 선택한
        # PC 경로에 빈 파일이 저장됨.
        # writer 는 클래스 정의 시점에 PajekReader 로 고정되므로 일반적으로 None 이 아님.
        if self.writer is None:
            return
        # basename: stored_name 우선, 없으면 'network'
        if self.stored_name:
            basename = os.path.splitext(os.path.basename(self.stored_name))[0]
        else:
            basename = 'network'
        download_dir = '/config/.pc_download'
        try:
            os.makedirs(download_dir, exist_ok=True)
            # 기존 파일 정리
            for _f in os.listdir(download_dir):
                try:
                    os.remove(os.path.join(download_dir, _f))
                except OSError:
                    pass
            # Pajek (.net) 포맷으로 저장
            ext = self.writer.EXTENSIONS[0] if self.writer.EXTENSIONS else '.net'
            fname = f'{basename}{ext}'
            fpath = os.path.join(download_dir, fname)
            if self.data is not None:
                net = self.data
                if self.label_variable is not None:
                    labels = net.nodes.get_column(self.label_variable)
                else:
                    labels = range(1, net.number_of_nodes() + 1)
                self.writer.write(fpath, net, labels)
            else:
                # 데이터 미입력 — 빈 파일 생성 (탐색창은 표시되도록)
                with open(fpath, 'wb') as _ef:
                    _ef.write(b'')
            label = f"{self.writer.DESCRIPTION} (*{ext})"
            saved = [{"label": label, "filename": fname}]
            with open('/config/.pc_download_ready', 'w', encoding='utf-8') as f:
                json.dump({"basename": basename, "files": saved,
                           "force_new": bool(force_new),
                           "widget_id": self._widget_id}, f, ensure_ascii=False)
            # 첫 저장(force_new=False) 시 PC 저장 활성화 → auto_save 가 PC 저장 호출
            if not force_new:
                self._pc_save_active = True
                self.update_messages()
        except Exception as e:
            QMessageBox.critical(self, "내 PC 저장", f"네트워크 저장 실패: {e}")

    def _poll_pc_saved_name(self):
        """브라우저가 저장 완료 후 /config/.pc_save_name 에 남기는 파일명을 폴링."""
        path = '/config/.pc_save_name'
        if not os.path.exists(path):
            return
        try:
            with open(path, 'r', encoding='utf-8') as f:
                name = f.read().strip()
            os.remove(path)
            if name and self.bt_save is not None:
                self.bt_save.setText(f"Save as {name}")
        except Exception:
            pass

    # ── auto_save 분기 ─────────────────────────────────────────────────────
    def on_new_input(self):
        """PC 저장이 활성화돼 있으면 auto_save 시 PC 저장으로 분기."""
        self.Error.clear()
        self.Warning.clear()
        self.Information.clear()
        self.update_messages()
        self.update_status()
        if self.auto_save:
            if getattr(self, '_pc_save_active', False) and self.data is not None:
                self._save_to_pc(force_new=False)
            elif self.filename:
                self.save_file()

    def update_messages(self):
        super().update_messages()
        # PC 저장은 self.filename 을 설정하지 않으므로 기본 'no_file_name' 에러 억제
        if getattr(self, '_pc_save_active', False) and self.auto_save:
            self.Error.no_file_name.clear()

    # ── 원본 save_file (호출되는 일은 거의 없으나 호환성 유지) ─────────────
    def save_file(self):
        if not self.filename:
            self.save_file_as()
            return
        self.Error.general_error.clear()
        if self.data is None or not self.filename or self.writer is None:
            return
        try:
            net = self.data
            if self.label_variable is not None:
                labels = net.nodes.get_column(self.label_variable)
            else:
                labels = range(1, net.number_of_nodes() + 1)
            self.writer.write(self.filename, net, labels)
        except IOError as err_value:
            self.Error.general_error(str(err_value))

    def send_report(self):
        self.report_items((
            (_tr.m[280, "Node labels"],
             self.label_variable.name if self.label_variable else _tr.m[281, "none"]),
            (_tr.m[282, "File name"], self.filename or _tr.m[283, "not set"]),
        ))


def main_with_annotation():
    from AnyQt.QtWidgets import QApplication
    from OWNxFile import OWNxFile
    app = QApplication([])
    file_widget = OWNxFile()
    file_widget.Outputs.network.send = WidgetPreview(OWNxSave).run
    file_widget.open_net_file("../networks/leu_by_genesets.net")


def main_without_annotation():
    net = readwrite.read_pajek("../networks/leu_by_genesets.net")
    WidgetPreview(OWNxSave).run(net)


if __name__ == "__main__":  # pragma: no cover
    main_with_annotation()
