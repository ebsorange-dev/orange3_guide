"""
Save Model — 내 PC 저장 (브라우저 showSaveFilePicker)

OWSaveBase 기본 동작은 컨테이너 안의 QFileDialog 를 띄워 *서버*의 파일시스템을
보여주므로, 사용자 PC 의 탐색창을 띄울 수 없다. 본 override 는 OWSave (Save Data)
가 사용하는 동일한 PC 저장 인프라를 그대로 사용한다:

  1) pickle 결과를 컨테이너의 /config/.pc_download/<name>.pkcls 로 기록
  2) /config/.pc_download_ready 에 JSON 신호(basename + files + force_new)
  3) 브라우저(session-manager 의 wrapper page) 가 1.5s 주기로 폴링하다가
     window.showSaveFilePicker() 로 *사용자 PC* 의 네이티브 저장 다이얼로그를
     띄우고, /pc_download/get 로 파일을 받아 사용자가 고른 핸들에 기록.
  4) 저장 완료 후 /pc_download/notify_saved → /config/.pc_save_name 에 파일명이
     남고, 본 위젯이 1s 폴링으로 bt_save 텍스트를 'Save as <name>' 로 갱신.

저장 로직 자체(pickle.dump)는 원본 OWSaveModel.do_save 와 동일.
"""
import os
import json
import pickle
import uuid

from Orange.widgets.widget import Input
from Orange.base import Model
from Orange.widgets.utils.save.owsavebase import OWSaveBase
from Orange.widgets.utils.widgetpreview import WidgetPreview


class OWSaveModel(OWSaveBase):
    name = "Save Model"
    description = "Save a trained model to an output file."
    icon = "icons/SaveModel.svg"
    replaces = ["Orange.widgets.classify.owsaveclassifier.OWSaveClassifier"]
    priority = 3000
    keywords = "save model, save"

    class Inputs:
        model = Input("Model", Model)

    filters = ["Pickled model (*.pkcls)"]

    def __init__(self):
        super().__init__()
        # 첫 PC 저장 후 True → auto_save 가 PC 저장을 호출
        self._pc_save_active = False
        # 위젯 인스턴스 고유 ID — 브라우저가 위젯별로 파일 핸들을 분리 캐시하기
        # 위해 사용. 같은 세션에 Save Model 위젯이 여러 개 있을 때, 새로 추가된
        # 위젯이 앞 위젯의 저장 핸들을 재사용하지 않도록 보장한다. 매 인스턴스
        # 마다 새로 발급되므로 워크플로 재로딩 시에도 항상 "미설정" 상태로 시작.
        self._widget_id = f"savemodel-{uuid.uuid4().hex[:8]}"
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

    @Inputs.model
    def set_model(self, model):
        self.data = model
        self.on_new_input()

    # ── PC 저장 ────────────────────────────────────────────────────────────
    def _save_to_pc(self, force_new=False):
        from AnyQt.QtWidgets import QMessageBox
        # 모델 미입력 상태여도 PC 탐색창은 동일하게 호출 (사용자 요청).
        # self.data 가 None 이면 pickle.dump(None, f) 가 그대로 기록되어
        # 사용자가 선택한 PC 경로에 빈 모델(None)이 저장됨.
        # basename 우선순위: 기존 stored_name → 'model'
        if self.stored_name:
            basename = os.path.splitext(os.path.basename(self.stored_name))[0]
        else:
            basename = 'model'
        download_dir = '/config/.pc_download'
        try:
            os.makedirs(download_dir, exist_ok=True)
            # 기존 파일 정리
            for _f in os.listdir(download_dir):
                try:
                    os.remove(os.path.join(download_dir, _f))
                except OSError:
                    pass
            fname = f'{basename}.pkcls'
            fpath = os.path.join(download_dir, fname)
            # 저장 로직: 원본 do_save 와 동일한 pickle.dump
            with open(fpath, 'wb') as f:
                pickle.dump(self.data, f)
            saved = [{"label": "Pickled model (*.pkcls)", "filename": fname}]
            with open('/config/.pc_download_ready', 'w', encoding='utf-8') as f:
                json.dump({"basename": basename, "files": saved,
                           "force_new": bool(force_new),
                           "widget_id": self._widget_id}, f, ensure_ascii=False)
            # 첫 저장(force_new=False) 시 PC 저장 활성화 → auto_save 가 PC 저장 호출
            if not force_new:
                self._pc_save_active = True
                self.update_messages()
        except Exception as e:
            QMessageBox.critical(self, "내 PC 저장", f"저장 실패: {e}")

    def _poll_pc_saved_name(self):
        """브라우저가 저장 완료 후 /config/.pc_save_name 에 파일명을 남기면 버튼 갱신"""
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

    # ── 원본 do_save (호출되는 일은 거의 없으나 호환성 유지) ───────────────
    def do_save(self):
        with open(self.filename, "wb") as f:
            pickle.dump(self.data, f)


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWSaveModel).run()
