"""
Save Distance Matrix — 내 PC 저장 (브라우저 showSaveFilePicker)

OWSaveBase 기본 동작은 컨테이너 안의 QFileDialog 를 띄워 *서버*의 파일시스템을
보여주므로, 사용자 PC 의 탐색창을 띄울 수 없다. 본 override 는 OWSave / OWSaveModel
이 사용하는 동일한 PC 저장 인프라를 그대로 사용한다:

  1) 결과를 컨테이너의 /config/.pc_download/<name>.{xlsx,dst} 로 기록
  2) /config/.pc_download_ready 에 JSON 신호(basename + files + force_new)
  3) 브라우저(session-manager 의 wrapper page) 가 1.5s 주기로 폴링하다가
     window.showSaveFilePicker() 로 *사용자 PC* 의 네이티브 저장 다이얼로그를
     띄우고, /pc_download/get 로 파일을 받아 사용자가 고른 핸들에 기록.
  4) 저장 완료 후 /pc_download/notify_saved → /config/.pc_save_name 에 파일명이
     남고, 본 위젯이 1s 폴링으로 bt_save 텍스트를 'Save as <name>' 로 갱신.

저장 로직 자체(DistMatrix.save)는 원본 OWSaveDistances.do_save 와 동일.
"""
from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator

import os
import json
import uuid

from Orange.widgets.widget import Input, Msg
from Orange.misc import DistMatrix
from Orange.widgets.utils.save.owsavebase import OWSaveBase
from Orange.widgets.utils.widgetpreview import WidgetPreview


class OWSaveDistances(OWSaveBase):
    name = _tr.m[3021, "Save Distance Matrix"]
    description = _tr.m[3022, "Save distance matrix to an output file."]
    icon = "icons/SaveDistances.svg"
    keywords = _tr.m[3023, "save distance matrix, distance matrix, save"]

    filters = [_tr.m[3024, "Excel File (*.xlsx)"], _tr.m[3025, "Distance File (*.dst)"]]

    class Warning(OWSaveBase.Warning):
        table_not_saved = Msg(_tr.m[3026, "Associated data was not saved."])
        part_not_saved = Msg(_tr.m[3027, "Data associated with {} was not saved."])

    class Inputs:
        distances = Input(_tr.m[3028, "Distances"], DistMatrix, id="Distances")

    def __init__(self):
        super().__init__()
        # 첫 PC 저장 후 True → auto_save 가 PC 저장을 호출
        self._pc_save_active = False
        # 위젯 인스턴스 고유 ID — 브라우저가 위젯별로 파일 핸들을 분리 캐시하기 위해 사용
        self._widget_id = f"savedistances-{uuid.uuid4().hex[:8]}"
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

    @Inputs.distances
    def set_distances(self, data):
        self.data = data
        self.on_new_input()

    # ── PC 저장 ────────────────────────────────────────────────────────────
    def _save_to_pc(self, force_new=False):
        from AnyQt.QtWidgets import QMessageBox
        # 거리행렬 미입력 상태여도 PC 탐색창은 동일하게 호출 (Save Model 과 동일 정책).
        # self.data 가 None 이면 빈 placeholder 파일을 기록하여 사용자가 선택한
        # PC 경로에 빈 파일이 저장됨.
        # basename 우선순위: 기존 stored_name → 'distances'
        if self.stored_name:
            basename = os.path.splitext(os.path.basename(self.stored_name))[0]
        else:
            basename = 'distances'
        download_dir = '/config/.pc_download'
        try:
            os.makedirs(download_dir, exist_ok=True)
            # 기존 파일 정리
            for _f in os.listdir(download_dir):
                try:
                    os.remove(os.path.join(download_dir, _f))
                except OSError:
                    pass
            # 단일 포맷만 picker 에 전송 — 같은 MIME 타입의 다중 type 엔트리는
            # Chrome showSaveFilePicker 가 거부하거나 .dst 같은 비표준 확장자를
            # 차단하여 anchor 다운로드 폴백(silent)으로 빠지는 문제를 회피.
            # 위젯의 self.filter 설정(기본 = filters[0]=Excel) 을 따른다.
            current_filter = (self.filter or "Excel File (*.xlsx)") if hasattr(self, 'filter') else "Excel File (*.xlsx)"
            # 한글 모드에서 self.filter 가 번역되어 있을 수 있어 .xlsx/.dst 키워드로 구분
            if ".dst" in str(current_filter).lower():
                label, ext = "Distance File (*.dst)", ".dst"
            else:
                label, ext = "Excel File (*.xlsx)", ".xlsx"
            fname = f'{basename}{ext}'
            fpath = os.path.join(download_dir, fname)
            saved = []
            try:
                if self.data is not None:
                    self.data.save(fpath)
                else:
                    # 데이터 미입력 — 빈 파일 생성 (탐색창은 표시되도록)
                    with open(fpath, 'wb') as _ef:
                        _ef.write(b'')
                saved.append({"label": label, "filename": fname})
            except Exception:
                pass
            if not saved:
                QMessageBox.warning(self, "내 PC 저장", "저장 가능한 포맷이 없습니다.")
                return
            with open('/config/.pc_download_ready', 'w', encoding='utf-8') as f:
                json.dump({"basename": basename, "files": saved,
                           "force_new": bool(force_new),
                           "widget_id": self._widget_id}, f, ensure_ascii=False)
            # 첫 저장(force_new=False) 시 PC 저장 활성화 → auto_save 가 PC 저장 호출
            if not force_new:
                self._pc_save_active = True
                self.update_messages()
            # 원본 do_save 의 부수효과(연관 데이터 미저장 경고) 재현 — data 있을 때만
            if self.data is not None:
                dist = self.data
                skip_row = not dist.has_row_labels() and dist.row_items is not None
                skip_col = not dist.has_col_labels() and dist.col_items is not None
                self.Warning.table_not_saved(shown=skip_row and skip_col)
                self.Warning.part_not_saved(
                    _tr.m[3029, "columns"] if skip_col else _tr.m[3030, "rows"],
                    shown=skip_row != skip_col,
                )
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
        dist = self.data
        dist.save(self.filename)
        skip_row = not dist.has_row_labels() and dist.row_items is not None
        skip_col = not dist.has_col_labels() and dist.col_items is not None
        self.Warning.table_not_saved(shown=skip_row and skip_col)
        self.Warning.part_not_saved(_tr.m[3029, "columns"] if skip_col else _tr.m[3030, "rows"],
                                    shown=skip_row != skip_col,)

    def send_report(self):
        self.report_items((
            (_tr.m[3031, "Input"], _tr.m[3032, "none"] if self.data is None else self._description()),
            (_tr.m[3033, "File name"], self.filename or _tr.m[3034, "not set"])))

    def _description(self):
        dist = self.data
        labels = _tr.m[3035, " and "].join(
            filter(None, (dist.row_items is not None and _tr.m[3036, "row"],
                          dist.col_items is not None and _tr.m[3037, "column"])))
        if labels:
            labels = _tr.e(_tr.c(3038, f"; {labels} labels"))
        return _tr.e(_tr.c(3039, f"{len(dist)}-dimensional matrix{labels}"))


if __name__ == "__main__":
    from Orange.data import Table
    from Orange.distance import Euclidean
    WidgetPreview(OWSaveDistances).run(Euclidean(Table("iris")))
