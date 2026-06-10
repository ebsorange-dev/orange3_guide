from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator
import os.path

from Orange.data.table import Table
from Orange.data.io import \
    TabReader, CSVReader, PickleReader, ExcelReader, XlsReader, FileFormat
from Orange.widgets import gui, widget
from Orange.widgets.widget import Input
from Orange.widgets.settings import Setting
from Orange.widgets.utils.save.owsavebase import OWSaveBase
from Orange.widgets.utils.widgetpreview import WidgetPreview


_userhome = os.path.expanduser(f"~{os.sep}")


class OWSave(OWSaveBase):
    name = _tr.m[1446, "Save Data"]
    description = _tr.m[1447, "Save data to an output file."]
    icon = "icons/Save.svg"
    category = _tr.m[1448, "Data"]
    keywords = _tr.m[1449, "save data, export"]

    settings_version = 3

    class Inputs:
        data = Input(_tr.m[1450, "Data"], Table, id="Data")

    class Error(OWSaveBase.Error):
        unsupported_sparse = widget.Msg(_tr.m[1451, "Use Pickle format for sparse data."])

    add_type_annotations = Setting(True)

    builtin_order = [TabReader, CSVReader, PickleReader, ExcelReader, XlsReader]

    def __init__(self):
        super().__init__(2)
        import uuid
        # 내 PC 저장 활성화 플래그: 첫 PC 저장 후 True → auto_save가 PC 저장을 호출
        self._pc_save_active = False
        # 위젯 인스턴스 고유 ID — 브라우저가 위젯별로 파일 핸들을 분리 캐시.
        # 매 인스턴스마다 새 UUID → 위젯 삭제+재추가 시 새 widget_id → 캐시 miss → picker 재호출
        self._widget_id = f"savedata-{uuid.uuid4().hex[:8]}"
        self.grid.addWidget(
            gui.checkBox(
                None, self, "add_type_annotations",
                _tr.m[1452, "Add type annotations to header"],
                tooltip=
                (_tr.m[1453, "Some formats (Tab-delimited, Comma-separated) can include \n"] + _tr.m[1454, "additional information about variables types in header rows."]),
                callback=self.update_messages),
            0, 0, 1, 2)
        self.grid.setRowMinimumHeight(1, 8)
        # OWSaveBase가 만든 Save / Save as ... 버튼의 callback을 PC 저장 기능으로 교체
        # Save: 첫 클릭 위치 묻기, 이후 같은 위치에 자동 저장 (force_new=False)
        try:
            self.bt_save.clicked.disconnect()
        except Exception:
            pass
        self.bt_save.clicked.connect(lambda: self._save_to_pc(force_new=False))
        # Save as ...: 항상 새로운 저장 다이얼로그 (force_new=True)
        from AnyQt.QtWidgets import QPushButton
        for btn in self.buttonsArea.findChildren(QPushButton):
            if btn is not self.bt_save:
                try:
                    btn.clicked.disconnect()
                except Exception:
                    pass
                btn.clicked.connect(lambda: self._save_to_pc(force_new=True))
                break
        # 브라우저에서 저장된 파일명 폴링 (1초마다) → bt_save 텍스트 "Save as 이름" 갱신
        from AnyQt.QtCore import QTimer
        self._pc_name_timer = QTimer(self)
        self._pc_name_timer.timeout.connect(self._poll_pc_saved_name)
        self._pc_name_timer.start(1000)
        self.adjustSize()

    def _poll_pc_saved_name(self):
        """브라우저가 저장 완료 후 /config/.pc_save_name 에 파일명을 남기면 버튼 텍스트 갱신"""
        import os
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

    def _save_to_pc(self, force_new=False):
        from AnyQt.QtWidgets import QMessageBox
        if self.data is None:
            QMessageBox.warning(self, "내 PC 저장", "저장할 데이터가 없습니다.")
            return
        # 베이스명 우선순위: filename(Save as 지정) → data.name(File 위젯 원본) → 'data'
        import os, json
        if self.filename:
            basename = os.path.splitext(os.path.basename(self.filename))[0]
            # .tab.gz 같은 이중 확장자 처리
            if basename.endswith(('.tab', '.csv', '.pkl', '.xlsx', '.xls')):
                basename = os.path.splitext(basename)[0]
        elif getattr(self.data, 'name', None):
            basename = os.path.splitext(os.path.basename(self.data.name))[0]
        else:
            basename = 'data'
        download_dir = '/config/.pc_download'
        try:
            os.makedirs(download_dir, exist_ok=True)
            # 기존 파일 정리
            for _f in os.listdir(download_dir):
                try: os.remove(os.path.join(download_dir, _f))
                except OSError: pass
            # 모든 지원 포맷 저장 (sparse 미지원 포맷은 자동 제외, 저장 실패 시 건너뜀)
            sparse = self.data.is_sparse()
            saved = []
            for label, writer in self.get_filters().items():
                if sparse and not writer.SUPPORT_SPARSE_DATA:
                    continue
                ext = writer.EXTENSIONS[0]
                if "Compressed" in label:
                    fname = f'{basename}{ext}.gz'
                else:
                    fname = f'{basename}{ext}'
                fpath = os.path.join(download_dir, fname)
                try:
                    writer.write(fpath, self.data, self.add_type_annotations)
                    saved.append({"label": label, "filename": fname})
                except Exception:
                    pass
            if not saved:
                QMessageBox.warning(self, "내 PC 저장", "저장 가능한 포맷이 없습니다.")
                return
            # 신호 파일: JSON으로 사용 가능 파일 목록 + force_new 플래그 + widget_id 기록
            # widget_id 가 있어야 브라우저가 위젯별로 핸들 캐시를 분리 → 위젯 삭제+재추가 시 picker 재호출
            with open('/config/.pc_download_ready', 'w', encoding='utf-8') as f:
                json.dump({"basename": basename, "files": saved,
                           "force_new": bool(force_new),
                           "widget_id": self._widget_id}, f, ensure_ascii=False)
            # 첫 저장 (force_new=False) 시 PC 저장 활성화 → auto_save가 PC 저장 호출
            if not force_new:
                self._pc_save_active = True
                self.update_messages()
        except Exception as e:
            QMessageBox.critical(self, "내 PC 저장", f"저장 실패: {e}")

    def on_new_input(self):
        """입력 데이터 변경 시 호출. PC 저장이 활성화된 경우 PC 저장을 자동 호출."""
        # 기본 메시지/상태 갱신 (super.on_new_input의 일부 로직 재사용)
        self.Error.clear()
        self.Warning.clear()
        self.Information.clear()
        self.update_messages()
        self.update_status()
        # auto_save 분기:
        #  PC 저장 활성화 → _save_to_pc (PC 저장 핸들 재사용)
        #  PC 저장 미활성 + filename 있음 → 기본 save_file (디스크에 저장)
        if self.auto_save:
            if getattr(self, '_pc_save_active', False) and self.data is not None:
                self._save_to_pc(force_new=False)
            elif self.filename:
                self.save_file()

    @classmethod
    def get_filters(cls):
        writers = [format for format in FileFormat.formats
                   if getattr(format, 'write_file', None)
                   and getattr(format, "EXTENSIONS", None)]
        writers.sort(key=lambda writer: cls.builtin_order.index(writer)
                     if writer in cls.builtin_order else 99)

        return {
            **{f"{w.DESCRIPTION} (*{w.EXTENSIONS[0]})": w
               for w in writers},
            **{_tr.e(_tr.c(1455, f"Compressed {w.DESCRIPTION} (*{w.EXTENSIONS[0]}.gz)")): w
               for w in writers if w.SUPPORT_COMPRESSED}
        }

    @Inputs.data
    def dataset(self, data):
        self.data = data
        self.on_new_input()

    def do_save(self):
        if self.writer is None:
            super().do_save()  # This will do nothing but indicate an error
            return
        if self.data.is_sparse() and not self.writer.SUPPORT_SPARSE_DATA:
            return
        self.writer.write(self.filename, self.data, self.add_type_annotations)

    def update_messages(self):
        super().update_messages()
        self.Error.unsupported_sparse(
            shown=self.data is not None and self.data.is_sparse()
            and self.filename
            and self.writer is not None and not self.writer.SUPPORT_SPARSE_DATA)
        # PC 저장 활성화 + auto_save 켜져 있으면 "File name is not set" 에러 제거
        # (PC 저장은 self.filename을 설정하지 않으므로 기본 구현이 잘못 표시함)
        if getattr(self, '_pc_save_active', False) and self.auto_save:
            self.Error.no_file_name.clear()

    def send_report(self):
        self.report_data_brief(self.data)
        writer = self.writer
        noyes = [_tr.m[1456, "No"], _tr.m[1457, "Yes"]]
        self.report_items((
            (_tr.m[1458, "File name"], self.filename or _tr.m[1459, "not set"]),
            (_tr.m[1460, "Format"], writer and writer.DESCRIPTION),
            (_tr.m[1461, "Type annotations"],
             writer and writer.OPTIONAL_TYPE_ANNOTATIONS
             and noyes[self.add_type_annotations])
        ))

    @classmethod
    def migrate_settings(cls, settings, version=0):
        def migrate_to_version_2():
            # Set the default; change later if possible
            settings.pop("compression", None)
            settings["filter"] = next(iter(cls.get_filters()))
            filetype = settings.pop("filetype", None)
            if filetype is None:
                return

            ext = cls._extension_from_filter(filetype)
            if settings.pop("compress", False):
                for afilter in cls.get_filters():
                    if ext + ".gz" in afilter:
                        settings["filter"] = afilter
                        return
                # If not found, uncompressed may have been erroneously set
                # for a writer that didn't support if (such as .xlsx), so
                # fall through to uncompressed
            for afilter in cls.get_filters():
                if ext in afilter:
                    settings["filter"] = afilter
                    return

        if version < 2:
            migrate_to_version_2()

        if version < 3:
            if settings.get("add_type_annotations") and \
                    settings.get("stored_name") and \
                    os.path.splitext(settings["stored_name"])[1] == ".xlsx":
                settings["add_type_annotations"] = False

    def initial_start_dir(self):
        if self.filename and os.path.exists(os.path.split(self.filename)[0]):
            return self.filename
        else:
            data_name = getattr(self.data, 'name', '')
            if data_name:
                if self.writer is None:
                    self.filter = self.default_filter()
                assert self.writer is not None
                data_name += self.writer.EXTENSIONS[0]
            return os.path.join(self.last_dir or _userhome, data_name)

    def valid_filters(self):
        if self.data is None or not self.data.is_sparse():
            return self.get_filters()
        else:
            return {filt: writer for filt, writer in self.get_filters().items()
                    if writer.SUPPORT_SPARSE_DATA}

    def default_valid_filter(self):
        valid = self.valid_filters()
        if self.data is None or not self.data.is_sparse() \
                or (self.filter in valid
                        and valid[self.filter].SUPPORT_SPARSE_DATA):
            return self.filter
        return next(iter(valid))


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWSave).run(Table("iris"))
