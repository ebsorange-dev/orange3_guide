"""
Save Images — 내 PC 저장 (브라우저 showSaveFilePicker)

원본 OWSaveImages 는 컨테이너 안의 QFileDialog 로 디렉터리를 고른 뒤 그 디렉터리에
이미지들을 분류 폴더 구조로 저장한다 (서버 파일시스템). PC 저장으로 가져오려면
디렉터리 자체를 옮겨야 하므로 다음 전략을 사용:

  1) 원본 save_images() 로직을 컨테이너의 임시 디렉터리(/config/.pc_download/<basename>/)에
     원본과 동일한 구조(클래스별 서브폴더 + 이미지 파일)로 저장
  2) 그 디렉터리를 .zip 으로 압축해 /config/.pc_download/<basename>.zip 생성
  3) /config/.pc_download_ready 에 신호 JSON 작성 (basename, files, widget_id)
  4) 브라우저 폴링이 showSaveFilePicker() 호출 → 사용자가 .zip 저장 위치 선택
  5) 저장 완료 후 /config/.pc_save_name 으로 파일명 회신 → 버튼 텍스트 갱신

같은 widget_id 의 두 번째 클릭부터는 캐시된 핸들로 silent 저장 (Save Model 패턴과 동일).
위젯 삭제 + 재추가 시 새 widget_id 발급되어 picker 가 다시 호출됨.
"""
from orangecanvas.utils.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.utils.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.imageanalytics", "biolab.si", "Orange")
del Translator

import os
import os.path
import json
import uuid
import shutil
import zipfile
from collections import deque
from os.path import join, isdir
from types import SimpleNamespace as namespace
from urllib.parse import urlparse

from AnyQt.QtWidgets import QGridLayout, QMessageBox
from AnyQt.QtCore import Qt, QSize, QTimer

from Orange.data.table import Table
from Orange.widgets import gui, widget
from Orange.widgets.utils.concurrent import TaskState, ConcurrentWidgetMixin
from Orange.widgets.utils.itemmodels import VariableListModel
from Orange.widgets.settings import Setting
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import Input, OWWidget

from orangecontrib.imageanalytics.image_embedder import MODELS
from orangecontrib.imageanalytics.utils.embedder_utils import ImageLoader
from orangecontrib.imageanalytics.utils.image_utils import (
    extract_paths,
    filter_image_attributes,
)

SUPPORTED_FILE_FORMATS = ["png", "jpg", "gif", "tiff", "pdf", "bmp", "eps", "ico"]


class Result(namespace):
    paths = None


def _get_classes(data):
    return list(map(data.domain.class_var.repr_val, data.Y)) \
        if data.domain.class_var else None


def _clean_dir(dir_name):
    if isdir(dir_name):
        shutil.rmtree(dir_name)


def _create_dir(path):
    dir_path = os.path.dirname(path)
    if not isdir(dir_path):
        os.makedirs(dir_path)


def _is_url(url):
    return urlparse(url).scheme != ""


def _save_an_image(loader, origin, save_path, target_size):
    _create_dir(save_path)
    _, orig_ext = os.path.splitext(origin)
    _, save_ext = os.path.splitext(save_path)
    if not _is_url(origin) and target_size is None and orig_ext == save_ext:
        if os.path.exists(origin):
            shutil.copyfile(origin, save_path)
    else:
        image = loader.load_image_or_none(origin, target_size)
        if image is not None:
            image.save(save_path)


def _prepare_dir_and_save_images(
        paths_queue, dir_name, target_size, previously_saved, state: TaskState):
    res = Result(paths=paths_queue)
    if previously_saved == 0:
        _clean_dir(dir_name)

    steps = len(paths_queue) + previously_saved
    loader = ImageLoader()
    while res.paths:
        from_path, to_path = res.paths.popleft()
        _save_an_image(loader, from_path, to_path, target_size)

        state.set_progress_value((1 - len(res.paths) / steps) * 100)
        state.set_partial_result(res)
        if state.is_interruption_requested():
            return res

    return res


class OWSaveImages(OWWidget, ConcurrentWidgetMixin):
    name = _tr.m[123, "Save Images"]
    description = _tr.m[124, "Save images in the directory structure."]
    icon = "icons/SaveImages.svg"
    keywords = _tr.m[125, "save images, save, images"]

    userhome = os.path.expanduser(f"~{os.sep}")

    class Inputs:
        data = Input(_tr.m[126, "Data"], Table, id="Data")

    class Error(widget.OWWidget.Error):
        no_file_name = widget.Msg(_tr.m[127, "Directory name is not set."])
        general_error = widget.Msg("{}")
        no_image_attribute = widget.Msg(_tr.m[128, "Data does not have any image attribute."])

    want_main_area = False
    resizing_enabled = False

    last_dir: str = Setting("")
    dirname: str = Setting("", schema_only=True)
    auto_save: bool = Setting(False)
    use_scale: bool = Setting(False)
    scale_index: int = Setting(0)
    file_format_index: int = Setting(0)
    image_attr_current_index: int = Setting(0)

    image_attributes = None
    data = None
    paths_queue = None
    previously_saved = 0

    def __init__(self):
        OWWidget.__init__(self)
        ConcurrentWidgetMixin.__init__(self)

        # 위젯 인스턴스 고유 ID — 브라우저가 위젯별로 파일 핸들을 분리 캐시.
        # 매 인스턴스마다 새로 발급 → 위젯 삭제+재추가 시 picker 가 다시 호출됨.
        self._widget_id = f"saveimages-{uuid.uuid4().hex[:8]}"
        # 첫 PC 저장 후 True → auto_save 가 PC 저장으로 분기
        self._pc_save_active = False

        self.available_scales = sorted(
            MODELS.values(), key=lambda x: x["order"])

        # create grid (원본 그대로)
        grid = QGridLayout()
        gui.widgetBox(self.controlArea, orientation=grid)

        # image attribute selection
        hbox_attr = gui.hBox(None)
        self.cb_image_attr = gui.comboBox(
            widget=hbox_attr, master=self, value='image_attr_current_index',
            label=_tr.m[129, 'Image attribute'], orientation=Qt.Horizontal,
            callback=self.setting_changed)
        grid.addWidget(hbox_attr, 0, 0, 1, 2)

        # Scale images option
        hbox_scale = gui.hBox(None)
        gui.checkBox(
            widget=hbox_scale, master=self, value="use_scale",
            label=_tr.m[130, "Scale images to "], callback=self.setting_changed)
        self.scale_combo = gui.comboBox(
            widget=hbox_scale, master=self, value="scale_index",
            items=["{} ({}×{})".format(v["name"], *v["target_image_size"])
                   for v in self.available_scales],
            callback=self.setting_changed)
        grid.addWidget(hbox_scale, 1, 0, 1, 2)

        # file format
        hbox_format = gui.hBox(None)
        gui.comboBox(
            widget=hbox_format, master=self, value="file_format_index",
            label=_tr.m[131, "File format"],
            items=[x.upper() for x in SUPPORTED_FILE_FORMATS],
            orientation=Qt.Horizontal, callback=self.setting_changed)
        grid.addWidget(hbox_format, 2, 0, 1, 2)

        # auto save
        grid.addWidget(
            gui.checkBox(
                widget=None, master=self, value="auto_save",
                label=_tr.m[132, "Autosave when receiving new data or settings change"],
                callback=self._update_messages),
            3, 0, 1, 2)

        # buttons — 콜백을 PC 저장 경로로 교체
        self.bt_save = gui.button(
            self.buttonsArea, self, _tr.m[133, "Save"],
            callback=lambda: self._save_to_pc(force_new=False))
        gui.button(
            self.buttonsArea, self, _tr.m[134, "Save as ..."],
            callback=lambda: self._save_to_pc(force_new=True))

        # 브라우저가 저장 완료 후 /config/.pc_save_name 에 남기는 파일명 폴링
        self._pc_name_timer = QTimer(self)
        self._pc_name_timer.timeout.connect(self._poll_pc_saved_name)
        self._pc_name_timer.start(1000)

        self.scale_combo.setEnabled(self.use_scale)
        self.adjustSize()
        self._update_messages()

    # ── PC 저장 ────────────────────────────────────────────────────────────
    def _save_to_pc(self, force_new=False):
        # 이미지 미입력 상태에서는 picker 호출하지 않음 (저장할 게 없음)
        if self.data is None or not self.image_attributes:
            return
        # 진행 중인 작업이 있으면 취소 (원본 save_file 동작 보존)
        if self.task is not None:
            self.cancel()
            self.bt_save.setText(_tr.m[137, "Resume save"])
            return

        self.Error.general_error.clear()

        # basename — Save 위젯은 폴더 단위 → ZIP 파일명으로 사용
        basename = "images"
        download_dir = '/config/.pc_download'
        try:
            os.makedirs(download_dir, exist_ok=True)
            # 기존 파일 정리
            for _f in os.listdir(download_dir):
                _fp = os.path.join(download_dir, _f)
                try:
                    if os.path.isdir(_fp):
                        shutil.rmtree(_fp)
                    else:
                        os.remove(_fp)
                except OSError:
                    pass

            # 1) 원본 save_images() 와 동일한 디렉터리 구조로 임시 저장
            tmp_dir = os.path.join(download_dir, basename)
            self.dirname = tmp_dir  # gather_paths 가 self.dirname 사용
            from_paths, to_paths = self.gather_paths()
            paths_queue = deque(list(zip(from_paths, to_paths)))
            image_size = (self.available_scales[self.scale_index]["target_image_size"]
                          if self.use_scale else None)

            # 백그라운드 작업 시작 — on_done 콜백에서 ZIP 생성 + 신호 작성으로 분기
            self._pc_pending = {
                "basename": basename,
                "download_dir": download_dir,
                "tmp_dir": tmp_dir,
                "force_new": bool(force_new),
            }
            self.bt_save.setText("Stop")
            self.start(_prepare_dir_and_save_images, paths_queue,
                       tmp_dir, image_size, 0)
        except Exception as e:
            QMessageBox.critical(self, "내 PC 저장", f"이미지 저장 실패: {e}")

    def _finalize_pc_save(self):
        """원본 save_images 완료 후 호출: tmp_dir 를 ZIP 으로 묶어 신호 파일 작성."""
        if not getattr(self, "_pc_pending", None):
            return
        info = self._pc_pending
        self._pc_pending = None
        basename = info["basename"]
        download_dir = info["download_dir"]
        tmp_dir = info["tmp_dir"]
        force_new = info["force_new"]
        try:
            zip_name = f"{basename}.zip"
            zip_path = os.path.join(download_dir, zip_name)
            # 디렉터리를 zip 으로 패키징 (분류 폴더 구조 유지)
            with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
                for root, _, files in os.walk(tmp_dir):
                    for fn in files:
                        full = os.path.join(root, fn)
                        arc = os.path.relpath(full, tmp_dir)
                        zf.write(full, arcname=arc)
            # ZIP 만들었으면 원본 임시 디렉터리 정리
            try:
                shutil.rmtree(tmp_dir)
            except OSError:
                pass
            saved = [{"label": "ZIP archive (*.zip)", "filename": zip_name}]
            with open('/config/.pc_download_ready', 'w', encoding='utf-8') as f:
                json.dump({"basename": basename, "files": saved,
                           "force_new": force_new,
                           "widget_id": self._widget_id}, f, ensure_ascii=False)
            if not force_new:
                self._pc_save_active = True
                self._update_messages()
        except Exception as e:
            QMessageBox.critical(self, "내 PC 저장", f"ZIP 생성 실패: {e}")

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

    # ── 원본 메서드 (UI 보존) ─────────────────────────────────────────────────
    def setting_changed(self):
        self.scale_combo.setEnabled(self.use_scale)
        self.reset_queue()
        if self.auto_save and self._pc_save_active:
            self._save_to_pc(force_new=False)

    def gather_paths(self):
        classes = _get_classes(self.data)
        file_paths_attr = self.image_attributes[self.image_attr_current_index]
        file_paths = extract_paths(self.data, file_paths_attr)
        file_format = SUPPORTED_FILE_FORMATS[self.file_format_index]
        from_paths, to_paths = [], []

        for i, path in enumerate(file_paths):
            from_paths.append(path)
            filename = os.path.basename(path)
            if "." in filename:
                filename = filename.rsplit(".")[0]
            to_paths.append(join(join(self.dirname, classes[i])
                                 if classes is not None else self.dirname,
                                 "{}.{}".format(filename, file_format)))
        return from_paths, to_paths

    def on_partial_result(self, result: Result):
        self.paths_queue = result.paths
        self.previously_saved += 1

    def on_done(self, result: Result):
        assert len(result.paths) == 0
        self.bt_save.setText(_tr.m[135, "Save"])
        self.reset_queue()
        # PC 저장 모드이면 ZIP 생성 + 신호 파일 작성
        self._finalize_pc_save()

    def on_exception(self, ex: Exception):
        self.Error.general_error(ex)
        self.bt_save.setText(_tr.m[136, "Save"])
        self.reset_queue()
        self._pc_pending = None

    def reset_queue(self):
        self.paths_queue = None
        self.previously_saved = 0

    @Inputs.data
    def dataset(self, data):
        self.Error.clear()
        self.data = data
        self._update_messages()
        self.image_attributes = (
            filter_image_attributes(data) if data is not None else []
        )
        self._update_image_attributes()
        # PC 저장 활성화된 경우 auto_save 동작
        if self.auto_save and self._pc_save_active and self.data is not None:
            self._save_to_pc(force_new=False)

    def _update_image_attributes(self):
        self.cb_image_attr.setModel(VariableListModel(self.image_attributes))
        self.cb_image_attr.setCurrentIndex(self.image_attr_current_index)
        if not self.image_attributes:
            self.Error.no_image_attribute()

    def _update_messages(self):
        # PC 저장 활성화 + auto_save → 디렉터리 미설정 에러 억제 (PC 저장은 dirname 안 씀)
        if getattr(self, '_pc_save_active', False) and self.auto_save:
            self.Error.no_file_name.clear()
        else:
            self.Error.no_file_name(
                shown=not self.dirname and self.auto_save)

    def clear(self):
        super().clear()
        self.cancel()

    def onDeleteWidget(self):
        self.shutdown()
        super().onDeleteWidget()

    def sizeHint(self):
        return QSize(500, 450)


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWSaveImages).run(
        Table("https://datasets.biolab.si/core/bone-healing.xlsx"))
