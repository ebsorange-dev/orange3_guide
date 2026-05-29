from orangecanvas.utils.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.utils.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.imageanalytics", "biolab.si", "Orange")
del Translator
"""
Import Images
-------------

Import images 'into' canvas session from a local file system

Allows the user to load[1] all images in a directory

.. [1]:
    I.e create a Table with the specially constructed image string variable

"""
import sys
import os
import enum
import warnings
import logging
import traceback

from types import SimpleNamespace as namespace

from AnyQt.QtCore import Qt, QEvent, QFileInfo, QThread
from AnyQt.QtCore import pyqtSlot as Slot
from AnyQt.QtGui import QStandardItem, QDropEvent

from AnyQt.QtWidgets import (
    QAction, QPushButton, QComboBox, QApplication, QStyle, QFileDialog,
    QFileIconProvider, QStackedWidget, QProgressBar, QWidget, QHBoxLayout,
    QVBoxLayout, QLabel
)

from Orange.data import Table
from Orange.widgets import widget, gui, settings
from Orange.widgets.utils.filedialogs import RecentPath
from Orange.widgets.utils.concurrent import (
    ThreadExecutor, FutureWatcher, methodinvoke
)
from Orange.widgets.utils.localization import pl

from orangecanvas.preview.previewbrowser import TextLabel

from Orange.widgets.utils.signals import Output

from orangecontrib.imageanalytics.import_images import ImportImages

def prettyfypath(path):
    home = os.path.expanduser("~/")
    if path.startswith(home):  # case sensitivity!
        path = os.path.join("~", os.path.relpath(path, home))
    return path


log = logging.getLogger(__name__)


class standard_icons(object):
    def __init__(self, widget=None):
        self.widget = widget
        if widget is None:
            self.style = QApplication.instance().style()
        else:
            self.style = widget.style()

    @property
    def dir_open_icon(self):
        return self.style.standardIcon(QStyle.SP_DirOpenIcon)

    @property
    def reload_icon(self):
        return self.style.standardIcon(QStyle.SP_BrowserReload)

    @property
    def cancel_icon(self):
        return self.style.standardIcon(QStyle.SP_DialogCancelButton)


class RuntimeEvent(QEvent):
    Init = QEvent.registerEventType()


def RecentPath_asqstandarditem(pathitem):
    icon_provider = QFileIconProvider()
    # basename of a normalized name (strip right path component separators)
    basename = os.path.basename(os.path.normpath(pathitem.abspath))
    item = QStandardItem(
        icon_provider.icon(QFileInfo(pathitem.abspath)),
        basename
    )
    item.setToolTip(pathitem.abspath)
    item.setData(pathitem, Qt.UserRole)
    return item


class State(enum.IntEnum):
    NoState, Processing, Done, Cancelled, Error = range(5)


class OWImportImages(widget.OWWidget):
    name = _tr.m[79, "Import Images"]
    description = _tr.m[80, "Import images from a directory(s)"]
    keywords = _tr.m[81, "import images, import, image, read, load"]
    icon = "icons/ImportImages.svg"
    priority = 110

    class Outputs:
        data = Output(_tr.m[82, 'Data'], Table, default=True, id="Data")

    #: list of recent paths
    recent_paths = settings.Setting([])  # type: List[RecentPath]

    want_main_area = False
    resizing_enabled = False

    Modality = Qt.ApplicationModal
    # Modality = Qt.WindowModal

    MaxRecentItems = 20

    def __init__(self):
        super().__init__()
        #: widget's runtime state
        self.__state = State.NoState
        self.data = None
        self._n_image_categories = 0
        self._n_image_data = 0
        self._n_skipped = 0

        self.__invalidated = False
        self.__pendingTask = None

        vbox = gui.vBox(self.controlArea)
        hbox = gui.hBox(vbox)
        self.recent_cb = QComboBox(
            sizeAdjustPolicy=QComboBox.AdjustToMinimumContentsLengthWithIcon,
            minimumContentsLength=16,
            acceptDrops=True
        )
        self.recent_cb.installEventFilter(self)
        self.recent_cb.activated[int].connect(self.__onRecentActivated)
        icons = standard_icons(self)

        browseaction = QAction(
            _tr.m[83, "Open/Load Images"], self,
            iconText="\N{HORIZONTAL ELLIPSIS}",
            icon=icons.dir_open_icon,
            toolTip=_tr.m[84, "Select a directory from which to load the images"]
        )
        browseaction.triggered.connect(self.__runOpenDialog)
        reloadaction = QAction(
            _tr.m[85, "Reload"], self,
            icon=icons.reload_icon,
            toolTip=_tr.m[86, "Reload current image set"]
        )
        reloadaction.triggered.connect(self.reload)
        self.__actions = namespace(
            browse=browseaction,
            reload=reloadaction,
        )

        browsebutton = QPushButton(
            browseaction.iconText(),
            icon=browseaction.icon(),
            toolTip=browseaction.toolTip(),
            clicked=browseaction.trigger
        )
        reloadbutton = QPushButton(
            reloadaction.iconText(),
            icon=reloadaction.icon(),
            clicked=reloadaction.trigger,
            default=True,
        )

        hbox.layout().addWidget(self.recent_cb)
        hbox.layout().addWidget(browsebutton)
        hbox.layout().addWidget(reloadbutton)

        self.addActions([browseaction, reloadaction])

        reloadaction.changed.connect(
            lambda: reloadbutton.setEnabled(reloadaction.isEnabled())
        )
        box = gui.vBox(vbox, "Info")
        self.infostack = QStackedWidget()

        self.info_area = QLabel(
            text=_tr.m[87, "No image set selected"],
            wordWrap=True
        )
        self.progress_widget = QProgressBar(
            minimum=0, maximum=0
        )
        self.cancel_button = QPushButton(
            _tr.m[88, "Cancel"], icon=icons.cancel_icon,
        )
        self.cancel_button.clicked.connect(self.cancel)

        w = QWidget()
        vlayout = QVBoxLayout()
        vlayout.setContentsMargins(0, 0, 0, 0)
        hlayout = QHBoxLayout()
        hlayout.setContentsMargins(0, 0, 0, 0)

        hlayout.addWidget(self.progress_widget)
        hlayout.addWidget(self.cancel_button)
        vlayout.addLayout(hlayout)

        self.pathlabel = TextLabel()
        self.pathlabel.setTextElideMode(Qt.ElideMiddle)
        self.pathlabel.setAttribute(Qt.WA_MacSmallSize)

        vlayout.addWidget(self.pathlabel)
        w.setLayout(vlayout)

        self.infostack.addWidget(self.info_area)
        self.infostack.addWidget(w)

        box.layout().addWidget(self.infostack)

        self.__initRecentItemsModel()
        self.__invalidated = True
        self.__executor = ThreadExecutor(self)

        QApplication.postEvent(self, QEvent(RuntimeEvent.Init))

        # ── PC 폴더 업로드 결과 폴링 (브라우저가 webkitdirectory 로 업로드 후
        #     /config/.upload_path_images 에 디렉터리 경로 기록 → 자동 로드) ──
        from AnyQt.QtCore import QTimer as _QTimer
        self.__pc_upload_timer = _QTimer(self)
        self.__pc_upload_timer.timeout.connect(self.__pc_upload_check)
        self.__pc_upload_timer.start(1000)

    def __initRecentItemsModel(self):
        self._relocate_recent_files()
        recent_paths = []
        for item in self.recent_paths:
            recent_paths.append(item)
        recent_paths = recent_paths[:OWImportImages.MaxRecentItems]
        recent_model = self.recent_cb.model()
        recent_model.clear()

        for pathitem in recent_paths:
            item = RecentPath_asqstandarditem(pathitem)
            recent_model.appendRow(item)

        self.recent_paths = recent_paths

        if self.recent_paths and os.path.isdir(self.recent_paths[0].abspath):
            self.recent_cb.setCurrentIndex(0)
            self.__actions.reload.setEnabled(True)
        else:
            self.recent_cb.setCurrentIndex(-1)
            self.__actions.reload.setEnabled(False)

    def customEvent(self, event):
        """Reimplemented."""
        if event.type() == RuntimeEvent.Init:
            if self.__invalidated:
                try:
                    self.start()
                finally:
                    self.__invalidated = False

        super().customEvent(event)

    def __runOpenDialog(self):
        """원본 동작(서버측 디렉터리 다이얼로그)을 PC 폴더 업로드 신호 작성으로 교체.
        브라우저가 /config/.upload_request_images 신호를 감지하여 webkitdirectory
        파일 입력을 트리거 → 사용자 PC 의 폴더 선택 → 모든 이미지 업로드 →
        /config/.upload_path_images 에 경로 기록 → __pc_upload_check 가 setCurrentPath 호출."""
        import time as _time
        try:
            with open("/config/.upload_request_images", "w") as _f:
                _f.write(str(_time.time()))
        except OSError:
            # 신호 파일 작성 실패 시에만 원본 동작(서버측 다이얼로그) 폴백
            startdir = os.path.expanduser("~/")
            if self.recent_paths:
                startdir = os.path.dirname(self.recent_paths[0].abspath)
            dirpath = QFileDialog.getExistingDirectory(
                self, _tr.m[90, "Select Top Level Directory"], startdir
            )
            if dirpath:
                self.setCurrentPath(dirpath)
                self.start()

    def __pc_upload_check(self):
        """1초 폴링 — 브라우저가 PC 폴더 업로드를 완료하면 /config/.upload_path_images 에
        업로드 디렉터리 경로를 기록한다. 감지하면 setCurrentPath + start 호출."""
        signal = "/config/.upload_path_images"
        if not os.path.isfile(signal):
            return
        try:
            with open(signal, "r") as _f:
                dirpath = _f.read().strip()
            os.remove(signal)
            if dirpath and os.path.isdir(dirpath):
                self.setCurrentPath(dirpath)
                self.start()
        except OSError:
            pass

    def __onRecentActivated(self, index):
        item = self.recent_cb.itemData(index)
        if item is None:
            return
        assert isinstance(item, RecentPath)
        self.setCurrentPath(item.abspath)
        self.start()

    def __updateInfo(self):
        if self.__state == State.NoState:
            text = _tr.m[91, "No image set selected"]
        elif self.__state == State.Processing:
            text = _tr.m[92, "Processing"]
        elif self.__state == State.Done:
            nvalid = self._n_image_data
            ncategories = self._n_image_categories
            n_skipped = self._n_skipped
            if ncategories < 2:
                text = _tr.e(_tr.c(93, '{nvalid} {pl(nvalid, "image")}'))
            else:
                text = _tr.e(_tr.c(94, '{nvalid} {pl(nvalid, "image")} / {ncategories} {pl(ncategories, "category")}'))
            if n_skipped > 0:
                text = text + _tr.e(_tr.c(95, ', {n_skipped} skipped'))
        elif self.__state == State.Cancelled:
            text = _tr.m[96, "Cancelled"]
        elif self.__state == State.Error:
            text = _tr.m[97, "Error state"]
        else:
            assert False

        self.info_area.setText(text)

        if self.__state == State.Processing:
            self.infostack.setCurrentIndex(1)
        else:
            self.infostack.setCurrentIndex(0)

    def setCurrentPath(self, path):
        """
        Set the current root image path to path

        If the path does not exists or is not a directory the current path
        is left unchanged

        Parameters
        ----------
        path : str
            New root import path.

        Returns
        -------
        status : bool
            True if the current root import path was successfully
            changed to path.
        """
        if self.recent_paths and path is not None and \
                os.path.isdir(self.recent_paths[0].abspath) and os.path.isdir(path) \
                and os.path.samefile(self.recent_paths[0].abspath, path):
            return True

        success = True
        error = None
        if path is not None:
            if not os.path.exists(path):
                error = _tr.m[98, "'{}' does not exist"].format(path)
                path = None
                success = False
            elif not os.path.isdir(path):
                error = _tr.m[99, "'{}' is not a directory"].format(path)
                path = None
                success = False

        if error is not None:
            self.error(error)
            warnings.warn(error, UserWarning, stacklevel=3)
        else:
            self.error()

        if path is not None:
            newindex = self.addRecentPath(path)
            self.recent_cb.setCurrentIndex(newindex)

        self.__actions.reload.setEnabled(len(self.recent_paths) > 0)

        if self.__state == State.Processing:
            self.cancel()

        return success

    def _search_paths(self):
        basedir = self.workflowEnv().get("basedir", None)
        if basedir is None:
            return []
        return [("basedir", basedir)]

    def addRecentPath(self, path):
        """
        Prepend a path entry to the list of recent paths

        If an entry with the same path already exists in the recent path
        list it is moved to the first place

        Parameters
        ----------
        path : str
        """
        existing = None
        for pathitem in self.recent_paths:
            try:
                if os.path.samefile(pathitem.abspath, path):
                    existing = pathitem
                    break
            except FileNotFoundError:
                # file not found if the `pathitem.abspath` no longer exists
                pass

        model = self.recent_cb.model()

        if existing is not None:
            selected_index = self.recent_paths.index(existing)
            assert model.item(selected_index).data(Qt.UserRole) is existing
            self.recent_paths.remove(existing)
            row = model.takeRow(selected_index)
            self.recent_paths.insert(0, existing)
            model.insertRow(0, row)
        else:
            item = RecentPath.create(path, self._search_paths())
            self.recent_paths.insert(0, item)
            model.insertRow(0, RecentPath_asqstandarditem(item))
        return 0

    def __setRuntimeState(self, state):
        assert state in State
        self.setBlocking(state == State.Processing)
        message = ""
        if state == State.Processing:
            assert self.__state in [State.Done,
                                    State.NoState,
                                    State.Error,
                                    State.Cancelled]
            message = _tr.m[100, "Processing"]
        elif state == State.Done:
            assert self.__state == State.Processing
        elif state == State.Cancelled:
            assert self.__state == State.Processing
            message = _tr.m[101, "Cancelled"]
        elif state == State.Error:
            message = _tr.m[102, "Error during processing"]
        elif state == State.NoState:
            message = ""
        else:
            assert False

        self.__state = state

        if self.__state == State.Processing:
            self.infostack.setCurrentIndex(1)
        else:
            self.infostack.setCurrentIndex(0)

        self.setStatusMessage(message)
        self.__updateInfo()

    def reload(self):
        """
        Restart the image scan task
        """
        if self.__state == State.Processing:
            self.cancel()

        self.data = None
        self.start()

    def start(self):
        """
        Start/execute the image indexing operation
        """
        self.error()

        self.__invalidated = False
        if not self.recent_paths:
            return

        if self.__state == State.Processing:
            assert self.__pendingTask is not None
            log.info(("Starting a new task while one is in progress. " + "Cancel the existing task (dir:'{}')")
                     .format(self.__pendingTask.startdir))
            self.cancel()

        startdir = self.recent_paths[0].abspath

        self.__setRuntimeState(State.Processing)

        report_progress = methodinvoke(
            self, "__onReportProgress", (object,))

        task = ImportImages(report_progress=report_progress)

        # collect the task state in one convenient place
        self.__pendingTask = taskstate = namespace(
            task=task,
            startdir=startdir,
            future=None,
            watcher=None,
            cancelled=False,
            cancel=None,
        )

        def cancel():
            # Cancel the task and disconnect
            if taskstate.future.cancel():
                pass
            else:
                taskstate.task.cancelled = True
                taskstate.cancelled = True
                try:
                    taskstate.future.result(timeout=3)
                except UserInterruptError:
                    pass
                except TimeoutError:
                    log.info("The task did not stop in in a timely manner")
            taskstate.watcher.finished.disconnect(self.__onRunFinished)

        taskstate.cancel = cancel

        def run_image_scan_task_interupt():
            try:
                return task(startdir)
            except UserInterruptError:
                # Suppress interrupt errors, so they are not logged
                return

        taskstate.future = self.__executor.submit(run_image_scan_task_interupt)
        taskstate.watcher = FutureWatcher(taskstate.future)
        taskstate.watcher.finished.connect(self.__onRunFinished)

    @Slot()
    def __onRunFinished(self):
        assert QThread.currentThread() is self.thread()
        assert self.__state == State.Processing
        assert self.__pendingTask is not None
        assert self.sender() is self.__pendingTask.watcher
        assert self.__pendingTask.future.done()
        task = self.__pendingTask
        self.__pendingTask = None

        try:
            data, n_skipped = task.future.result()
        except Exception:
            sys.excepthook(*sys.exc_info())
            state = State.Error
            data = None
            n_skipped = 0
            self.error(traceback.format_exc())
        else:
            state = State.Done
            self.error()

        if data:
            self._n_image_data = len(data)
            self._n_image_categories = len(data.domain.class_var.values)\
                if data.domain.class_var else 0
        else:
            self._n_image_data, self._n_image_categories = 0, 0

        self.data = data
        self._n_skipped = n_skipped

        self.__setRuntimeState(state)
        self.commit()

    def cancel(self):
        """
        Cancel current pending task (if any).
        """
        if self.__state == State.Processing:
            assert self.__pendingTask is not None
            self.__pendingTask.cancel()
            self.__pendingTask = None
            self.__setRuntimeState(State.Cancelled)

    @Slot(object)
    def __onReportProgress(self, arg):
        # report on scan progress from a worker thread
        # arg must be a namespace(count: int, lastpath: str)
        assert QThread.currentThread() is self.thread()
        if self.__state == State.Processing:
            self.pathlabel.setText(prettyfypath(arg.lastpath))

    def commit(self):
        """
        Commit a Table from the collected image meta data.
        """
        self.Outputs.data.send(self.data)

    def onDeleteWidget(self):
        self.cancel()
        self.__executor.shutdown(wait=True)
        self.__invalidated = False

    def eventFilter(self, receiver, event):
        # re-implemented from QWidget
        # intercept and process drag drop events on the recent directory
        # selection combo box
        def dirpath(event):
            # type: (QDropEvent) -> Optional[str]
            """Return the directory from a QDropEvent."""
            data = event.mimeData()
            urls = data.urls()
            if len(urls) == 1:
                url = urls[0]
                path = url.toLocalFile()
                if path.endswith("/"):
                    path = path[:-1]  # remove last /
                if os.path.isdir(path):
                    return path
            return None

        if receiver is self.recent_cb and \
                event.type() in {QEvent.DragEnter, QEvent.DragMove,
                                 QEvent.Drop}:
            assert isinstance(event, QDropEvent)
            path = dirpath(event)
            if path is not None and event.possibleActions() & Qt.LinkAction:
                event.setDropAction(Qt.LinkAction)
                event.accept()
                if event.type() == QEvent.Drop:
                    self.setCurrentPath(path)
                    self.start()
            else:
                event.ignore()
            return True

        return super().eventFilter(receiver, event)

    def _relocate_recent_files(self):
        search_paths = self._search_paths()
        rec = []
        for recent in self.recent_paths:
            kwargs = dict(
                title=recent.title, sheet=recent.sheet,
                file_format=recent.file_format)
            resolved = recent.resolve(search_paths)
            if resolved is not None:
                rec.append(
                    RecentPath.create(resolved.abspath, search_paths, **kwargs))
            else:
                rec.append(recent)
        # change the list in-place for the case the widgets wraps this list
        self.recent_paths[:] = rec

    def workflowEnvChanged(self, key, value, oldvalue):
        """
        Function called when environment changes (e.g. while saving the scheme)
        It make sure that all environment connected values are modified
        (e.g. relative file paths are changed)
        """
        self.__initRecentItemsModel()


class UserInterruptError(BaseException):
    """
    A BaseException subclass used for cooperative task/thread cancellation
    """
    pass


if __name__ == "__main__":
    from orangewidget.utils.widgetpreview import WidgetPreview
    WidgetPreview(OWImportImages).run()
