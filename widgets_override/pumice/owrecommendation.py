from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.pumice", "biolab.si", "Orange")
del Translator
import os.path
from dataclasses import dataclass
from typing import Optional
from concurrent.futures import Future, CancelledError

import numpy as np

from AnyQt.QtCore import (
    Qt, QSize, QAbstractTableModel, QModelIndex, QRect, QUrl, Slot)
from AnyQt.QtGui import QPixmap, QImage, QFont, QFontMetrics, QPen, QIcon
from AnyQt.QtWidgets import QTableView, QSizePolicy, QItemDelegate, QHeaderView

from Orange.data import Table
from Orange.widgets import gui, settings
from Orange.widgets.utils.textimport import StampIconEngine
from Orange.widgets.widget import OWWidget, Input
from Orange.widgets.utils.itemmodels import VariableListModel

from orangecontrib.network import Network
from orangecontrib.imageanalytics.widgets.owimageviewer import (
    ImageLoader, image_loader)
from orangewidget.utils.concurrent import FutureWatcher
from orangewidget.widget import Msg


def height(text, font=None, bold=False):
    if font is None:
        font = QFont()
    oldbold = font.bold()
    if bold:
        font.setBold(True)
    fm = QFontMetrics(font)
    rect = QRect(0, 0, 150, 1000)
    height = fm.boundingRect(rect, Qt.TextWordWrap, text).height()
    font.setBold(oldbold)
    return height


class PersonDelegate(QItemDelegate):
    def paint(self, painter, option, index):
        painter.save()
        rect = option.rect.adjusted(5, 5, -5, -5)
        painter.setRenderHint(painter.Antialiasing)
        name, friends, choices = (
            index.data(Qt.ItemDataRole.DisplayRole).split("\x00"))
        align = index.data(Qt.ItemDataRole.TextAlignmentRole)

        painter.save()
        font = QFont(painter.font())
        font.setPixelSize(24)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(rect, align, name)
        rect.adjust(0, height(name, font) + 12, 0, 0)
        painter.restore()

        painter.drawText(rect, align, choices)
        rect.adjust(0, height(choices, painter.font()) + 12, 0, 0)

        painter.drawText(rect, align, friends)
        painter.restore()

    def sizeHint(self, option, index):
        text = index.data(Qt.ItemDataRole.DisplayRole)
        if text is None:
            return QSize(150, 0)

        name, friends, choices = text.split("\x00")
        nfont = QFont()
        nfont.setBold(True)
        nfont.setPixelSize(24)
        font = QFont()
        h = (height(name, nfont) + 12
             + height(friends, font) + 12
             + height(choices, font) + 20)
        return QSize(150, h)


class ItemDelegate(QItemDelegate):
    def paint(self, painter, option, index):
        painter.save()
        painter.setRenderHint(painter.Antialiasing)
        image = index.data(Qt.ItemDataRole.DecorationRole)
        rect = option.rect.adjusted(5, 5, -5, -5)
        if image is not None:
            x = rect.x() + (rect.width() - image.width()) // 2
            y = rect.y()
            painter.drawPixmap(x, y, image)
            painter.save()
            painter.setPen(QPen(Qt.GlobalColor.lightGray, 1))
            painter.drawRect(x, y, image.width(), image.height())
            painter.restore()
            rect.adjust(0, image.height() + 10, 0, 0)

        text = index.data(Qt.ItemDataRole.DisplayRole)
        align = index.data(Qt.ItemDataRole.TextAlignmentRole)
        if text is not None:
            title, recommenders = text.split("\x00")
            painter.save()
            font = QFont(painter.font())
            font.setBold(True)
            painter.setFont(font)
            painter.drawText(rect, align, title)
            text_rect = painter.fontMetrics().boundingRect(
                rect, Qt.TextWordWrap, title)
            h = text_rect.height()
            painter.restore()
            rect.adjust(0, h + 4, 0, 0)
            painter.drawText(rect, align, recommenders)
        painter.restore()

    def sizeHint(self, option, index):
        h = 0
        image = index.data(Qt.ItemDataRole.DecorationRole)
        if image is not None:
            h += image.height() + 10

        text = index.data(Qt.ItemDataRole.DisplayRole)
        if text is not None:
            title, recommenders = text.split("\x00")
            tfont = QFont()
            tfont.setBold(True)
            font = QFont()
            h += (height(title, tfont) + 4 +
                  (height(recommenders, font) if recommenders else 0)
                 )

        return QSize(100, h + 20)


class CartoonTableModel(QAbstractTableModel):
    def __init__(self):
        super().__init__()
        self.names: Optional[np.ndarray] = None  # strings
        self.row_order: Optional[np.ndarray] = None # indices
        self.items: Optional[np.ndarray] = None  # strings
        self.urls: Optional[list[str]] = None

        self.friends: Optional[list[list[tuple[int, float]]]] = None
        self.chosen_items: Optional[list[list[int]]] = None
        self.recommendations: Optional[list[list[int]]] = None
        self.recommenders: Optional[list[list[list[int]]]] = None

        self.pending: Optional[dict[Future[QImage], int]] = None
        self.image_cache: dict[str, CartoonTableModel._Item] = {}

    def set_data(self,
                 names, items, urls,
                 friends, chosen_items, recommendations, recommenders):
        # Keep the cache; new data likely uses the same images, and the
        # cache is small enough to not be a problem.
        self.beginResetModel()
        self.names = names
        self.row_order = np.argsort(names)
        self.items = items
        self.urls = urls
        self.friends = friends
        self.chosen_items = chosen_items
        self.recommendations = recommendations
        self.recommenders = recommenders
        if self.urls is not None:
            self.start_download()
        self.endResetModel()

    def reset(self):
        # TODO: stop pending downloads?
        # Keep the cache; new data likely uses the same images, and the
        # cache is small enough to not be a problem.
        self.beginResetModel()
        self.names = None
        self.row_order = None
        self.items = None
        self.urls = None
        self.friends = None
        self.chosen_items = None
        self.recommendations = None
        self.recommenders = None
        self.pending: dict[Future[QImage], int] = None
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        if parent.isValid() or self.names is None:
            return 0
        return len(self.friends)

    def columnCount(self, parent=QModelIndex()):
        if parent.isValid() or self.recommendations is None:
            return 0
        return max(map(len, self.recommendations)) + 1

    def data(self, index, role):
        row = self.row_order[index.row()]
        column = index.column()
        if column == 0:
            return self.data_for_person(row, role)
        else:
            return self.data_for_recommendation(row, column - 1, role)

    def data_for_person(self, row, role):
        if role == Qt.ItemDataRole.TextAlignmentRole:
            return (Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignTop
                    | Qt.TextWordWrap)

        if role == Qt.ItemDataRole.DisplayRole:
            name = self.names[row]
            friends = _tr.m[64, "Similar: "] + ", ".join(self.names[self.friends[row][0]])
            choices = ", ".join(self.items[self.chosen_items[row]])
            return "\x00".join((name, friends, choices))
        return None

    def data_for_recommendation(self, row, column, role):
        if column >= len(self.recommendations[row]):
            return None

        if role == Qt.ItemDataRole.TextAlignmentRole:
            return (Qt.AlignmentFlag.AlignHCenter | Qt.AlignmentFlag.AlignTop
                    | Qt.TextWordWrap)

        if role == Qt.ItemDataRole.DecorationRole and self.urls is not None:
            url = self.urls[self.recommendations[row][column]]
            item = self.image_cache.get(url)
            if item is None or item.image is None:
                if item is None:
                    icon = StampIconEngine("\N{Hourglass}", Qt.gray)
                else:
                    icon = StampIconEngine("\N{Empty Set}", Qt.red)
                return icon.pixmap(QSize(100, 100), QIcon.Normal, QIcon.On)
            return item.image

        if role == Qt.ItemDataRole.DisplayRole:
            title = self.items[self.recommendations[row][column]]
            recommenders = ', '.join(self.names[self.recommenders[row][column]])
            if recommenders:
                recommenders = f"({recommenders})"
            return f"{title}\x00{recommenders}"

        return None

    @dataclass
    class _Item:
        image: Optional[QPixmap]
        error_text: Optional[str]

    def start_download(self) -> bool:
        assert self.urls is not None
        # qnam has no parent and may die before completing the request
        # One solution is to create an instance here and give it a parent,
        # the other is to add a reference to the future (see below)
        # qnam = QNetworkAccessManager(self)
        qnam = ImageLoader.networkAccessManagerInstance()
        used_images = set().union(*map(set, self.recommendations))
        self.pending = {}
        for img_index, url in enumerate(self.urls):
            if img_index not in used_images:
                continue
            future, deferred = image_loader(QUrl(url), qnam)
            f = deferred()
            self.pending[f] = img_index
            w = FutureWatcher(f, )
            w.done.connect(self.__on_future_done)
            f._p_watcher = w  # type: ignore
            f._qnam = qnam  # keep a weak reference as long as necessary

    @Slot(object)
    def __on_future_done(self, f: 'Future[QImage]'):
        assert self.urls is not None
        assert self.pending is not None

        try:
            img = f.result()
        except CancelledError:
            return
        except BaseException as err:
            item = CartoonTableModel._Item(None, str(err))
        else:
            img = img.scaled(150, 200, Qt.KeepAspectRatio, Qt.SmoothTransformation)
            pixmap = QPixmap.fromImage(img)
            item = CartoonTableModel._Item(pixmap, None)
        img_index = self.pending.pop(f)
        self.image_cache[self.urls[img_index]] = item
        for rowi, row in enumerate(self.recommendations):
            for coli, rec_index in enumerate(row, start=1):
                if rec_index == img_index:
                    index = self.index(rowi, coli)
                    self.dataChanged.emit(
                        index, index,
                        (Qt.ItemDataRole.DecorationRole, Qt.SizeHintRole))


class OWRecommendation(OWWidget):
    name = _tr.m[65, "Recommendation"]
    description = _tr.m[66, "Demo for simple network-based recommendation algorithm"]
    icon = "icons/recommendation.svg"

    class Inputs:
        network = Input(_tr.m[67, "Network"], Network, default=True)
        item_data = Input(_tr.m[68, "Items"], Table)

    class Error(OWWidget.Error):
        no_choices = Msg(
            _tr.m[69, "Network does not contain user choices. Provide separate data."])
        no_item_names = Msg(
            _tr.m[70, "Network does not contain item names."])
        no_user_names_in_net = Msg(
            _tr.m[71, "Data included in the network does not contain user names."])
        user_names_mismatch = Msg(
            _tr.m[72, "Some network nodes are missing from data columns"]
        )
        network_names_ambiguous = Msg(
            (_tr.m[73, "Network nodes contain multiple string attributes.\n"] + (_tr.m[74, "When network and data are both present, the network must have\n"] + _tr.m[75, "a single string attribute whose values match the names of persons."]))
        )
        invalid_node_data = Msg(_tr.m[76, "Network data must be a table or a 1-d array"])

    item_column_hint: Optional[str] = settings.Setting(None)
    person_column_hint: Optional[str] = settings.Setting(None)

    want_control_area = False

    def __init__(self):
        """
        This widget is complicated because it can receive data from network
        and/or a separate signal. This is further complicated because the two
        sources are likely transposed because of the way they are constructed
        in Orange.

        Sources of data and their arrangement
        -------------------------------------

        `network.nodes` can be an instance of `Table` or a list of person names.
        If it is a `Table`, its rows correspond to persons and columns to items.

        `data`, if present, is a `Table`, whose rows correspond to items and
        columns to persons.

        `network.nodes` and `data` are transposed w.r.t. each other due to the
        way in which they are created. In the network, rows always represent
        nodes, which are persons. (TODO: what about a network of items?).
        In `data`, rows are items so that we can attach a column with images,
        and columns are persons because this is how other activities in Pumice
        arrange data.

        One or two sources (or none)
        ----------------------------

        Either `network.nodes` must be a `Table`, or there must be an input
        table (`data`). Otherwise, the widget shows an error and `person_names`
        and `items_names` are `None`. This can be used to test whether the
        widget is operational.

        If both sources are present, there must be exactly one column in
        `network.nodes` whose values equal the names of attributes in `data`.
        This column is taken to represent items. Otherwise, `item_column`
        is `None` and widget is non-operational.

        Names of nodes (persons) and items
        ----------------------------------

        `person_names` and `item_names` (both np.array with strings) contain
        names of persons and of items. If either is `None`, the data is not
        valid; the widget shows an error and is empty and non-operational.

        Depending upon the situation, the user may be able to choose columns
        whose values are used to fill those arrays.

        `person_column` and `item_column` (taken from `person_column_model` and
        `item_column_model`) contain variables with this data IF they are chosen
        by user. In situations where they can't be chosen, models are empty
        and attributes are `None`, combos are hidden. If there is only a
        single choice, the model contains it, the attribute (person_column,
        item_column) is set, but combo is hidden.

        - If `data` is not present, it is read from `network.nodes`.
          Its rows correspond to persons and user chooses how to name them:
          `person_column_model` contains string attributes from `network.nodes`,
          `person_column` is set and combo is shown if there is more than one
          choice.

          `item_names` are set to names of `network.nodes.domain.attributes`;
          the corresponding model is empty and combo is hidden.

        - If data is present, its rows correspond to items, so the user can
          choose how to name items (`item_names`, with `item_column` and
          `item_column_model`) -- if there are multiple options.
          Options include all string variables who do not have type=image;
          if all variables are type=image, they are all candidates.
          If there are no candidates, this is an error.

          `person_names` are set from `network.nodes`.


        Attributes:

            network (Network): input network (mandatory)
                - If `network.nodes` is an instance of Table, rows correspond
                to persons and columns to items.
                - Otherwise, `network.nodes` is a list of labels, representing
                persons.
                - TODO: Distances widget across columns outputs a table with
                labels and positions. This should also be treated as valid,
                but interpreted more like the latter case.

            data (Table): input table. Its *rows* represent items,
                and columns are persons. **This is the opposite from
                `network.nodes`.

            choices (np.ndarray of dtype bool):
                if `data` is given, choices equal `data.X.T` so that
                rows' names (persons, this is X.T!) correspond to person_names
                (nodes in the network). Otherwise, it equals `network.nodes.X`.

            person_column (StringVariable): variable with names of persons,
                or None if person can't be chosen (because it's taken from
                network)
            person_names (np.ndarray of strings): names of persons

            item_column (StringVariable): variable with names of items,
                or None if it can't be chosen.
            item_names (np.ndarray of strings): names of items

            image_column (StringVariable): variable with image names
            images (list of QPixmap): images
        """
        super().__init__()

        # ── wiget_card_26_work.md §2 / windowwk.md 유형 B 패턴 ────────────────
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.Window) | Qt.Dialog | Qt.WindowMaximizeButtonHint
        )

        self.network: Network = None
        self.data: Table = None
        self.choices = None

        self.person_column_model = VariableListModel()
        self.person_column = None
        self.person_names = None

        self.item_column_model = VariableListModel()
        self.item_names = None
        self.item_column = None

        self.image_column = None
        self.urls = None

        self.column_box = gui.hBox(self.mainArea)
        gui.comboBox(
            self.column_box, self, "person_column",
            label=_tr.m[77, "Person name column (in network data): "], box=True,
            contentsLength=20,
            model=self.person_column_model,
            callback=self.on_person_column_changed,
            orientation=Qt.Horizontal)

        gui.comboBox(
            self.column_box, self, "item_column",
            label=_tr.m[78, "Item column: "], box=True,
            contentsLength=20,
            model=self.item_column_model,
            callback=self.on_item_column_changed,
            orientation=Qt.Horizontal)

        gui.rubber(self.column_box)

        self.rec_model = CartoonTableModel()
        self.rec_table = rec = QTableView()
        self.rec_table.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.MinimumExpanding)
        self.rec_table.setItemDelegate(ItemDelegate())
        self.rec_table.setItemDelegateForColumn(0, PersonDelegate())
        self.rec_table.verticalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.rec_table.setSelectionMode(QTableView.SelectionMode.NoSelection)
        rec.setModel(self.rec_model)
        rec.verticalHeader().hide()
        rec.horizontalHeader().hide()
        rec.setShowGrid(False)
        rec.horizontalHeader().setDefaultSectionSize(160)
        rec.horizontalHeader().setDefaultAlignment(Qt.AlignmentFlag.AlignHCenter)
        self.mainArea.layout().addWidget(rec)

    def sizeHint(self):
        return QSize(1200, 600)

    def clear(self):
        self.Error.clear()
        self.column_box.setHidden(True)

        self.controls.person_column.box.setHidden(True)
        self.person_column_model.clear()
        self.person_column = None
        self.person_names = None

        self.controls.item_column.box.setHidden(True)
        self.item_column_model.clear()
        self.item_column = None
        self.item_names = None

        self.choices = None
        self.image_column = None
        self.urls = None

        self.update_page()

    @Inputs.network
    def set_network(self, network):
        self.network = network

    @Inputs.item_data
    def set_item_data(self, item_data):
        self.data = item_data

    def handleNewSignals(self):
        self.clear()
        if self.network is None:
            return
        if self.data is None and not isinstance(self.network.nodes, Table):
            self.Error.no_choices()
            return

        self.init_person_column()
        self.init_item_column()
        self.update_page()

    @property
    def is_valid(self):
        return self.person_names is not None and self.item_names is not None

    def init_person_column(self):
        if self.network is None:
            return
        elif isinstance(self.network.nodes, Table):
            self._init_person_column_from_net_table()
        elif not (isinstance(self.network.nodes, np.ndarray)
                and self.network.number_of_nodes() == self.network.nodes.size):
            self.Error.invalid_node_data()
        else:
            assert self.data is not None  # see handleNewSignals
            self._init_person_column_from_net_array()

    def on_person_column_changed(self):
        assert self.network is not None
        assert isinstance(self.network.nodes, Table)
        self.person_column_hint = self.person_column.name
        self._set_person_names_from_column(self.person_column)

    def _set_person_names_from_column(self, var):
        assert var.is_string
        self._set_person_names(self.network.nodes.get_column(var))

    def _set_person_names(self, names):
        assert isinstance(names, np.ndarray)
        self.person_names = names

        if self.data is None:
            choices = self.network.nodes.X
        else:
            domain = self.data.domain
            order = np.array([domain.index(name) for name in self.person_names])
            choices = self.data.X.T[order]
        self.choices = np.nan_to_num(choices).astype(bool)
        self.update_page()

    def init_item_column(self):
        if self.data is None:
            self._init_item_column_from_net()
        else:
            self._init_item_column_from_data()

    def on_item_column_changed(self):
        self.item_column_hint = self.item_column.name
        self.item_names = self.data.get_column(self.item_column)
        self.update_page()

    def _init_person_column_from_net_table(self):
        assert isinstance(self.network.nodes, Table)
        names = self.data and {var.name for var in self.data.domain.attributes}
        nnodes = self.network.number_of_nodes()
        applicable = [
            var for var in self.network.nodes.domain.metas
            if var.is_string and
               len(cnames := set(self.network.nodes.get_column(var))) == nnodes
               and (names is None or cnames >= names)
        ]
        if not applicable:
            self.Error.no_user_names_in_net()
            return

        if len(applicable) == 1:
            self._set_person_names_from_column(applicable[0])
            return

        self.person_column_model[:] = applicable
        self.column_box.setHidden(False)
        self.controls.person_column.box.setHidden(False)
        for var in applicable:
            if var.name == self.person_column_hint:
                self.person_column = var
                break
        else:
            self.person_column = applicable[0]
        self._set_person_names_from_column(self.person_column)

    def _init_person_column_from_net_array(self):
        assert isinstance(self.network.nodes, np.ndarray)
        assert self.network.number_of_nodes() == self.network.nodes.size
        person_names = self.network.nodes.flatten()
        if set(person_names) != {var.name for var in self.data.domain.attributes}:
            self.Error.user_names_mismatch()
            return
        self._set_person_names(person_names)

    def _init_item_column_from_net(self):
        # tested in handleNewSignals
        assert isinstance(self.network.nodes, Table)
        item_names = [var.name for var in self.network.nodes.domain.attributes]
        if not item_names:
            self.Error.no_item_names()
            return
        self.item_names = np.array(item_names)

    def _init_item_column_from_data(self):
        # Candidates for item names and images
        string_vars = [var for var in self.data.domain.metas if var.is_string]
        if not string_vars:
            self.Error.no_item_names()
            return

        # Find first applicable image column, either marked or heuristically
        for var in string_vars:
            if var.attributes.get("type", None) == "image":
                self.image_column = var
                break
        else:
            for var in string_vars:
                column = self.data.get_column(var)
                if all(os.path.splitext(v)[1] in {".png", ".jpg", ".jpeg", ".gif"}
                       for v in column):
                    self.image_column = var
                    break
            else:
                self.image_column = None
        self.set_images()

        # Exclude columns marked as images, but allow the hinted variable
        # If there are no such columns, allow any string variable
        if self.item_column_hint in [var.name for var in string_vars]:
            hinted = self.data.domain[self.item_column_hint]
        else:
            hinted = None
        applicable = [
            var for var in string_vars
            if var is hinted or var.attributes.get("type") != "image"]
        if not applicable:
            applicable = string_vars

        if len(applicable) == 1:
            self.item_names = self.data.get_column(applicable[0])
            return

        self.item_column_model[:] = applicable
        self.item_column = hinted or applicable[0]
        self.item_names = self.data.get_column(self.item_column)
        self.column_box.setHidden(False)
        self.controls.item_column.box.setHidden(False)

    def update_page(self):
        if not self.is_valid:
            self.rec_model.reset()
            return

        friends = self.get_friends()
        recommendations, recommenders = self.get_recommendations(5)
        self.rec_model.set_data(
            self.person_names, self.item_names, self.urls,
            friends,
            [np.flatnonzero(row) for row in self.choices],
            recommendations, recommenders)

    def set_images(self):
        if self.image_column is None:
            self.urls = None
            return

        image_origin = self.image_column.attributes.get("origin", ".")
        self.urls = []
        for url in self.data.get_column(self.image_column):
            if not url.startswith("http"):
                url = "file://" + os.path.join(image_origin, url)
            self.urls.append(url)

    def get_friends(self):
        if not self.is_valid:
            return None
        return [self._get_friends_one(row)
                for row in range(len(self.person_names))]

    def _get_friends_one(self, row):
        # TODO: when https://github.com/biolab/orange3-network/pull/273
        # is released, use
        # neighs, weights = self.network.outgoing(row, weights=True)
        matrix = self.network.edges[0].edges
        fr, to = matrix.indptr[row], matrix.indptr[row + 1]
        neighs = matrix.indices[fr:to]
        weights = matrix.data[fr:to]
        # stable sort, but reversed, thus - (not [::-1]
        inds = np.argsort(-weights)
        return neighs[inds], weights[inds]

    def get_recommendations(self, n):
        if not self.is_valid:
            return None
        return list(zip(*(self._get_recommendations_one(row, n)
                          for row in range(len(self.person_names)))))

    def _get_recommendations_one(self, row, n):
        neighbours, _ = self._get_friends_one(row)
        if len(neighbours) == 0:
            return [], []

        neighbours_choices = self.choices[neighbours]
        counts = np.sum(neighbours_choices, axis=0)
        counts[self.choices[row] == 1] = -1
        # Add a bit of noise to break ties randomly
        sorted_items = np.argsort(
            np.random.uniform(0, 0.00001, len(counts)) - counts)
        if n > len(sorted_items):
            n = len(sorted_items)
        if sorted_items[n - 1] == -1:
            n = np.flatnonzero(sorted_items == -1)[0] - 1
        if n == 0:
            return [], []
        most_freq = sorted_items[:n]
        item_indices = list(most_freq)
        recommenders = [
            list(neighbours[neighbours_choices[:, i] == 1]) for i in most_freq]
        return item_indices, recommenders


def main():
    # pylint: disable=import-outside-toplevel
    from Orange.widgets.utils.widgetpreview import WidgetPreview
    from orangecontrib.network.network.readwrite import read_pajek

    dirname = os.path.join(os.path.dirname(__file__), "..", 'datasets', 'cartoons')

    items = Table(os.path.join(dirname, 'cartoons.xlsx'))
    items.domain["poster"].attributes["origin"] = dirname

    network = read_pajek(os.path.join(dirname, 'cartoons.net'))
    #network.nodes = Table(os.path.join(dirname, 'cartoons-persons.tab'))
    WidgetPreview(OWRecommendation).run(set_network=network, set_item_data=items)


if __name__ == "__main__":
    main()
