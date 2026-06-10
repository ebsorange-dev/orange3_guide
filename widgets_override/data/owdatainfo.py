from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator
import threading
import textwrap

import numpy as np

from Orange.widgets import widget, gui
from Orange.widgets.utils.localization import pl
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import Input

from AnyQt.QtCore import QEvent

from Orange.data import \
    Table, StringVariable, DiscreteVariable, ContinuousVariable

try:
    from Orange.data.sql.table import SqlTable
except ImportError:
    def is_sql(_):
        return False
else:
    def is_sql(data):
        return isinstance(data, SqlTable)


class OWDataInfo(widget.OWWidget):
    name = _tr.m[520, "Data Info"]
    id = "orange.widgets.data.info"
    description = _tr.m[521, "Display basic information about the data set"]
    icon = "icons/DataInfo.svg"
    priority = 80
    category = _tr.m[522, "Data"]
    keywords = _tr.m[523, "data info, information, inspect"]

    class Inputs:
        data = Input(_tr.m[524, "Data"], Table, id="Data")

    want_main_area = False
    buttons_area_orientation = None
    resizing_enabled = False

    def closeEvent(self, event):
        super().closeEvent(event)
        self.hide()
        event.accept()

    def changeEvent(self, event):
        super().changeEvent(event)
        if event.type() == QEvent.ActivationChange and not self.isActiveWindow():
            self.hide()

    def __init__(self):
        super().__init__()

        self.data_desc = {}
        self.data_attrs = {}
        self.description = gui.widgetLabel(
            gui.vBox(self.controlArea, box=_tr.m[525, "Data table properties"]))
        self.attributes = gui.widgetLabel(
            gui.vBox(self.controlArea, box=_tr.m[526, "Additional attributes"]))

    @Inputs.data
    def data(self, data):
        if data is None:
            self.data_desc = self.data_attrs = {}
            self.update_info()
        else:
            self.data_desc = {
                label: value
                for label, func in ((_tr.m[527, "Name"], self._p_name),
                                    (_tr.m[528, "Location"], self._p_location),
                                    (_tr.m[529, "Size"], self._p_size),
                                    (_tr.m[530, "Features"], self._p_features),
                                    (_tr.m[531, "Targets"], self._p_targets),
                                    (_tr.m[532, "Metas"], self._p_metas),
                                    (_tr.m[533, "Missing data"], self._p_missing))
                if bool(value := func(data))}
            self.data_attrs = data.attributes
            self.update_info()

            if is_sql(data):
                def set_exact_length():
                    self.data_desc[_tr.m[534, "Size"]] = self._p_size(data, exact=True)
                    self.update_info()

                threading.Thread(target=set_exact_length).start()

    def update_info(self):
        style = """<style>
                       th { text-align: right; vertical-align: top; }
                       th, td { padding-top: 4px; line-height: 125%}
                    </style>"""

        def dict_as_table(d):
            return "<table>" + \
                   "".join(f"<tr><th>{label}: </th><td>" + \
                           '<br/>'.join(textwrap.wrap(value, width=60)) + \
                           "</td></tr>"
                           for label, value in d.items()) + \
                   "</table>"

        if not self.data_desc:
            self.description.setText(_tr.m[535, "No data."])
        else:
            self.description.setText(style + dict_as_table(self.data_desc))
        self.attributes.setHidden(not self.data_attrs)
        if self.data_attrs:
            self.attributes.setText(
                style + dict_as_table({k: str(v)
                                       for k, v in self.data_attrs.items()}))

    def send_report(self):
        if self.data_desc:
            self.report_items(_tr.m[536, "Data table properties"], self.data_desc)
        if self.data_attrs:
            self.report_items(_tr.m[537, "Additional attributes"], self.data_attrs)

    @staticmethod
    def _p_name(data):
        return getattr(data, "name", "-")

    @staticmethod
    def _p_location(data):
        if not is_sql(data):
            return None

        connection_string = ' '.join(
            f'{key}={value}'
            for key, value in data.connection_params.items()
            if value is not None and key != 'password')
        return _tr.e(_tr.c(538, f"SQL Table using connection:<br/>{connection_string}"))

    @staticmethod
    def _p_size(data, exact=False):
        exact = exact or is_sql(data)
        if exact:
            n = len(data)
            desc = _tr.e(_tr.c(539, f"{n} {pl(n, 'row')}"))
        else:
            n = data.approx_len()
            desc = _tr.e(_tr.c(540, f"~{n} {pl(n, 'row')}"))
        ncols = len(data.domain.variables) + len(data.domain.metas)
        desc += _tr.e(_tr.c(541, f", {ncols} {pl(ncols, 'column')}"))

        sparseness = [s for s, m in ((_tr.m[542, "features"], data.X_density),
                                     (_tr.m[543, "meta attributes"], data.metas_density),
                                     (_tr.m[544, "targets"], data.Y_density)) if m() > 1]
        if sparseness:
            desc += _tr.m[545, "; sparse {', '.join(sparseness)}"]
        return desc

    @classmethod
    def _p_features(cls, data):
        return cls._pack_var_counts(data.domain.attributes)

    def _p_targets(self, data):
        if class_var := data.domain.class_var:
            if class_var.is_continuous:
                return _tr.m[546, "numeric target variable"]
            else:
                nclasses = len(class_var.values)
                return (_tr.e(_tr.c(547, "categorical outcome with ")) + _tr.e(_tr.c(548, f"{nclasses} {pl(nclasses, 'class|classes')}")))
        if class_vars := data.domain.class_vars:
            disc_class = self._count(class_vars, DiscreteVariable)
            cont_class = self._count(class_vars, ContinuousVariable)
            if not cont_class:
                return _tr.e(_tr.c(549, f"{disc_class} categorical {pl(disc_class, 'target')}"))
            elif not disc_class:
                return _tr.e(_tr.c(550, f"{cont_class} numeric {pl(cont_class, 'target')}"))
            return _tr.m[551, "multi-target data,<br/>"] + self._pack_var_counts(class_vars)

    @classmethod
    def _p_metas(cls, data):
        return cls._pack_var_counts(data.domain.metas)

    @staticmethod
    def _p_missing(data: Table):
        if is_sql(data):
            return _tr.m[552, "(not checked for SQL data)"]

        counts = []
        for name, part, n_miss in ((pl(len(data.domain.attributes), _tr.m[553, "feature"]),
                                    data.X, data.get_nan_count_attribute()),
                                   (pl(len(data.domain.class_vars), _tr.m[554, "targets"]),
                                    data.Y, data.get_nan_count_class()),
                                   (pl(len(data.domain.metas), _tr.m[555, "meta variable"]),
                                    data.metas, data.get_nan_count_metas())):
            if n_miss:
                counts.append(
                    _tr.e(_tr.c(556, f"{n_miss} ({n_miss / np.prod(part.shape):.1%}) in {name}")))
        if not counts:
            return _tr.m[557, "none"]
        return ", ".join(counts)

    @staticmethod
    def _count(s, tpe):
        return sum(isinstance(x, tpe) for x in s)

    @classmethod
    def _pack_var_counts(cls, s):
        counts = (
            (name, cls._count(s, type_))
            for name, type_ in ((_tr.m[558, "categorical"], DiscreteVariable),
                                (_tr.m[559, "numeric"], ContinuousVariable),
                                (_tr.m[560, "text"], StringVariable)))
        return ", ".join(_tr.e(_tr.c(561, f"{count} {name}")) for name, count in counts if count)


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWDataInfo).run(Table("heart_disease"))
