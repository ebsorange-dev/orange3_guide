from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator
import numbers

import numpy
from AnyQt.QtWidgets import QFormLayout
from AnyQt.QtCore import Qt, QSize

from orangewidget.report import bool_str
from orangewidget.settings import Setting

from Orange.data import Table, Domain, StringVariable, ContinuousVariable
from Orange.data.util import get_unique_names
from Orange.data.sql.table import SqlTable, AUTO_DL_LIMIT
from Orange.preprocess import preprocess
from Orange.projection import PCA
from Orange.widgets import widget, gui
from Orange.widgets.utils.annotated_data import add_columns
from Orange.widgets.utils.concurrent import ConcurrentWidgetMixin
from Orange.widgets.utils.slidergraph import SliderGraph
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import Input, Output

# Maximum number of PCA components that we can set in the widget
MAX_COMPONENTS = 100
LINE_NAMES = [_tr.m[2990, "component variance"], _tr.m[2991, "cumulative variance"]]


class OWPCA(widget.OWWidget, ConcurrentWidgetMixin):
    name = _tr.m[2992, "PCA"]
    description = _tr.m[2993, "Principal component analysis with a scree-diagram."]
    icon = "icons/PCA.svg"
    priority = 3050
    keywords = _tr.m[2994, "pca, principal component analysis, linear transformation"]

    class Inputs:
        data = Input(_tr.m[2995, "Data"], Table, id="Data")

    class Outputs:
        transformed_data = Output(_tr.m[2996, "Transformed Data"], Table, id="Transformed Data", replaces=["Transformed data"])
        data = Output(_tr.m[2998, "Data"], Table, id="Data", default=True)
        components = Output(_tr.m[2999, "Components"], Table, id="Components", dynamic=False)
        pca = Output(_tr.m[3000, "PCA"], PCA, id="PCA", dynamic=False)

    ncomponents = Setting(2)
    variance_covered = Setting(100)
    auto_commit = Setting(True)
    normalize = Setting(True)
    maxp = Setting(20)
    axis_labels = Setting(10)

    graph_name = "plot.plotItem"  # QGraphicsView (pg.PlotWidget -> SliderGraph)

    class Warning(widget.OWWidget.Warning):
        trivial_components = widget.Msg(
            (_tr.m[3001, "All components of the PCA are trivial (explain 0 variance). "] + _tr.m[3002, "Input data is constant (or near constant)."]))

    class Error(widget.OWWidget.Error):
        no_features = widget.Msg(_tr.m[3003, "At least 1 feature is required"])
        no_instances = widget.Msg(_tr.m[3004, "At least 1 data instance is required"])

    def sizeHint(self):
        return QSize(800, 600)

    def __init__(self):
        super().__init__()
        self.setWindowFlags(
            (self.windowFlags() & ~Qt.Window) | Qt.Dialog | Qt.WindowMaximizeButtonHint
        )
        ConcurrentWidgetMixin.__init__(self)

        self.data = None
        self._pca = None
        self._transformed = None
        self._variance_ratio = None
        self._cumulative = None

        # Components Selection
        form = QFormLayout()
        box = gui.widgetBox(self.controlArea, _tr.m[3005, "Components Selection"],
                            orientation=form)

        self.components_spin = gui.spin(
            box, self, "ncomponents", 1, MAX_COMPONENTS,
            callback=self._update_selection_component_spin,
            keyboardTracking=False, addToLayout=False
        )
        self.components_spin.setSpecialValueText(_tr.m[3006, "All"])

        self.variance_spin = gui.spin(
            box, self, "variance_covered", 1, 100,
            callback=self._update_selection_variance_spin,
            keyboardTracking=False, addToLayout=False
        )
        self.variance_spin.setSuffix("%")

        form.addRow(_tr.m[3007, "Components:"], self.components_spin)
        form.addRow(_tr.m[3008, "Explained variance:"], self.variance_spin)

        # Options
        self.options_box = gui.vBox(self.controlArea, _tr.m[3009, "Options"])
        self.normalize_box = gui.checkBox(
            self.options_box, self, "normalize",
            _tr.m[3010, "Normalize variables"], callback=self._update_normalize,
            attribute=Qt.WA_LayoutUsesWidgetRect
        )

        self.maxp_spin = gui.spin(
            self.options_box, self, "maxp", 1, MAX_COMPONENTS,
            label=_tr.m[3011, "Show only first"], callback=self._setup_plot,
            keyboardTracking=False
        )

        gui.rubber(self.controlArea)

        gui.auto_apply(self.buttonsArea, self, "auto_commit")

        self.plot = SliderGraph(
            _tr.m[3012, "Principal Components"], _tr.m[3013, "Proportion of variance"],
            self._on_cut_changed)

        self.mainArea.layout().addWidget(self.plot)
        self._update_normalize()

    @Inputs.data
    def set_data(self, data):
        self.cancel()
        self.clear_messages()
        self.clear()
        self.information()
        self.data = None
        if not data:
            self.clear_outputs()
        if isinstance(data, SqlTable):
            if data.approx_len() < AUTO_DL_LIMIT:
                data = Table(data)
            else:
                self.information(_tr.m[3014, "Data has been sampled"])
                data_sample = data.sample_time(1, no_cache=True)
                data_sample.download_data(2000, partial=True)
                data = Table(data_sample)
        if isinstance(data, Table):
            if not data.domain.attributes:
                self.Error.no_features()
                self.clear_outputs()
                return
            if not data:
                self.Error.no_instances()
                self.clear_outputs()
                return

        self.data = data
        self.fit()

    def fit(self):
        self.cancel()
        self.clear()
        self.Warning.trivial_components.clear()
        if self.data is None:
            return

        data = self.data

        projector = self._create_projector()

        if not isinstance(data, SqlTable):
            self.start(self._call_projector, data, projector)

    @staticmethod
    def _call_projector(data: Table, projector, state):

        def callback(i: float, status=""):
            state.set_progress_value(i * 100)
            if status:
                state.set_status(status)
            if state.is_interruption_requested():
                raise Exception  # pylint: disable=broad-exception-raised

        return projector(data, progress_callback=callback)

    def on_done(self, result):
        pca = result
        variance_ratio = pca.explained_variance_ratio_
        cumulative = numpy.cumsum(variance_ratio)

        if numpy.isfinite(cumulative[-1]):
            self.components_spin.setRange(0, len(cumulative))
            self._pca = pca
            self._variance_ratio = variance_ratio
            self._cumulative = cumulative
            self._setup_plot()
        else:
            self.Warning.trivial_components()

        self.commit.now()

    def on_partial_result(self, result):
        pass

    def onDeleteWidget(self):
        self.shutdown()
        super().onDeleteWidget()

    def clear(self):
        self._pca = None
        self._transformed = None
        self._variance_ratio = None
        self._cumulative = None
        self.plot.clear_plot()

    def clear_outputs(self):
        self.Outputs.transformed_data.send(None)
        self.Outputs.data.send(None)
        self.Outputs.components.send(None)
        self.Outputs.pca.send(self._create_projector())

    def _setup_plot(self):
        if self._pca is None:
            self.plot.clear_plot()
            return

        explained_ratio = self._variance_ratio
        explained = self._cumulative
        cutpos = self._nselected_components()
        p = min(len(self._variance_ratio), self.maxp)

        self.plot.update(
            numpy.arange(1, p+1), [explained_ratio[:p], explained[:p]],
            [Qt.red, Qt.darkYellow], cutpoint_x=cutpos, names=LINE_NAMES)

        self._update_axis()

    def _on_cut_changed(self, components):
        if self.ncomponents in (components, 0):
            return

        self.ncomponents = components
        if self._pca is not None:
            var = self._cumulative[components - 1]
            if numpy.isfinite(var):
                self.variance_covered = int(var * 100)

        self._invalidate_selection()

    def _update_selection_component_spin(self):
        # cut changed by "ncomponents" spin.
        if self._pca is None:
            self._invalidate_selection()
            return

        if self.ncomponents == 0:
            # Special "All" value
            cut = len(self._variance_ratio)
        else:
            cut = self.ncomponents

        var = self._cumulative[cut - 1]
        if numpy.isfinite(var):
            self.variance_covered = int(var * 100)

        self.plot.set_cut_point(cut)
        self._invalidate_selection()

    def _update_selection_variance_spin(self):
        # cut changed by "max variance" spin.
        if self._pca is None:
            return

        cut = numpy.searchsorted(self._cumulative,
                                 self.variance_covered / 100.0) + 1
        cut = min(cut, len(self._cumulative))
        self.ncomponents = cut
        self.plot.set_cut_point(cut)
        self._invalidate_selection()

    def _update_normalize(self):
        self.fit()
        if self.data is None:
            self._invalidate_selection()

    def _create_projector(self):
        projector = PCA(n_components=MAX_COMPONENTS, random_state=0)
        projector.component = self.ncomponents  # for use as a Scorer
        if self.normalize:
            projector.preprocessors = \
                PCA.preprocessors + [preprocess.Normalize(center=False)]
        return projector

    def _nselected_components(self):
        """Return the number of selected components."""
        if self._pca is None:
            return 0

        if self.ncomponents == 0:
            # Special "All" value
            max_comp = len(self._variance_ratio)
        else:
            max_comp = self.ncomponents

        var_max = self._cumulative[max_comp - 1]
        if var_max != numpy.floor(self.variance_covered / 100.0):
            cut = max_comp
            assert numpy.isfinite(var_max)
            self.variance_covered = int(var_max * 100)
        else:
            self.ncomponents = cut = numpy.searchsorted(
                self._cumulative, self.variance_covered / 100.0) + 1
        return cut

    def _invalidate_selection(self):
        self.commit.deferred()

    def _update_axis(self):
        p = min(len(self._variance_ratio), self.maxp)
        axis = self.plot.getAxis("bottom")
        d = max((p-1)//(self.axis_labels-1), 1)
        axis.setTicks([[(i, str(i)) for i in range(1, p + 1, d)]])

    @gui.deferred
    def commit(self):
        transformed = data = components = None
        if self._pca is not None:
            if self._transformed is None:
                # Compute the full transform (MAX_COMPONENTS components) once.
                self._transformed = self._pca(self.data)
            transformed = self._transformed

            if self._variance_ratio is not None:
                for var, explvar in zip(
                        transformed.domain.attributes,
                        self._variance_ratio[:self.ncomponents]):
                    var.attributes["variance"] = round(explvar, 6)
            domain = Domain(
                transformed.domain.attributes[:self.ncomponents],
                self.data.domain.class_vars,
                self.data.domain.metas
            )
            transformed = transformed.from_table(domain, transformed)

            # prevent caching new features by defining compute_value
            proposed = [a.name for a in self._pca.orig_domain.attributes]
            meta_name = get_unique_names(proposed, _tr.m[3015, 'components'])
            meta_vars = [StringVariable(name=meta_name)]
            metas = numpy.array(
                [[_tr.e(_tr.c(3016, f"PC{i + 1}"))for i in range(self.ncomponents)]], dtype=object
            ).T
            if self._variance_ratio is not None:
                variance_name = get_unique_names(proposed, "variance")
                meta_vars.append(ContinuousVariable(variance_name))
                metas = numpy.hstack(
                    (metas,
                     self._variance_ratio[:self.ncomponents, None]))

            dom = Domain(
                [ContinuousVariable(name, compute_value=lambda _: None)
                 for name in proposed],
                metas=meta_vars)
            components = Table(dom, self._pca.components_[:self.ncomponents],
                               metas=metas)
            components.name = _tr.m[3017, 'components']

            data_dom = add_columns(self.data.domain, metas=domain.attributes)
            data = self.data.transform(data_dom)

        self.Outputs.transformed_data.send(transformed)
        self.Outputs.components.send(components)
        self.Outputs.data.send(data)
        self.Outputs.pca.send(self._create_projector())

    def send_report(self):
        if self.data is None:
            return
        self.report_items((
            (_tr.m[3018, "Normalize data"], bool_str(self.normalize)),
            (_tr.m[3019, "Selected components"], self.ncomponents),
            (_tr.m[3020, "Explained variance"], f"{self.variance_covered:.3f} %")
        ))
        self.report_plot()

    @classmethod
    def migrate_settings(cls, settings, version):
        if "variance_covered" in settings:
            # Due to the error in gh-1896 the variance_covered was persisted
            # as a NaN value, causing a TypeError in the widgets `__init__`.
            vc = settings["variance_covered"]
            if isinstance(vc, numbers.Real):
                if numpy.isfinite(vc):
                    vc = int(vc)
                else:
                    vc = 100
                settings["variance_covered"] = vc
        if settings.get("ncomponents", 0) > MAX_COMPONENTS:
            settings["ncomponents"] = MAX_COMPONENTS

        # Remove old `decomposition_idx` when SVD was still included
        settings.pop("decomposition_idx", None)

        # Remove RemotePCA settings
        settings.pop("batch_size", None)
        settings.pop("address", None)
        settings.pop("auto_update", None)


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWPCA).run(Table("housing"))
