from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator
import warnings
from itertools import chain

import numpy as np

from AnyQt.QtWidgets import QWidget, QFormLayout
from AnyQt.QtGui import QFontMetrics
from AnyQt.QtCore import Qt

from Orange.data import Table, Domain, ContinuousVariable
from Orange.data.util import get_unique_names
from Orange.projection import (MDS, Isomap, LocallyLinearEmbedding,
                               SpectralEmbedding, TSNE)
from Orange.projection.manifold import TSNEModel
from Orange.widgets.utils.widgetpreview import WidgetPreview
from Orange.widgets.widget import OWWidget, Msg, Input, Output
from Orange.widgets.settings import Setting, SettingProvider
from Orange.widgets import gui


class ManifoldParametersEditor(QWidget, gui.OWComponent):
    def __init__(self, parent):
        QWidget.__init__(self, parent)
        gui.OWComponent.__init__(self, parent)
        self.parameters = {}
        self.parameters_name = {}
        self.parent_callback = parent.settings_changed

        layout = QFormLayout()
        self.setLayout(layout)
        layout.setVerticalSpacing(4)
        layout.setContentsMargins(0, 0, 0, 0)

    def get_parameters(self):
        return self.parameters

    def __parameter_changed(self, update_parameter, parameter_name):
        update_parameter(parameter_name)
        self.parent_callback()

    def _create_spin_parameter(self, name, minv, maxv, label):
        self.__spin_parameter_update(name)
        width = QFontMetrics(self.font()).horizontalAdvance("0" * 10)
        control = gui.spin(
            self, self, name, minv, maxv,
            alignment=Qt.AlignRight, callbackOnReturn=True,
            addToLayout=False, controlWidth=width,
            callback=lambda f=self.__spin_parameter_update,
                            p=name: self.__parameter_changed(f, p))
        self.layout().addRow(label, control)

    def __spin_parameter_update(self, name):
        self.parameters[name] = getattr(self, name)

    def _create_combo_parameter(self, name, label):
        self.__combo_parameter_update(name)
        items = (x[1] for x in getattr(self, name + "_values"))
        control = gui.comboBox(
            None, self, name + "_index", items=items,
            callback=lambda f=self.__combo_parameter_update,
                            p=name: self.__parameter_changed(f, p)
        )
        self.layout().addRow(label, control)

    def __combo_parameter_update(self, name):
        index = getattr(self, name + "_index")
        values = getattr(self, name + "_values")
        self.parameters[name] = values[index][0]
        self.parameters_name[name] = values[index][1]

    def _create_radio_parameter(self, name, label):
        self.__radio_parameter_update(name)
        values = (x[1] for x in getattr(self, name + "_values"))
        space = QWidget()
        space.setFixedHeight(4)
        self.layout().addRow(space)
        rbt = gui.radioButtons(
            None, self, name + "_index", btnLabels=values,
            callback=lambda f=self.__radio_parameter_update,
                            p=name: self.__parameter_changed(f, p))
        labox = gui.vBox(None)
        gui.widgetLabel(labox, label)
        gui.rubber(labox)
        self.layout().addRow(labox, rbt)

    def __radio_parameter_update(self, name):
        index = getattr(self, name + "_index")
        values = getattr(self, name + "_values")
        self.parameters[name] = values[index][0]
        self.parameters_name[name] = values[index][1]


class TSNEParametersEditor(ManifoldParametersEditor):
    _metrics = ("euclidean", "manhattan", "chebyshev", "jaccard")
    metric_index = Setting(0)
    metric_values = [("euclidean", _tr.m[2897, "Euclidean"]), ("manhattan", _tr.m[2898, "Manhattan"]),
                     ("chebyshev", _tr.m[2899, "Chebyshev"]), ("jaccard", _tr.m[2900, "Jaccard"])]

    perplexity = Setting(30)
    early_exaggeration = Setting(12)
    learning_rate = Setting(200)
    n_iter = Setting(1000)

    initialization_index = Setting(0)
    initialization_values = [("pca", "PCA"), ("random", _tr.m[2901, "Random"])]

    def __init__(self, parent):
        super().__init__(parent)
        self._create_combo_parameter("metric", _tr.m[2902, "Metric:"])
        self._create_spin_parameter("perplexity", 1, 100, _tr.m[2903, "Perplexity:"])
        self._create_spin_parameter("early_exaggeration", 1, 100,
                                    _tr.m[2904, "Early exaggeration:"])
        self._create_spin_parameter("learning_rate", 1, 1000, _tr.m[2905, "Learning rate:"])
        self._create_spin_parameter("n_iter", 250, 10000, _tr.m[2906, "Max iterations:"])
        self._create_radio_parameter("initialization", _tr.m[2907, "Initialization:"])

    def get_report_parameters(self):
        return {_tr.m[2908, "Metric"]: self.parameters_name["metric"],
                _tr.m[2909, "Perplexity"]: self.parameters["perplexity"],
                _tr.m[2910, "Early exaggeration"]: self.parameters["early_exaggeration"],
                _tr.m[2911, "Learning rate"]: self.parameters["learning_rate"],
                _tr.m[2912, "Max iterations"]: self.parameters["n_iter"],
                _tr.m[2913, "Initialization"]: self.parameters_name["initialization"]}

class MDSParametersEditor(ManifoldParametersEditor):
    max_iter = Setting(300)
    init_type_index = Setting(0)
    init_type_values = (("PCA", "PCA (Torgerson)"),
                        ("random", _tr.m[2914, "Random"]))

    def __init__(self, parent):
        super().__init__(parent)
        self._create_spin_parameter("max_iter", 10, 10 ** 4, _tr.m[2915, "Max iterations:"])
        self._create_radio_parameter("init_type", _tr.m[2916, "Initialization:"])

    def get_parameters(self):
        par = super().get_parameters()
        if self.init_type_index == 0:
            par = {"n_init": 1, **par}
        return par

    def get_report_parameters(self):
        return {_tr.m[2917, "Max iterations"]: self.parameters["max_iter"],
                _tr.m[2918, "Initialization"]: self.parameters_name["init_type"]}

class IsomapParametersEditor(ManifoldParametersEditor):
    n_neighbors = Setting(5)

    def __init__(self, parent):
        super().__init__(parent)
        self._create_spin_parameter("n_neighbors", 1, 10 ** 2, _tr.m[2919, "Neighbors:"])

    def get_report_parameters(self):
        return {_tr.m[2920, "Neighbors"]: self.parameters["n_neighbors"]}

class LocallyLinearEmbeddingParametersEditor(ManifoldParametersEditor):
    n_neighbors = Setting(5)
    max_iter = Setting(100)
    method_index = Setting(0)
    method_values = (("standard", _tr.m[2921, "Standard"]),
                     ("modified", _tr.m[2922, "Modified"]),
                     ("hessian", _tr.m[2923, "Hessian eigenmap"]),
                     ("ltsa", _tr.m[2924, "Local"]))

    def __init__(self, parent):
        super().__init__(parent)
        self._create_combo_parameter("method", _tr.m[2925, "Method:"])
        self._create_spin_parameter("n_neighbors", 1, 10 ** 2, _tr.m[2926, "Neighbors:"])
        self._create_spin_parameter("max_iter", 10, 10 ** 4, _tr.m[2927, "Max iterations:"])

    def get_report_parameters(self):
        return {_tr.m[2928, "Method"]: self.parameters_name["method"],
                _tr.m[2929, "Neighbors"]: self.parameters["n_neighbors"],
                _tr.m[2930, "Max iterations"]: self.parameters["max_iter"]}

class SpectralEmbeddingParametersEditor(ManifoldParametersEditor):
    affinity_index = Setting(0)
    affinity_values = (("nearest_neighbors", _tr.m[2931, "Nearest neighbors"]),
                       ("rbf", _tr.m[2932, "RBF kernel"]))

    def __init__(self, parent):
        super().__init__(parent)
        self._create_combo_parameter("affinity", _tr.m[2933, "Affinity:"])

    def get_report_parameters(self):
        return {_tr.m[2934, "Affinity"]: self.parameters_name["affinity"]}

class OWManifoldLearning(OWWidget):
    name = _tr.m[2935, "Manifold Learning"]
    description = _tr.m[2936, "Nonlinear dimensionality reduction."]
    icon = "icons/Manifold.svg"
    priority = 2200
    keywords = _tr.m[2937, "manifold learning"]
    settings_version = 2

    class Inputs:
        data = Input(_tr.m[2938, "Data"], Table, id="Data")

    class Outputs:
        transformed_data = Output(_tr.m[2939, "Transformed Data"], Table, id="Transformed Data", dynamic=False,
                                  replaces=["Transformed data"])

    MANIFOLD_METHODS = (TSNE, MDS, Isomap, LocallyLinearEmbedding,
                        SpectralEmbedding)

    tsne_editor = SettingProvider(TSNEParametersEditor)
    mds_editor = SettingProvider(MDSParametersEditor)
    isomap_editor = SettingProvider(IsomapParametersEditor)
    lle_editor = SettingProvider(LocallyLinearEmbeddingParametersEditor)
    spectral_editor = SettingProvider(SpectralEmbeddingParametersEditor)

    resizing_enabled = False
    want_main_area = False

    manifold_method_index = Setting(0)
    n_components = Setting(2)
    auto_apply = Setting(True)

    class Error(OWWidget.Error):
        n_neighbors_too_small = Msg((_tr.m[2941, "For chosen method and components, "] + _tr.m[2942, "neighbors must be greater than {}"]))
        manifold_error = Msg("{}")
        sparse_not_supported = Msg(_tr.m[2943, "Sparse data is not supported."])
        out_of_memory = Msg(_tr.m[2944, "Out of memory"])

    class Warning(OWWidget.Warning):
        graph_not_connected = Msg(_tr.m[2945, "Disconnected graph, embedding may not work"])

    @classmethod
    def migrate_settings(cls, settings, version):
        if version < 2:
            tsne_settings = settings.get('tsne_editor', {})
            # Fixup initialization index
            if 'init_index' in tsne_settings:
                idx = tsne_settings.pop('init_index')
                idx = min(idx, len(TSNEParametersEditor.initialization_values))
                tsne_settings['initialization_index'] = idx
            # We removed several metrics here
            if 'metric_index' in tsne_settings:
                idx = tsne_settings['metric_index']
                idx = min(idx, len(TSNEParametersEditor.metric_values))
                tsne_settings['metric_index'] = idx

    def __init__(self):
        self.data = None

        # GUI
        method_box = gui.vBox(self.controlArea, _tr.m[2946, "Method"])
        self.manifold_methods_combo = gui.comboBox(
            method_box, self, "manifold_method_index",
            items=[m.name for m in self.MANIFOLD_METHODS],
            callback=self.manifold_method_changed)

        self.params_box = gui.vBox(method_box)

        self.tsne_editor = TSNEParametersEditor(self)
        self.mds_editor = MDSParametersEditor(self)
        self.isomap_editor = IsomapParametersEditor(self)
        self.lle_editor = LocallyLinearEmbeddingParametersEditor(self)
        self.spectral_editor = SpectralEmbeddingParametersEditor(self)
        self.parameter_editors = [
            self.tsne_editor, self.mds_editor, self.isomap_editor,
            self.lle_editor, self.spectral_editor]

        for editor in self.parameter_editors:
            self.params_box.layout().addWidget(editor)
            editor.hide()
        self.params_widget = self.parameter_editors[self.manifold_method_index]
        self.params_widget.show()

        output_box = gui.vBox(self.controlArea, _tr.m[2947, "Output"])
        self.n_components_spin = gui.spin(
            output_box, self, "n_components", 1, 10, label=_tr.m[2948, "Components:"],
            controlWidth=QFontMetrics(self.font()).horizontalAdvance("0" * 10),
            alignment=Qt.AlignRight, callbackOnReturn=True,
            callback=self.settings_changed)
        gui.rubber(self.n_components_spin.box)
        self.apply_button = gui.auto_apply(self.buttonsArea, self)

    def manifold_method_changed(self):
        self.params_widget.hide()
        self.params_widget = self.parameter_editors[self.manifold_method_index]
        self.params_widget.show()
        self.commit.deferred()

    def settings_changed(self):
        self.commit.deferred()

    @Inputs.data
    def set_data(self, data):
        self.data = data
        self.n_components_spin.setMaximum(len(self.data.domain.attributes)
                                          if self.data else 10)
        self.commit.now()

    @gui.deferred
    def commit(self):
        builtin_warn = warnings.warn

        def _handle_disconnected_graph_warning(msg, *args, **kwargs):
            if msg.startswith(_tr.m[2949, "Graph is not fully connected"]):
                self.Warning.graph_not_connected()
            else:
                builtin_warn(msg, *args, **kwargs)

        out = None
        data = self.data
        method = self.MANIFOLD_METHODS[self.manifold_method_index]
        have_data = data is not None and len(data)
        self.Error.clear()
        self.Warning.clear()

        if have_data and data.is_sparse():
            self.Error.sparse_not_supported()
        elif have_data:
            names = [var.name for var in chain(data.domain.class_vars,
                                               data.domain.metas) if var]
            proposed = ["C{}".format(i) for i in range(self.n_components)]
            unique = get_unique_names(names, proposed)
            domain = Domain([ContinuousVariable(name) for name in unique],
                            data.domain.class_vars,
                            data.domain.metas)
            try:
                warnings.warn = _handle_disconnected_graph_warning
                projector = method(**self.get_method_parameters(data, method))
                model = projector(data)
                if isinstance(model, TSNEModel):
                    out = model.embedding
                else:
                    X = model.embedding_
                    out = Table(domain, X, data.Y, data.metas)
            except ValueError as e:
                if e.args[0] == ("for method='hessian', n_neighbors " + ("must be greater than [n_components" + " * (n_components + 3) / 2]")):
                    n = self.n_components * (self.n_components + 3) / 2
                    self.Error.n_neighbors_too_small("{}".format(n))
                else:
                    self.Error.manifold_error(e.args[0])
            except MemoryError:
                self.Error.out_of_memory()
            except np.linalg.linalg.LinAlgError as e:
                self.Error.manifold_error(str(e))
            finally:
                warnings.warn = builtin_warn

        self.Outputs.transformed_data.send(out)

    def get_method_parameters(self, data, method):
        parameters = dict(n_components=self.n_components)
        parameters.update(self.params_widget.get_parameters())
        return parameters

    def send_report(self):
        method = self.MANIFOLD_METHODS[self.manifold_method_index]
        self.report_items(((_tr.m[2950, "Method"], method.name),))
        parameters = {_tr.m[2951, "Number of components"]: self.n_components}
        parameters.update(self.params_widget.get_report_parameters())
        self.report_items(_tr.m[2952, "Method parameters"], parameters)
        if self.data:
            self.report_data(_tr.m[2953, "Data"], self.data)


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWManifoldLearning).run(Table("brown-selected"))
