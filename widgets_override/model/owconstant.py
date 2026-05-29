from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator
from Orange.data import Table
from Orange.modelling.constant import ConstantLearner
from Orange.widgets.utils.owlearnerwidget import OWBaseLearner
from Orange.widgets.utils.widgetpreview import WidgetPreview


class OWConstant(OWBaseLearner):
    name = _tr.m[2149, "Constant"]
    description = (_tr.m[2150, "Predict the most frequent class or mean value "] + _tr.m[2151, "from the training set."])
    icon = "icons/Constant.svg"
    replaces = [
        "Orange.widgets.classify.owmajority.OWMajority",
        "Orange.widgets.regression.owmean.OWMean",
    ]
    priority = 10
    keywords = _tr.m[2152, "constant, majority, mean"]

    LEARNER = ConstantLearner


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWConstant).run(Table("iris"))
