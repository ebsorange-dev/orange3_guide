"""Naive Bayes Learner
"""
from orangecanvas.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("Orange", "biolab.si", "Orange")
del Translator

from Orange.data import Table
from Orange.classification.naive_bayes import NaiveBayesLearner
from Orange.widgets.utils.owlearnerwidget import OWBaseLearner
from Orange.widgets.utils.widgetpreview import WidgetPreview


class OWNaiveBayes(OWBaseLearner):
    name = _tr.m[2281, "Naive Bayes"]
    description = (_tr.m[2282, "A fast and simple probabilistic classifier based on "] + _tr.m[2283, "Bayes' theorem with the assumption of feature independence."])
    icon = "icons/NaiveBayes.svg"
    replaces = [
        "Orange.widgets.classify.ownaivebayes.OWNaiveBayes",
    ]
    priority = 70
    keywords = _tr.m[2284, "naive bayes"]

    LEARNER = NaiveBayesLearner


if __name__ == "__main__":  # pragma: no cover
    WidgetPreview(OWNaiveBayes).run(Table("iris"))
