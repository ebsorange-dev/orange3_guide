from orangecanvas.utils.localization.si import plsi, plsi_sz, z_besedo
from orangecanvas.utils.localization import Translator  # pylint: disable=wrong-import-order
_tr = Translator("orangecontrib.geo", "biolab.si", "Orange")
del Translator
# Category metadata.

# Index 128 added to Korean.json for "지리" (Geo in Korean)
NAME = _tr.m[128, "Geo"]
DESCRIPTION = _tr.m[10, "Transformation and visualization of geographical data."]

# Category icon show in the menu
ICON = "icons/category.svg"

# Background color for category background in menu
# and widget icon background in workflow.
BACKGROUND = "#a0eaa0"

# Location of widget help files.
WIDGET_HELP_PATH = (
    ("{DEVELOP_ROOT}/doc/_build/html/index.html", None),
    ("http://orange3-geo.readthedocs.io/en/latest/", "")
)
