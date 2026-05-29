"""
Pattern 2 (Type B) 적용 스크립트 — windowwk.md 기준
setWindowFlags + sizeHint 추가, Python 문법 검사 포함
"""
import py_compile, sys, textwrap

DST = "e:/_26_Use_Orange_New_set_/widgets_override/visualize"

FLAGS = (
    "        self.setWindowFlags(\n"
    "            (self.windowFlags() & ~Qt.Window) | Qt.Dialog | Qt.WindowMaximizeButtonHint\n"
    "        )\n"
)

errors = []


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def replace_once(text, old, new, label):
    if old not in text:
        errors.append(f"  [MISS] {label}: anchor not found")
        return text
    if text.count(old) > 1:
        errors.append(f"  [WARN] {label}: anchor found {text.count(old)} times, replacing first")
    return text.replace(old, new, 1)


def add_qsize(text, old_import, label):
    """old_import 줄에 QSize 추가 (이미 있으면 skip)"""
    if "QSize" in old_import:
        return text  # 이미 있음
    new_import = old_import.replace("import Qt,", "import Qt, QSize,") \
                           .replace("import Qt\n", "import Qt, QSize\n")
    if new_import == old_import:
        errors.append(f"  [WARN] {label}: QSize 추가 위치 못 찾음 — 수동 확인 필요")
        return text
    return text.replace(old_import, new_import, 1)


def sizehint_block(w, h):
    return (
        f"    def sizeHint(self):\n"
        f"        return QSize({w}, {h})\n\n"
    )


def verify(path, fname):
    try:
        py_compile.compile(path, doraise=True)
        return True
    except py_compile.PyCompileError as e:
        errors.append(f"  [SYNTAX ERROR] {fname}: {e}")
        return False


# ══════════════════════════════════════════════════════════
# 1. owtreeviewer.py
#    import: from AnyQt.QtCore import Qt, QPointF, QSizeF, QRectF  → +QSize
#    sizeHint 없음 → 추가
#    super().__init__() 다음: self.domain = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owtreeviewer.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QPointF, QSizeF, QRectF", "owtreeviewer")
INIT_ANCHOR = "    def __init__(self):\n        super().__init__()\n        self.domain = None\n"
t = replace_once(t, INIT_ANCHOR,
    sizehint_block(800, 600) + INIT_ANCHOR + FLAGS,
    "owtreeviewer.__init__")
write(p, t); verify(p, "owtreeviewer.py")
print(f"{'OK' if not any('owtreeviewer' in e for e in errors) else 'NG'} owtreeviewer.py")

# ══════════════════════════════════════════════════════════
# 2. owboxplot.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 다음: self._axis_font = QFont()
# ══════════════════════════════════════════════════════════
p = f"{DST}/owboxplot.py"; t = read(p)
ANCHOR = "        super().__init__()\n        self._axis_font = QFont()\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owboxplot.__init__")
write(p, t); verify(p, "owboxplot.py")
print(f"{'OK' if not any('owboxplot' in e for e in errors) else 'NG'} owboxplot.py")

# ══════════════════════════════════════════════════════════
# 3. owviolinplot.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 의 다음 첫 줄 확인 필요
# ══════════════════════════════════════════════════════════
p = f"{DST}/owviolinplot.py"; t = read(p)
# owviolinplot __init__에서 super().__init__() 직후를 찾아야 함
# sizeHint는 이미 있으므로 skip
import re
# super().__init__() 다음 줄을 찾아서 FLAGS 삽입
# "        super().__init__()\n" 다음에 삽입 (OWViolinPlot 클래스의 것)
# violinplot에는 super().__init__()가 한 번만 있는지 확인
cnt = t.count("        super().__init__()\n")
if cnt == 1:
    t = t.replace("        super().__init__()\n",
                  "        super().__init__()\n" + FLAGS, 1)
else:
    # 클래스 context 좁혀서 찾기
    # OWViolinPlot class 내 __init__ 직후
    m = re.search(r"class OWViolinPlot.*?def __init__\(self\):\n        super\(\)\.__init__\(\)\n",
                  t, re.DOTALL)
    if m:
        pos = m.end()
        t = t[:pos] + FLAGS + t[pos:]
    else:
        errors.append("  [MISS] owviolinplot: super().__init__() anchor")
write(p, t); verify(p, "owviolinplot.py")
print(f"{'OK' if not any('owviolinplot' in e for e in errors) else 'NG'} owviolinplot.py")

# ══════════════════════════════════════════════════════════
# 4. owdistributions.py
#    import: from AnyQt.QtCore import Qt, QRectF, QPointF, pyqtSignal as Signal  → +QSize
#    sizeHint 없음 → 추가
#    super().__init__() 이후
# ══════════════════════════════════════════════════════════
p = f"{DST}/owdistributions.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QRectF, QPointF, pyqtSignal as Signal", "owdistributions")
cnt = t.count("        super().__init__()\n")
# OWDistributions의 __init__에서만 처리 — super() 앞뒤 문맥으로 구분
# class OWDistributions 이후 첫 super().__init__()
cls_pos = t.find("class OWDistributions(")
if cls_pos == -1:
    cls_pos = t.find("class OWDistribution(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
super_pos = t.find("        super().__init__()\n", init_pos)
if super_pos != -1:
    # sizeHint 삽입 위치: init_pos 직전
    sh = sizehint_block(900, 500)
    t = t[:init_pos] + sh + t[init_pos:]
    # 삽입 후 super_pos 재계산
    super_pos += len(sh)
    t = t[:super_pos + len("        super().__init__()\n")] + FLAGS + t[super_pos + len("        super().__init__()\n"):]
else:
    errors.append("  [MISS] owdistributions: super().__init__()")
write(p, t); verify(p, "owdistributions.py")
print(f"{'OK' if not any('owdistributions' in e for e in errors) else 'NG'} owdistributions.py")

# ══════════════════════════════════════════════════════════
# 5. owscatterplot.py
#    import: from AnyQt.QtCore import Qt, QTimer, QPointF  → +QSize
#    sizeHint 없음 → 추가
#    super().__init__() 가 __init__ 끝부분
# ══════════════════════════════════════════════════════════
p = f"{DST}/owscatterplot.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QTimer, QPointF", "owscatterplot")
cls_pos = t.find("class OWScatterPlot(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
# sizeHint 삽입: init_pos 직전
sh = sizehint_block(1000, 600)
t = t[:init_pos] + sh + t[init_pos:]
# super().__init__() 다음: # manually register Matplotlib
ANCHOR = "        super().__init__()\n\n        # manually register Matplotlib file writers\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS + "\n", "owscatterplot.super()")
# 불필요하게 추가된 \n 정리 — FLAGS 끝에 이미 \n 있으므로
write(p, t); verify(p, "owscatterplot.py")
print(f"{'OK' if not any('owscatterplot' in e for e in errors) else 'NG'} owscatterplot.py")

# ══════════════════════════════════════════════════════════
# 6. owlineplot.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__(parent) 다음: self.__groups = []
# ══════════════════════════════════════════════════════════
p = f"{DST}/owlineplot.py"; t = read(p)
ANCHOR = "        super().__init__(parent)\n        self.__groups = []\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owlineplot.__init__")
write(p, t); verify(p, "owlineplot.py")
print(f"{'OK' if not any('owlineplot' in e for e in errors) else 'NG'} owlineplot.py")

# ══════════════════════════════════════════════════════════
# 7. owbarplot.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 다음: self.data: Optional[Table] = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owbarplot.py"; t = read(p)
ANCHOR = "        super().__init__()\n        self.data: Optional[Table] = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owbarplot.__init__")
write(p, t); verify(p, "owbarplot.py")
print(f"{'OK' if not any('owbarplot' in e for e in errors) else 'NG'} owbarplot.py")

# ══════════════════════════════════════════════════════════
# 8. owsieve.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 다음: self.data = self.discrete_data = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owsieve.py"; t = read(p)
ANCHOR = "        super().__init__()\n        self.data = self.discrete_data = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owsieve.__init__")
write(p, t); verify(p, "owsieve.py")
print(f"{'OK' if not any('owsieve' in e for e in errors) else 'NG'} owsieve.py")

# ══════════════════════════════════════════════════════════
# 9. owmosaic.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 다음: self.data = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owmosaic.py"; t = read(p)
ANCHOR = "        super().__init__()\n        self.data = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owmosaic.__init__")
write(p, t); verify(p, "owmosaic.py")
print(f"{'OK' if not any('owmosaic' in e for e in errors) else 'NG'} owmosaic.py")

# ══════════════════════════════════════════════════════════
# 10. owfreeviz.py
#    import: from AnyQt.QtCore import Qt, QRectF, QLineF, QPoint  → +QSize
#    sizeHint 없음 → 추가
#    OWAnchorProjectionWidget.__init__(self) 다음 → FLAGS
#    그다음: ConcurrentWidgetMixin.__init__(self)
# ══════════════════════════════════════════════════════════
p = f"{DST}/owfreeviz.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QRectF, QLineF, QPoint", "owfreeviz")
cls_pos = t.find("class OWFreeViz(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
sh = sizehint_block(800, 600)
t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        OWAnchorProjectionWidget.__init__(self)\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owfreeviz.OWAnchorProjectionWidget.__init__")
write(p, t); verify(p, "owfreeviz.py")
print(f"{'OK' if not any('owfreeviz' in e for e in errors) else 'NG'} owfreeviz.py")

# ══════════════════════════════════════════════════════════
# 11. owlinearprojection.py
#    import: from AnyQt.QtCore import QRectF, QLineF  → Qt, QSize 모두 추가
#    __init__ 없음 → sizeHint + __init__ 새로 추가 (_add_controls 앞)
# ══════════════════════════════════════════════════════════
p = f"{DST}/owlinearprojection.py"; t = read(p)
# Qt, QSize 모두 없음 — 정확한 치환
OLD_IMPORT = "from AnyQt.QtCore import QRectF, QLineF"
NEW_IMPORT = "from AnyQt.QtCore import Qt, QSize, QRectF, QLineF"
if OLD_IMPORT in t:
    t = t.replace(OLD_IMPORT, NEW_IMPORT, 1)
else:
    errors.append("  [MISS] owlinearprojection: QtCore import line")

ANCHOR = "    def _add_controls(self):\n"
NEW_BLOCK = (
    "    def sizeHint(self):\n"
    "        return QSize(800, 600)\n\n"
    "    def __init__(self):\n"
    "        super().__init__()\n"
    + FLAGS +
    "\n"
    "    def _add_controls(self):\n"
)
t = replace_once(t, ANCHOR, NEW_BLOCK, "owlinearprojection._add_controls")
write(p, t); verify(p, "owlinearprojection.py")
print(f"{'OK' if not any('owlinearprojection' in e for e in errors) else 'NG'} owlinearprojection.py")

# ══════════════════════════════════════════════════════════
# 12. owradviz.py
#    import: from AnyQt.QtCore import Qt, QRectF, QPoint  → +QSize
#    sizeHint 없음 → 추가
#    OWAnchorProjectionWidget.__init__(self) 다음 → FLAGS
# ══════════════════════════════════════════════════════════
p = f"{DST}/owradviz.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QRectF, QPoint", "owradviz")
cls_pos = t.find("class OWRadviz(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
sh = sizehint_block(800, 600)
t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        OWAnchorProjectionWidget.__init__(self)\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owradviz.OWAnchorProjectionWidget.__init__")
write(p, t); verify(p, "owradviz.py")
print(f"{'OK' if not any('owradviz' in e for e in errors) else 'NG'} owradviz.py")

# ══════════════════════════════════════════════════════════
# 13. owheatmap.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 다음: self.__pending_selection = self.selected_rows
# ══════════════════════════════════════════════════════════
p = f"{DST}/owheatmap.py"; t = read(p)
ANCHOR = "        super().__init__()\n        self.__pending_selection = self.selected_rows\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owheatmap.__init__")
write(p, t); verify(p, "owheatmap.py")
print(f"{'OK' if not any('owheatmap' in e for e in errors) else 'NG'} owheatmap.py")

# ══════════════════════════════════════════════════════════
# 14. owvenndiagram.py
#    import: from AnyQt.QtCore import Qt, QPointF, QRectF, QLineF  → +QSize
#    sizeHint 없음 → 추가 (OWVennDiagram 클래스)
#    super().__init__() 다음: # Diagram update is in progress
# ══════════════════════════════════════════════════════════
p = f"{DST}/owvenndiagram.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QPointF, QRectF, QLineF", "owvenndiagram")
cls_pos = t.find("class OWVennDiagram(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
sh = sizehint_block(700, 550)
t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        super().__init__()\n\n        # Diagram update is in progress\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owvenndiagram.__init__")
write(p, t); verify(p, "owvenndiagram.py")
print(f"{'OK' if not any('owvenndiagram' in e for e in errors) else 'NG'} owvenndiagram.py")

# ══════════════════════════════════════════════════════════
# 15. owsilhouetteplot.py
#    QSize 이미 있음, sizeHint 이미 있음
#    super().__init__() 다음: #: The input data
# ══════════════════════════════════════════════════════════
p = f"{DST}/owsilhouetteplot.py"; t = read(p)
ANCHOR = "        super().__init__()\n        #: The input data\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owsilhouetteplot.__init__")
write(p, t); verify(p, "owsilhouetteplot.py")
print(f"{'OK' if not any('owsilhouetteplot' in e for e in errors) else 'NG'} owsilhouetteplot.py")

# ══════════════════════════════════════════════════════════
# 16. owpythagorastree.py
#    import: from AnyQt.QtCore import Qt  → +QSize
#    sizeHint 없음 → 추가
#    super().__init__() 다음: # Instance variables
# ══════════════════════════════════════════════════════════
p = f"{DST}/owpythagorastree.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt", "owpythagorastree")
cls_pos = t.find("class OWPythagorasTree(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
sh = sizehint_block(800, 600)
t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        super().__init__()\n        # Instance variables\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owpythagorastree.__init__")
write(p, t); verify(p, "owpythagorastree.py")
print(f"{'OK' if not any('owpythagorastree' in e for e in errors) else 'NG'} owpythagorastree.py")

# ══════════════════════════════════════════════════════════
# 17. owpythagoreanforest.py
#    QSize 이미 있음, sizeHint 없음 → 추가
#    super().__init__() 다음: self.rf_model = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owpythagoreanforest.py"; t = read(p)
cls_pos = t.find("class OWPythagoreanForest(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
sh = sizehint_block(800, 600)
t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        super().__init__()\n        self.rf_model = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owpythagoreanforest.__init__")
write(p, t); verify(p, "owpythagoreanforest.py")
print(f"{'OK' if not any('owpythagoreanforest' in e for e in errors) else 'NG'} owpythagoreanforest.py")

# ══════════════════════════════════════════════════════════
# 18. owruleviewer.py
#    QSize 이미 있음 (multiline import), sizeHint 이미 있음
#    super().__init__() 다음: 빈줄 + self.data = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owruleviewer.py"; t = read(p)
ANCHOR = "        super().__init__()\n\n        self.data = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owruleviewer.__init__")
write(p, t); verify(p, "owruleviewer.py")
print(f"{'OK' if not any('owruleviewer' in e for e in errors) else 'NG'} owruleviewer.py")

# ══════════════════════════════════════════════════════════
# 19. ownomogram.py
#    QSize 이미 있음, sizeHint 확인 필요 (OWNomogram 클래스)
#    super().__init__() 다음: self.instances = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/ownomogram.py"; t = read(p)
cls_pos = t.find("class OWNomogram(")
# OWNomogram 클래스 내 sizeHint 있는지 확인
cls_text = t[cls_pos:]
has_sh = "def sizeHint" in cls_text[:cls_text.find("\nclass ") if "\nclass " in cls_text else len(cls_text)]
if not has_sh:
    init_pos = t.find("    def __init__(self):\n", cls_pos)
    sh = sizehint_block(1000, 600)
    t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        super().__init__()\n        self.instances = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "ownomogram.__init__")
write(p, t); verify(p, "ownomogram.py")
print(f"{'OK' if not any('ownomogram' in e for e in errors) else 'NG'} ownomogram.py")

# ══════════════════════════════════════════════════════════
# 20. owscoringsheetviewer.py
#    import: from AnyQt.QtCore import Qt, QRect, pyqtSignal as Signal  → +QSize
#    sizeHint 없음 → 추가
#    super().__init__() 다음: self.data = None
# ══════════════════════════════════════════════════════════
p = f"{DST}/owscoringsheetviewer.py"; t = read(p)
t = add_qsize(t, "from AnyQt.QtCore import Qt, QRect, pyqtSignal as Signal", "owscoringsheetviewer")
cls_pos = t.find("class OWScoringSheetViewer(")
init_pos = t.find("    def __init__(self):\n", cls_pos)
sh = sizehint_block(800, 500)
t = t[:init_pos] + sh + t[init_pos:]
ANCHOR = "        super().__init__()\n        self.data = None\n"
t = replace_once(t, ANCHOR, ANCHOR + FLAGS, "owscoringsheetviewer.__init__")
write(p, t); verify(p, "owscoringsheetviewer.py")
print(f"{'OK' if not any('owscoringsheetviewer' in e for e in errors) else 'NG'} owscoringsheetviewer.py")

# ══════════════════════════════════════════════════════════
# 결과 요약
# ══════════════════════════════════════════════════════════
print("\n" + "="*60)
if errors:
    print(f"경고/오류 {len(errors)}건:")
    for e in errors:
        print(e)
else:
    print("모든 파일 수정 완료, 문법 오류 없음.")
print("="*60)
