# Orange3 왼쪽 메뉴 레이어 분리 — 작업 명세서

**작성일:** 2026-05-12
**상태:** 검토 완료 / 본격 작업 대기
**예상 작업량:** 약 2일 (4단계 분할)
**관련 문서:** [layer_work_menu_report.html](layer_work_menu_report.html)

---

## 1. 목표

Orange3의 왼쪽 위젯 카테고리 사이드바(위젯 독)를 **HTML 레이어로 분리**하여 브라우저 왼쪽에 고정 표시. 진짜 Orange3 위젯 독은 숨김. 사용자가 HTML 사이드바를 통해 위젯을 캔버스에 드래그-드롭으로 추가할 수 있게 함.

## 2. 사용자 스토리

- "브라우저 viewport가 변하거나 zoom 변경 시에도 메뉴는 항상 같은 위치·크기에 보였으면 한다"
- "메뉴 영역만큼은 noVNC 지연 없이 즉시 반응했으면 한다"
- "위젯 클릭/드래그로 캔버스에 추가하는 기본 동작은 그대로 사용 가능해야 한다"

## 3. 기술 결정

| 항목 | 결정 |
|---|---|
| **렌더링 방식** | 100% HTML/CSS (브라우저 네이티브) |
| **카탈로그 출처** | Orange3 `WidgetRegistry` → JSON dump |
| **드래그-드롭 좌표 변환** | HTML drag end → iframe 상대 좌표 → noVNC scale 적용 → X11 scene 좌표 |
| **위젯 추가 명령 전달** | 시그널 파일 (`.add_widget.json`) → launcher watcher → `scheme.add_node()` |
| **진짜 위젯 독** | dock-hide 패치 활성화 (기존 코드 재사용) |

## 4. 단계별 구현 명세

### 단계 1 — 위젯 카탈로그 메타데이터 dump (0.5일)

#### 1.1 Launcher 추가 코드

`orange3_launcher.py`에 `WidgetRegistry` dump 함수 추가:

```python
def _dump_widget_catalog(output_path: str = "/config/.widget_catalog.json"):
    """현재 활성 WidgetRegistry를 순회하여 JSON 파일로 저장.

    출력 구조:
    {
      "language": "ko",
      "categories": [
        {
          "name": "데이터",
          "color": "#FFB861",
          "priority": 1,
          "widgets": [
            {
              "qualified_name": "Orange.widgets.data.owfile.OWFile",
              "name": "File",
              "description": "Read data from a file.",
              "icon_path": "icons/File.svg",  # 또는 base64
              "priority": 10,
              "keywords": ["data", "input", "load"]
            },
            ...
          ]
        },
        ...
      ]
    }
    """
    from orangecanvas.registry import WidgetRegistry
    from orangecanvas.application.canvasmain import CanvasMainWindow

    app = QApplication.instance()
    if app is None:
        return False

    # 활성 CanvasMainWindow에서 widget_registry 추출
    cmw = None
    for w in app.topLevelWidgets():
        if isinstance(w, CanvasMainWindow):
            cmw = w
            break
    if cmw is None:
        return False
    reg = cmw.widget_registry
    if reg is None:
        return False

    catalog = {
        "language": os.environ.get("LANG", "en").split("_")[0],
        "categories": [],
    }
    for cat_desc, widgets in reg.registry:
        cat_data = {
            "name": cat_desc.name,
            "color": cat_desc.background or "#cccccc",  # 카테고리 색상
            "priority": cat_desc.priority,
            "widgets": [],
        }
        for wd in widgets:
            # 아이콘 base64 인코딩 (HTML img src로 직접 사용 가능)
            icon_b64 = _encode_icon_base64(wd.icon)
            cat_data["widgets"].append({
                "qualified_name": wd.qualified_name,
                "name": wd.name,
                "description": wd.description or "",
                "icon_b64": icon_b64,
                "priority": wd.priority,
                "keywords": wd.keywords or [],
            })
        cat_data["widgets"].sort(key=lambda x: x["priority"])
        catalog["categories"].append(cat_data)
    catalog["categories"].sort(key=lambda x: x["priority"])

    with open(output_path, "w", encoding="utf-8") as f:
        import json
        json.dump(catalog, f, ensure_ascii=False, indent=2)
    print(f"[launcher] 위젯 카탈로그 dump: {output_path} ({sum(len(c['widgets']) for c in catalog['categories'])}개 위젯)", flush=True)
    return True
```

#### 1.2 dump 호출 시점

- Orange3 부팅 완료 후 `setup_ui_patched` 안에서 `QTimer.singleShot(3000, _dump_widget_catalog)`로 호출
- 또는 시그널 파일 `.widget_catalog_query` 감지 시 매번 다시 dump

#### 1.3 session_manager endpoint

`/widget-catalog` GET endpoint 추가:

```python
@app.get("/widget-catalog")
async def widget_catalog(sid: str):
    with _lock:
        info = sessions.get(sid)
    if not info:
        return JSONResponse({"ok": False, "error": "session not found"}, 401)
    catalog_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".widget_catalog.json")

    # 신호로 dump 트리거
    query_path = os.path.join(CONTAINER_SESSIONS_PATH, sid, ".widget_catalog_query")
    with open(query_path, "w") as f:
        f.write("1")

    # 응답 대기 (최대 5초)
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if os.path.isfile(catalog_path):
            with open(catalog_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return JSONResponse({"ok": True, **data})
        await asyncio.sleep(0.1)

    return JSONResponse({"ok": False, "error": "timeout"}, 504)
```

#### 1.4 검증 방법

- 컨테이너 부팅 후 `/widget-catalog?sid=<UUID>` 호출 → 카테고리 + 위젯 JSON 반환 확인
- 위젯 개수가 약 100~150개 사이인지 확인 (Orange3 기본 + add-ons)
- 한글 카테고리명이 올바른지 (`데이터`, `변환` 등)

---

### 단계 2 — HTML 사이드바 동적 렌더링 (0.5일)

#### 2.1 WRAPPER_PAGE JS 추가

페이지 로드 시 카탈로그 fetch + DOM 렌더링:

```javascript
async function _loadWidgetCatalog() {
  try {
    const r = await fetch('/widget-catalog?sid=' + SID);
    if (!r.ok) return;
    const j = await r.json();
    if (!j.ok) return;
    _renderHtmlDock(j.categories);
  } catch(e) {
    console.error('[hwd] catalog load failed:', e);
  }
}

function _renderHtmlDock(categories) {
  const dock = document.getElementById('html-widget-dock');
  if (!dock) return;
  dock.innerHTML = '';
  for (const cat of categories) {
    const el = document.createElement('div');
    el.className = 'hwd-cat';
    el.dataset.catName = cat.name;
    el.title = cat.name;
    el.innerHTML = `
      <div class="hwd-cat-icon" style="background:${cat.color}">${cat.name[0]}</div>
    `;
    el.addEventListener('click', () => _toggleWidgetPanel(cat));
    dock.appendChild(el);
  }
}

function _toggleWidgetPanel(cat) {
  // 패널 표시·숨김 토글
  let panel = document.getElementById('hwd-panel');
  if (!panel) {
    panel = document.createElement('div');
    panel.id = 'hwd-panel';
    document.body.appendChild(panel);
  }
  panel.innerHTML = `
    <div class="hwd-panel-header" style="background:${cat.color}">${cat.name}</div>
    <div class="hwd-panel-widgets">
      ${cat.widgets.map(w => `
        <div class="hwd-widget" draggable="true" data-qname="${w.qualified_name}" title="${w.description}">
          <img src="data:image/png;base64,${w.icon_b64}" alt="${w.name}" />
          <span>${w.name}</span>
        </div>
      `).join('')}
    </div>
  `;
  panel.classList.add('open');
}

// 페이지 로드 시 호출
_loadWidgetCatalog();
```

#### 2.2 CSS 추가 (위젯 패널)

```css
#hwd-panel {
  display: none;
  position: fixed;
  top: 83px;
  left: 60px;  /* 사이드바 너비 다음부터 */
  width: 220px;
  bottom: 0;
  background: #fff;
  border-right: 1px solid #d0d0d0;
  box-shadow: 2px 0 8px rgba(0,0,0,0.1);
  z-index: 8400;
  overflow-y: auto;
}
#hwd-panel.open { display: block; }
.hwd-panel-header {
  padding: 10px 14px;
  font-weight: 700;
  color: #fff;
  font-size: 14px;
}
.hwd-widget {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 8px 12px;
  cursor: grab;
  user-select: none;
  font-size: 13px;
  transition: background 0.1s;
}
.hwd-widget:hover { background: #f3f4f6; }
.hwd-widget:active { cursor: grabbing; }
.hwd-widget img { width: 24px; height: 24px; flex-shrink: 0; }
```

#### 2.3 검증 방법

- 페이지 로드 시 사이드바에 실제 Orange3 카테고리 + 색상 표시
- 카테고리 클릭 시 위젯 목록 패널 표시
- 위젯 아이콘이 실제 Orange3 SVG와 일치

---

### 단계 3 — 드래그-드롭 → 위젯 추가 (1일)

#### 3.1 HTML 드래그 이벤트

```javascript
document.querySelectorAll('.hwd-widget').forEach(el => {
  el.addEventListener('dragstart', (e) => {
    e.dataTransfer.effectAllowed = 'copy';
    e.dataTransfer.setData('text/plain', el.dataset.qname);
    // 드래그 중인 위젯 표시용
    _draggingWidget = el.dataset.qname;
  });
});

// iframe 위에 dragover/drop 받기 위해 오버레이 사용
const iframe = document.getElementById('vnc-frame');
iframe.style.pointerEvents = 'none'; // 드래그 중에만

// 또는 별도 drop zone 오버레이
const dropZone = document.createElement('div');
dropZone.id = 'hwd-drop-zone';
// position:fixed; top:83px; left:60px; right:0; bottom:0; pointer-events:none;
dropZone.addEventListener('dragover', (e) => {
  e.preventDefault();
  e.dataTransfer.dropEffect = 'copy';
});
dropZone.addEventListener('drop', (e) => {
  e.preventDefault();
  const qname = e.dataTransfer.getData('text/plain');
  const rect = dropZone.getBoundingClientRect();
  const x_viewport = e.clientX - rect.left;
  const y_viewport = e.clientY - rect.top;
  // viewport 좌표 → X11 scene 좌표 변환
  const x_scene = _convertToSceneX(x_viewport);
  const y_scene = _convertToSceneY(y_viewport);
  _addWidget(qname, x_scene, y_scene);
});
```

#### 3.2 좌표 변환 (`scaling=local` 환경)

```javascript
function _convertToSceneX(x_viewport) {
  // X11 framebuffer 너비 (서버 측, Xvnc geometry)
  const fb_width = 1920;  // 또는 noVNC에서 동적 조회
  const rect = iframe.getBoundingClientRect();
  return x_viewport * (fb_width / rect.width);
}
```

#### 3.3 Backend `/add-widget` endpoint

```python
@app.post("/add-widget")
async def add_widget(sid: str, request: Request):
    body = await request.json()
    qname = body.get("qualified_name")
    x = float(body.get("x", 0))
    y = float(body.get("y", 0))

    # 안전 검증
    if not re.match(r'^[\w.]+$', qname):
        return JSONResponse({"ok": False, "error": "invalid qname"}, 400)

    sess_dir = os.path.join(CONTAINER_SESSIONS_PATH, sid)
    signal_path = os.path.join(sess_dir, ".add_widget.json")
    with open(signal_path, "w", encoding="utf-8") as f:
        json.dump({"qualified_name": qname, "x": x, "y": y}, f)
    return JSONResponse({"ok": True})
```

#### 3.4 Launcher 위젯 추가 핸들러

```python
def _do_add_widget(payload_json: str):
    data = json.loads(payload_json)
    qname = data["qualified_name"]
    x = data["x"]
    y = data["y"]

    cmw = self._find_canvas_window()
    if cmw is None: return
    doc = cmw.current_document()
    scheme = doc.scheme()
    reg = cmw.widget_registry

    # qname으로 위젯 description 찾기
    widget_desc = None
    for cat_desc, widgets in reg.registry:
        for wd in widgets:
            if wd.qualified_name == qname:
                widget_desc = wd
                break
        if widget_desc:
            break
    if not widget_desc:
        print(f"[launcher] widget not found: {qname}", flush=True)
        return

    # SchemeNode 생성 + scheme에 추가 (undo macro 안에서)
    from orangecanvas.scheme.node import SchemeNode
    node = SchemeNode(widget_desc, position=(x, y))
    stack = doc.undoStack()
    stack.beginMacro("Add widget")
    doc.addNode(node)
    stack.endMacro()
    print(f"[launcher] added widget: {widget_desc.name} at ({x}, {y})", flush=True)
```

#### 3.5 검증 방법

- HTML 위젯 드래그 → 캔버스 drop → 정확한 위치에 노드 표시
- 드래그 후 Orange3 캔버스에 노드가 그려지는지
- Undo (Ctrl+Z) 가능한지

---

### 단계 4 — 진짜 Orange3 위젯 독 숨김 (0.1일)

이전에 작성한 dock-hide 패치 재활성화:

```python
# orange3_launcher.py setup_ui 패치 안에 추가
try:
    dw = getattr(self, 'dock_widget', None)
    if dw is not None:
        dw.setVisible(False)
        dw.setMaximumWidth(0)
except Exception:
    pass
```

방법 B (이벤트 루프 주기 검사)에도 추가.

---

## 5. API 스키마

### 5.1 GET `/widget-catalog?sid=<UUID>`

응답:
```json
{
  "ok": true,
  "language": "ko",
  "categories": [
    {
      "name": "데이터",
      "color": "#FFB861",
      "priority": 1,
      "widgets": [
        {
          "qualified_name": "Orange.widgets.data.owfile.OWFile",
          "name": "File",
          "description": "Read data from a file.",
          "icon_b64": "iVBORw0KG...",
          "priority": 10,
          "keywords": ["data", "input", "load"]
        }
      ]
    }
  ]
}
```

### 5.2 POST `/add-widget?sid=<UUID>`

요청 body:
```json
{
  "qualified_name": "Orange.widgets.data.owfile.OWFile",
  "x": 100.0,
  "y": 200.0
}
```

응답:
```json
{ "ok": true }
```

---

## 6. 데이터 흐름

```
[브라우저 페이지 로드]
   ↓
GET /widget-catalog?sid=X
   ↓
[session-manager] → 컨테이너에 .widget_catalog_query 신호
   ↓
[launcher watcher] → _dump_widget_catalog() 실행
   ↓
.widget_catalog.json 작성 (컨테이너 /config/ → 호스트 sessions/)
   ↓
[session-manager] → JSON 응답 반환
   ↓
[브라우저] → 사이드바 DOM 렌더링


[사용자 드래그 위젯 → 캔버스에 drop]
   ↓
좌표 변환 (viewport → scene)
   ↓
POST /add-widget {qname, x, y}
   ↓
[session-manager] → 컨테이너에 .add_widget.json 신호
   ↓
[launcher watcher] → _do_add_widget(payload)
   ↓
SchemeNode 생성 + scheme.add_node()
   ↓
[Orange3 canvas] → 새 노드 그림 (VNC 전송으로 클라이언트에도 보임)
```

---

## 7. 에러 핸들링

| 시나리오 | 처리 |
|---|---|
| `/widget-catalog` 타임아웃 (5초) | 클라이언트 토스트 "메뉴 로드 실패 — 새로고침 시도" |
| 카탈로그 dump 실패 (registry 없음) | 임시 정적 HTML로 fallback (현재 상태) |
| 위젯 qname이 registry에 없음 | launcher 로그 + 토스트 "위젯 추가 실패" |
| 드래그-드롭 좌표 음수 또는 범위 외 | x/y 클램프 (0 ≤ x ≤ canvas_width) |
| Orange3 종료 상태에서 add_widget | 신호 파일 무시 (다음 부팅 시 자동 삭제) |

---

## 8. 테스트 시나리오

| # | 시나리오 | 기대 결과 |
|---|---|---|
| 1 | 페이지 로드 | 카탈로그 fetch → 사이드바 렌더링 (1초 이내) |
| 2 | 카테고리 클릭 | 위젯 패널 표시 |
| 3 | 위젯 드래그-드롭 | 정확한 위치에 노드 그려짐 |
| 4 | Ctrl+Z (Undo) | 노드 사라짐 |
| 5 | 브라우저 zoom 변경 | 사이드바는 즉시 반응 (HTML 네이티브), 캔버스만 noVNC 지연 |
| 6 | 브라우저 창 리사이즈 | 사이드바 위치/크기 100% 고정 |
| 7 | 워크플로우 탭 전환 | 사이드바 그대로, 캔버스만 변경 |
| 8 | 언어 변경 (Korean → English) | 카탈로그 재dump → 사이드바 위젯명 변경 |
| 9 | add-on 설치 | 컨테이너 재시작 후 새 위젯 표시 |

---

## 9. 임시 작업 (현재 상태)

현재 정적 HTML 사이드바가 prototype으로 적용됨:

**위치**: [session_manager/main.py](session_manager/main.py) — `#html-widget-dock`

```html
<div id="html-widget-dock">
  <div class="hwd-cat" title="데이터 (Data)"> ... </div>
  ...
</div>
```

**특징**:
- 10개 카테고리 hardcoded (D/T/V/M/E/U/I/⏱/a/N)
- 클릭 시 `showToast('카테고리명 — 위젯 추가 동작 미연결')` 안내만
- 실제 Orange3 카탈로그와 무관 (시각 prototype)

**본격 작업 시작 시**:
1. 단계 1 (carbon catalog dump) 완성하면 정적 HTML → 동적 카탈로그로 교체
2. 단계 2~4 순차 진행
3. 임시 hwdAlert는 제거하고 _toggleWidgetPanel 등 실제 핸들러로 교체

---

## 10. 마일스톤

| 단계 | 작업 | 누적 시간 | 검증 |
|---|---|---|---|
| M1 | 단계 1 완료 — `/widget-catalog` endpoint 동작 | 0.5일 | curl로 JSON 확인 |
| M2 | 단계 2 완료 — 동적 사이드바 렌더링 | 1.0일 | 브라우저에서 시각 확인 |
| M3 | 단계 3 완료 — 드래그-드롭 위젯 추가 | 2.0일 | 위젯 노드 실제 생성 |
| M4 | 단계 4 완료 — 진짜 위젯 독 숨김 + 종합 테스트 | 2.5일 | 전체 시나리오 통과 |

각 마일스톤은 독립적 검증 가능. M1~M3은 진짜 위젯 독을 그대로 두고 진행 → 비교 검증 용이.

---

## 11. 참고 자료

- Orange3 `WidgetRegistry`: `orangecanvas/registry/base.py`
- Orange3 `SchemeNode`: `orangecanvas/scheme/node.py`
- Orange3 `doc.addNode()`: `orangecanvas/document/schemeedit.py`
- noVNC RFB scaling: https://github.com/novnc/noVNC/blob/master/docs/API.md

---

## 12. 결정 이력

- 2026-05-12 사용자 요청: 메뉴 분리 가능성 검토
- 2026-05-12 검토 완료: 7가지 옵션 평가 → 옵션 4 (HTML 복제) 권장
- 2026-05-12 임시 정적 HTML 사이드바 prototype 적용 (시각 확인용)
- 2026-05-12 본격 작업 보류 결정 → 본 명세서 작성

---

**문서 종료** · 본격 작업 재개 시 단계 1부터 순차 진행. 각 단계 검증 통과 후 다음 단계.
