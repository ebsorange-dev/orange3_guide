# 📁 Orange3 공용 데이터 폴더

이 폴더는 **모든 Orange3 사용자(세션)가 공유하는** 분석용 데이터셋 저장소입니다.

## 🗺️ 경로 매핑

| 환경 | 경로 |
|------|------|
| **호스트 (Windows 탐색기)** | `E:\_26_Use_Orange_New_set_\data\` |
| **컨테이너 내 (Orange3 파일 위젯에서 보이는 경로)** | `/data/` |
| **마운트 모드** | 읽기 전용 (read-only) — 데이터 무결성 보장 |

> 마운트는 `session_manager/main.py`의 `HOST_DATA_PATH` 환경변수로 자동 설정됩니다. 각 Orange3 컨테이너가 시작될 때 이 폴더를 `/data`로 마운트합니다.

## 📂 카테고리 폴더 구조

```
data/
├── Classification/   # 분류 — iris, titanic, heart_disease, ...
├── Regression/       # 회귀 — housing, auto-mpg, servo
├── Clustering/       # 군집화 — wine, glass, brown-selected
├── Text/             # 텍스트 마이닝 — grimm-tales, deerwester, ...
├── Image/            # 이미지 분석 — painters, yoga-poses, bone-healing
├── TimeSeries/       # 시계열 — airpassengers, amzn_stock, ...
├── Bio/              # 생물정보학 — GDS series, dictyexpress
└── Misc/             # 기타 예제 — bone-marrow, sailing, ...
```

## 🍊 Orange3에서 사용하는 방법

### 방법 ① — `File` 위젯으로 직접 불러오기
1. Orange3 캔버스에서 `File` 위젯을 추가
2. 위젯 더블클릭 → `Browse` 클릭
3. 좌측 트리에서 **`/data`** 폴더로 이동
4. 카테고리 폴더 → `.tab` 파일 선택

### 방법 ② — 절대 경로 직접 입력 (Python Script 위젯)
```python
import Orange
data = Orange.data.Table("/data/Classification/iris.tab")
```

### 방법 ③ — Workflow(.ows) 파일에 경로 저장
워크플로우 파일이 다른 사용자에게 전달되어도 `/data/...` 경로는 모든 컨테이너에서 동일하게 작동합니다.

## ➕ 새 데이터 추가하는 방법

호스트 시스템에서 직접 폴더에 파일을 복사하면 즉시 모든 컨테이너에 반영됩니다 (별도 재시작 불필요):

```powershell
# Windows PowerShell 예시
Copy-Item "C:\Downloads\my_data.tab" `
          "E:\_26_Use_Orange_New_set_\data\Classification\"
```

또는

```bash
# Bash / Git Bash
cp ~/Downloads/my_data.tab \
   "E:/_26_Use_Orange_New_set_/data/Classification/"
```

## 📝 명명 규칙 (권장)

- **파일명**: 영문 소문자 + 하이픈 (`iris.tab`, `breast-cancer-wisconsin.tab`)
- **확장자**: `.tab` (Orange 네이티브) / `.csv` / `.xlsx` 가능
- **공백 금지**: `Yoga poses.tab` ❌ → `yoga-poses.tab` ✅
- **한글 금지**: 인코딩 호환성 문제로 ASCII만 사용

## 🔒 권한

- 컨테이너 내부에서는 **읽기 전용**으로 마운트되어 사용자가 실수로 수정/삭제할 수 없습니다.
- 데이터 추가/수정/삭제는 **호스트 시스템에서만** 수행하세요.

## 📊 현재 보유 데이터

| 카테고리 | 파일 수 | 비고 |
|---------|--------:|------|
| Classification | 10 | ✅ 완료 |
| Regression | 0 | (추가 예정) |
| Clustering | 0 | (추가 예정) |
| Text | 0 | (추가 예정) |
| Image | 0 | (추가 예정) |
| TimeSeries | 0 | (추가 예정) |
| Bio | 0 | (추가 예정) |
| Misc | 0 | (추가 예정) |

---
**갱신일**: 2026-05-09
**관리 정책**: 호스트에서 추가, 컨테이너에서 read-only 사용
