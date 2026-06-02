# Google Cloud 배포 가이드 (orange3web)

> 목적: **로컬 → GCP(GCE) 이관 시 "위젯 스타일이 빠지는" 사고를 재발 없이** 배포·운영하기 위한 단일 기준 문서.
> 핵심 원인은 단 하나 — **`HOST_BASE` 경로**다. 이 문서의 체크리스트만 지키면 재발하지 않는다.

---

## 0. TL;DR (가장 중요한 한 가지)

이 서비스는 위젯 스타일(QSS)과 위젯 오버라이드를 **이미지에 굽지 않고**, 호스트 파일을
세션 컨테이너에 **bind-mount** 해서 입힌다. 그래서 호스트 경로 `HOST_BASE` 가 틀리면
스타일이 **에러 없이 조용히** 빠진다.

```
.env 의 HOST_BASE = "이 호스트(VM)에서 repo 의 절대경로" 여야 한다.
  - 로컬(Windows/Docker Desktop): /e/_26_Use_Orange_New_set_   ← 드라이브 문자식
  - GCP(Linux GCE):               /opt/orange3web (clone 한 실제 경로)  ← 리눅스 절대경로
```

> ⛔ **절대 금지:** 로컬의 `.env`(HOST_BASE=/e/...) 를 GCP 로 그대로 복사/커밋.
> GCP 에서는 그 경로가 존재하지 않아 Docker 가 빈 디렉터리를 만들어 마운트 → 스타일 누락.

---

## 1. 왜 스타일이 빠졌나 (원인 분석)

| 구성요소 | 값 | 의미 |
|---|---|---|
| `WIDGETS_HOST_PATH` | `${HOST_BASE}/widgets_override` | 오버라이드 위젯(.py/.svg/.png) 호스트 소스 |
| `LAUNCHER_HOST_PATH` | `${HOST_BASE}/orange3_launcher.py` | **QSS 스타일 주입 런처** 호스트 소스 |

- `session_manager/main.py` 의 `build_widget_override_volumes()` 는 호스트 경로의
  **존재 여부를 검증하지 않는다**(컨테이너 안에서 호스트 FS 가 안 보임).
- `HOST_BASE` 가 틀리면 → bind 소스가 없음 → Docker 가 **빈 디렉터리 자동 생성** →
  오버라이드/런처가 빈 파일로 덮임 → **위젯 스타일 미적용**(원본 기본 모양).
- 로컬은 `/e/...` 가 Docker Desktop 에 매핑돼 동작하므로 **로컬만 정상**으로 보였다.

---

## 2. 신규 배포 (Fresh deploy on GCE)

```bash
# 1) VM 에서 repo clone (경로는 자유, 예: /opt/orange3web)
sudo git clone https://github.com/ebsorange-dev/orange3web.git /opt/orange3web
cd /opt/orange3web

# 2) 부트스트랩 — Docker 설치 + .env 자동 생성(HOST_BASE = 현재 repo 경로)
bash deploy/gce/setup_gce.sh
#  ↳ .env 가 이미 있어도 HOST_BASE 를 현재 경로로 '강제 교정'하도록 개선됨(아래 §5)

# 3) 이미지 빌드
docker compose -f docker-compose.yml --profile build-only build

# 4) 기동
docker compose up -d

# 5) 검증 (필수, §4)
docker logs orange3-session-manager 2>&1 | grep mount-check
```

방화벽(로컬 gcloud 에서 1회):
```bash
gcloud compute firewall-rules create orange3web-allow \
  --allow=tcp:8888,tcp:10000-10199,tcp:13901-13950 \
  --target-tags=orange3web --source-ranges=0.0.0.0/0
```

접속: `http://<VM_EXTERNAL_IP>:8888`

---

## 3. 재배포 / 코드 업데이트

```bash
cd /opt/orange3web
git pull
bash deploy/gce/setup_gce.sh        # HOST_BASE 재확인/교정 (idempotent)
docker compose build                 # 변경 시
docker compose down && docker compose up -d
docker logs orange3-session-manager 2>&1 | grep mount-check   # 검증
```

> `main.py` 는 ro 로 핫마운트되므로 코드 수정 후 `docker restart orange3-session-manager`
> 만으로도 반영된다. 단 **HOST_BASE 변경은 컨테이너 재생성(up -d)** 이 필요.

---

## 4. 배포 후 검증 체크리스트 ✅

```bash
# (a) HOST_BASE 가 이 VM 의 실제 repo 경로인가
grep HOST_BASE .env
test -d "$(grep -m1 HOST_BASE .env | cut -d= -f2)/widgets_override" && echo OK || echo "✗ 경로없음"
test -f "$(grep -m1 HOST_BASE .env | cut -d= -f2)/orange3_launcher.py" && echo OK || echo "✗ 런처없음"

# (b) session-manager 가 본 env
docker exec orange3-session-manager env | grep -E 'HOST_BASE|WIDGETS_HOST_PATH|LAUNCHER_HOST_PATH'

# (c) 기동 로그의 자동 마운트 검증 결과 (핵심)
docker logs orange3-session-manager 2>&1 | grep mount-check
#   정상:  [mount-check] 위젯 오버라이드/런처 호스트 바인드 정상 (launcher NNNNN B, ...)
#   문제:  [mount-check] 위젯 스타일/오버라이드 마운트 문제 감지: ...

# (d) 실제 세션 컨테이너의 바인드 소스 경로 확인
docker inspect $(docker ps -q -f ancestor=orange3-gui | head -1) \
  --format '{{json .Mounts}}' | tr ',' '\n' | grep -i widgets_override | head
```

브라우저에서 새 세션을 열어 **위젯 사이드바/노드 스타일**이 로컬과 동일하면 완료.

---

## 5. 재발 방지 장치 (이미 코드에 반영됨)

1. **`deploy/gce/setup_gce.sh` 자동 교정**
   - `.env` 가 이미 있어도 `HOST_BASE` 가 현재 repo 경로와 다르면 **강제로 교정**(이전 값 `.env.bak.*` 백업).
   - Windows 드라이브식(`/e/...`) 잔존을 명시 경고.

2. **`session_manager/main.py` 기동 시 마운트 검증 가드 `_validate_host_mounts()`**
   - env 미설정 / `/widgets_override` 빈 마운트 / **실제 컨테이너 프로브로 런처 파일이 비어있는지** 점검.
   - 문제 시 `log.error("[mount-check] ...")` 로 크게 출력.
   - 환경변수 **`STRICT_WIDGET_OVERRIDE=1`** 이면 문제 발견 시 **기동 중단**(프로덕션 권장).

3. **`.gitignore` 에 `.env` 포함 권장** — 로컬 `.env` 가 GCP 로 커밋/복사되지 않게.
   (호스트별 값이므로 repo 에 넣지 말 것. 템플릿은 `deploy/gce/.env.gce.example`.)

> 프로덕션 권장 설정: `.env` 에 `STRICT_WIDGET_OVERRIDE=1` 추가 → 스타일 누락 상태로는
> 아예 안 뜨게 하여 "조용한 실패" 를 원천 차단.

---

## 6. 롤백

```bash
cd /opt/orange3web
git log --oneline -5
git checkout <직전_정상_커밋>
# .env 는 호스트 고유이므로 보존됨. HOST_BASE 만 재확인:
bash deploy/gce/setup_gce.sh
docker compose up -d
```

`.env` 를 잘못 건드렸으면 백업에서 복구:
```bash
ls -t .env.bak.* | head -1        # 최신 백업
cp "$(ls -t .env.bak.* | head -1)" .env
```

---

## 7. 서버 구성 정보 (운영 기준값, 2026-06-02)

### 7.1 컨테이너 구성
| 컨테이너 | 이미지 | 포트(호스트) | 역할 |
|---|---|---|---|
| session-manager | `orange3-session-manager` | **8888** → 8080 | 세션 오케스트레이션 + API |
| nginx | `nginx:1.27-alpine` | **8889** | 리버스 프록시 + 정적 오프로드 |
| web-server | `orange3-web-server` | 9508(내부) | 정적/보조 서빙 |
| (동적) GUI 세션 | `orange3-gui` | **10000–10199** | 사용자별 Orange3 (noVNC) |
| (동적) Xpra 세션 | `orange3-xpra:poc` | **13901–13950** | Xpra 실험 경로 |

### 7.2 세션당 자원
| 항목 | 값 | env |
|---|---|---|
| 메모리 상한 | **2 GiB** | `CONTAINER_MEM_LIMIT=2g` |
| CPU 상한 | **4 코어** | `cpu_quota=400000 / cpu_period=100000` |
| 유휴 타임아웃 | **7200초(2h)** | `SESSION_TIMEOUT=7200` |
| baseline 메모리 | ~775 MB (유휴) | — |

### 7.3 워밍풀(Warm Pool) — 즉시 배정 대기 컨테이너
| 풀 | 피크 | 유휴 | 비고 |
|---|---|---|---|
| noVNC(web) | **12** | 4 | `WARM_POOL_SIZE` / `WARM_POOL_SIZE_IDLE` |
| Xpra | **8** | 4 | `XPRA_WARM_POOL_SIZE` / `_IDLE` |
| 피크 시간대(KST) | `WARM_PEAK_HOURS=8-16` | | 그 외 유휴 크기 적용 |
| 동시 부팅 제한 | `WARM_BOOT_CONCURRENCY=6` | | 부팅 CPU 스파이크 분산 |
| 워밍 최대 생존 | `WARM_MAX_AGE=1800s` | | 초과 시 자동 교체 |

### 7.4 호스트(현재 측정 기준)
| 항목 | 값 |
|---|---|
| Docker 엔진 CPU | 20 코어 |
| Docker 엔진 RAM | ≈ 31.2 GiB (33.5 GB) |

### 7.5 동시 접속 수용량 (capacity)
| 기준 | 한계 | 비고 |
|---|---|---|
| 포트풀(web) | 200 | 10000–10199 |
| 포트풀(xpra) | 50 | 13901–13950 |
| CPU | ~5명 풀버스트 | 20 ÷ 4 (소프트, 초과 시 분배) |
| **메모리(하드리밋·안전)** | **≈ 14명** | (RAM − 인프라~3GiB) ÷ 2GiB ← **실질 상한** |
| 피크 워밍 baseline | web12+xpra8 ≈ 20개 상주 | 유휴 자원 점유 고려 |

> **인원 증설 시:** ① Docker/WSL2 또는 VM RAM 증설, ② `CONTAINER_MEM_LIMIT` 하향(1~1.5g),
> ③ 다중 호스트 분산. 메모리가 병목이므로 포트풀(200)은 여유.

---

## 8. 배포 이력 / 변경 로그 (Changelog)

> 신규 배포·중요 변경 시 **여기 한 줄씩 추가**(날짜 / 환경 / 변경 / 커밋). 운영 추적용.

| 날짜 | 환경 | 변경 내용 | 비고/커밋 |
|---|---|---|---|
| 2026-06-02 | local→GCP | **위젯 스타일 누락 원인 = HOST_BASE 오설정** 확정. setup_gce.sh HOST_BASE 강제 교정 + main.py `_validate_host_mounts()` 가드 + 본 문서 작성 | 재발방지 |
| 2026-05-31 | 운영 | 컨테이너 메모리 상한 2g 도입, 워밍풀 메모리 절감(피크/유휴 분리) | compose |
| 2026-05-23 | 실험 | Xpra 전환 실험(Phase 2) 경로 추가 | `orange3-xpra:poc` |

---

## 9. 자주 겪는 증상 → 원인 표

| 증상 | 1순위 원인 | 확인 |
|---|---|---|
| **위젯 스타일만 빠짐**(기능은 정상) | `HOST_BASE` 오설정 | §4 (c) `mount-check` 로그 |
| 특정 위젯 아이콘 누락 | override .svg/.png 마운트 누락 | `WIDGETS_HOST_PATH` 하위 파일 확인 |
| 세션이 안 뜸/포트 충돌 | 포트풀 고갈 또는 좀비 컨테이너 | `docker ps`, 매니저 재기동 |
| SQL Table 등 숨긴 위젯이 보임 | override 미적용 **또는** 위젯 레지스트리 캐시 잔존 | §4 + `widget-registry.pck` 재생성 |
| OOM 으로 세션 죽음 | 세션 2GiB 초과 | `CONTAINER_MEM_LIMIT` 상향 또는 인원↓ |

---

_마지막 갱신: 2026-06-02 · 관리 기준 문서. 배포·구성 변경 시 본 문서와 §8 이력을 함께 갱신할 것._
