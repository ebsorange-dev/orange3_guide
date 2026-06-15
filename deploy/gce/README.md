# orange3web — Google Compute Engine 배포 가이드

Orange3 웹 배포를 GCE 리눅스 VM에 **lift-and-shift**로 외부 공개하는 절차.
현재 Windows에서 돌리는 것과 **동일한 docker-compose 스택**을 그대로 올린다.

> 왜 VM인가: 세션 매니저가 `docker.sock` 으로 GUI 컨테이너를 **동적 생성**하므로
> 실제 Docker 데몬이 있는 호스트가 필요하다. Cloud Run/App Engine(서버리스)에서는 불가.

---

## 0. 사전 준비
- gcloud CLI 설치 + 로그인 (`gcloud init`)
- 프로젝트·리전 선택

## 1. VM 생성

RAM 집약적(컨테이너당 ~650–925MB, warm pool 포함 가동 시 수십 GB). 규모별 예시:

| 규모 | 머신 타입 | vCPU/RAM |
|------|-----------|----------|
| 소~중 | `e2-highmem-8` | 8 / 64GB |
| 중~대 | `n2-highmem-16` | 16 / 128GB |

```bash
gcloud compute instances create orange3web \
  --zone=asia-northeast3-a \
  --machine-type=e2-highmem-8 \
  --image-family=ubuntu-2204-lts --image-project=ubuntu-os-cloud \
  --boot-disk-size=120GB --boot-disk-type=pd-ssd \
  --tags=orange3web
```

## 2. 방화벽 (외부 접속 허용)

세션 매니저(`8888`) + GUI 컨테이너 포트 범위(`10000–10199`)를 연다.
GUI 컨테이너는 `0.0.0.0:<port>` 에 바인딩되고, 브라우저가 noVNC로 **직접** 접속한다.

```bash
gcloud compute firewall-rules create orange3web-allow \
  --allow=tcp:8888,tcp:10000-10199 \
  --target-tags=orange3web --source-ranges=0.0.0.0/0
```

> 보안: 운영에서는 `0.0.0.0/0` 대신 사내 IP 대역으로 제한하거나,
> nginx/로드밸런서 뒤로 프록시하는 것을 권장(저장소에 nginx 구성 보유).

## 3. 코드 가져오기 + 부트스트랩

```bash
gcloud compute ssh orange3web --zone=asia-northeast3-a   # VM 접속

# VM 안에서
sudo mkdir -p /opt && sudo chown "$USER" /opt
cd /opt
git clone https://github.com/ebsorange-dev/orange3web.git
cd orange3web
bash deploy/gce/setup_gce.sh      # Docker 설치 + .env 생성(HOST_BASE 자동)
newgrp docker                     # docker 그룹 즉시 적용 (또는 재로그인)
```

> 빌드 의존: 한국어 번역/오버라이드 파일은 저장소에 포함되어 있어
> **별도 준비 없이** 클린 클론만으로 빌드된다(Orange3 본체는 빌드 시 pip 설치).

## 4. 빌드 + 기동

```bash
docker compose -f docker-compose.yml --profile build-only build   # 최초 1회 (수십 분)
docker compose up -d
docker compose ps
```

접속: **`http://<VM_EXTERNAL_IP>:8888`**

외부 IP 확인:
```bash
gcloud compute instances describe orange3web --zone=asia-northeast3-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

## 5. 튜닝 / 운영

- **warm pool 크기**: 작은 VM이면 RAM 절약을 위해 낮춘다.
  `docker-compose.yml` 의 `WARM_POOL_SIZE`(기본 25) → 예 5~8.
  또는 가동 중 `PUT /api/admin/pool {"main": N}` 로 조정.
- **로그/상태**: `docker compose logs -f session-manager`, `curl localhost:8888/api/metrics`
- **재시작**: `docker compose restart session-manager` (활성 세션 끊김 주의)
- **영속성**: `sessions/ config/ data/` 는 repo 디렉터리에 생성됨. VM 재생성 대비
  별도 **Persistent Disk**에 두려면 해당 경로를 디스크 마운트로 옮기고 HOST_BASE 조정.

## 6. HTTPS (선택, 후속)

기본 구성은 **전부 HTTP** (noVNC URL 이 `http://host:port` 라 세션 매니저도 HTTP 여야
mixed-content 회피). HTTPS가 필요하면:
- GUI 포트까지 TLS 종단하는 리버스 프록시(nginx) 구성, 또는
- GCP 외부 HTTPS 로드밸런서 + 인증서 (단, GUI 직접 포트 접속 경로 별도 처리 필요).
별도 트랙으로 진행 권장.

---

## 트러블슈팅

| 증상 | 원인 / 조치 |
|------|-------------|
| 캔버스가 안 뜸(noVNC 연결 실패) | 방화벽 `10000–10199` 미개방. 2번 규칙 확인 |
| `permission denied /var/run/docker.sock` | `newgrp docker` 또는 재로그인 |
| 빌드 중 디스크 부족 | 부트 디스크 100GB+ (이미지 gui 5GB·xpra 6.7GB) |
| OOM / 컨테이너 죽음 | RAM 부족 → 큰 머신 타입 또는 `WARM_POOL_SIZE` 축소 |
| 접속은 되나 화면 localhost 로 감 | 브라우저가 외부 IP로 접속했는지 확인(novnc_url은 요청 host를 따름) |
