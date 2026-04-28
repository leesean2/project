# Runtime Detection Module

**Policy-as-Code K8s Compliance Platform — 런타임 탐지 & 자동 대응**

Falco(eBPF) + AI 차등 대응 + NetworkPolicy 자동 격리 + 오탐 완화 3중 레이어 + Prometheus 메트릭

---

## Architecture

```
  ┌──────────────────────────────────────────────────────────────────┐
  │                        Kubernetes Cluster                        │
  │                                                                  │
  │  Pod syscall ──► Falco (modern_ebpf DaemonSet)                   │
  │                         │ http_output                            │
  │                         ▼                                        │
  │              Signing Proxy (localhost:5001)                      │
  │              HMAC-SHA256 서명 + 타임스탬프 주입                  │
  │                         │                                        │
  │                         ▼                                        │
  │              Response Server (:5000)                             │
  │  ┌────────────────────────────────────────────────────────────┐  │
  │  │                                                            │  │
  │  │  WebhookSecurity (POST /webhook)                           │  │
  │  │  ① Rate Limit (token bucket, IP당)                        │  │
  │  │  ② IP Whitelist (CIDR 지원)                               │  │
  │  │  ③ HMAC-SHA256 서명 검증 + replay 방지                    │  │
  │  │  API Auth                                                  │  │
  │  │  ④ DELETE /isolations → Bearer API_TOKEN                  │  │
  │  │  ⑤ POST /heartbeat   → X-Watchdog-Token                   │  │
  │  │                  │                                         │  │
  │  │  EventProcessor  ▼                                         │  │
  │  │  1. Parse FalcoEvent                                       │  │
  │  │  2. HeartbeatMonitor.record_event()   ◄── 침묵 탐지       │  │
  │  │  3. K8s Metadata Enrichment          (container→pod)      │  │
  │  │     container_id 형식 검증 (hex 12~64자, 비정상 시 skip) │  │
  │  │  4. FalsePositiveFilter              ◄── 2차 오탐 필터    │  │
  │  │  5. ThreatClassifier                                       │  │
  │  │     AI Mode  → confidence < threshold → fallback          │  │
  │  │     Fallback → confidence < threshold → severity 하향     │  │
  │  │  6. Differential Response                                  │  │
  │  │     fp_suppressed:  log only (FP 억제)                    │  │
  │  │     low:            log only                               │  │
  │  │     medium:         alert & monitor                        │  │
  │  │     high:           NetworkPolicy 자동 격리 ──► K8s API   │  │
  │  │  7. EventStore (ring buffer)                               │  │
  │  │  8. MetricsStore ──────────────────────────► Prometheus   │  │
  │  │                                                 │          │  │
  │  └────────────────────────────────────────────────┼──────────┘  │
  │                                                    └──► Grafana  │
  └──────────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
Policy-as-code-Complience/
├── response-server/                  # Python 웹훅 서버 (stdlib only)
│   ├── server.py                     # 엔트리포인트 — 모듈 조립 + 서버 시작
│   ├── models/
│   │   └── events.py                 # FalcoEvent, Classification, ResponseRecord
│   ├── core/
│   │   ├── __init__.py               # EventStore — 링 버퍼 + 조회/필터/집계
│   │   ├── classifier.py             # ThreatClassifier — AI + fallback + confidence 임계값
│   │   ├── false_positive_filter.py  # FalsePositiveFilter — 2차 오탐 완화
│   │   ├── heartbeat.py              # HeartbeatMonitor — 침묵 탐지
│   │   ├── metrics.py                # MetricsStore — Prometheus exposition
│   │   └── processor.py             # EventProcessor — 파이프라인 오케스트레이션
│   ├── k8s/
│   │   └── client.py                 # KubeClient — NetworkPolicy CRUD + pod 메타 조회
│   ├── handlers/
│   │   └── http.py                   # HTTP 핸들러 — webhook + REST API
│   ├── middleware/
│   │   └── security.py               # WebhookSecurity — HMAC + IP whitelist + rate limit
│   ├── tests/
│   │   ├── test_all.py               # 단위 테스트 20개
│   │   └── test_integration.py       # 통합 테스트 (실제 HTTP 서버 기동)
│   └── Dockerfile
├── falco/
│   ├── values.yaml                   # Helm values — modern_ebpf + 커스텀 룰
│   └── compliance-rules.yaml         # 컴플라이언스 룰 6개 + 자체 보호 룰 5개
├── manifests/
│   ├── response-server.yaml          # NS + RBAC + Deployment + Service
│   ├── signing-proxy.yaml            # HMAC Signing Proxy — Sidekick → Response Server
│   ├── falco-watchdog.yaml           # Heartbeat Watchdog DaemonSet (신규)
│   ├── test-workloads.yaml           # 테스트용 취약 Pod들
│   ├── prometheus-integration.yaml   # Prometheus scrape config + ServiceMonitor
│   └── grafana/
│       ├── runtime-dashboard.json
│       └── dashboard-configmap.yaml
├── scripts/
│   ├── 00-deploy-all.sh              # 전체 원스텝 배포
│   ├── 01-setup-cluster.sh           # kind 클러스터 생성
│   ├── 02-deploy-falco.sh            # Falco + Sidekick Helm 배포
│   ├── 03-deploy-response-server.sh  # Docker build + K8s 배포
│   ├── 04-run-tests.sh               # 공격 시뮬레이션
│   ├── 05-cleanup.sh                 # 테스트 리소스 정리
│   ├── 06-attack-demo.sh             # 졸업심사 데모 (다단계 공격)
│   ├── 07-harden-falco.sh            # chattr +i + heartbeat watchdog 설치
│   └── 08-setup-signing-proxy.sh     # Signing Proxy + HMAC 키 배포
└── docs/
    └── ai-api-spec.yaml              # AI 모듈 API 인터페이스 명세
```

---

## Falco Custom Rules

### 컴플라이언스 탐지 룰 (container.id != host)

모든 룰에 `evt.dir = <` 조건 적용 — syscall 진입이 아닌 반환(완료) 시점에만 발화해 이중 발화 방지.

| # | Rule | Priority | ISMS-P / PCI-DSS | 탐지 대상 | 주요 조건 |
|---|------|----------|-----------------|----------|----------|
| 1 | Read Sensitive File | WARNING | ISMS-P 2.6.1, PCI-DSS 7.1 | /etc/shadow, SSH 키, kubeconfig | `evt.dir = <` |
| 2 | Shell Spawned | WARNING | ISMS-P 2.6.1 | 컨테이너 내 interactive shell exec | `evt.dir = <`, `proc.tty != 0` |
| 3 | Unexpected Outbound | NOTICE | ISMS-P 2.6.7, PCI-DSS 1.3 | 외부 IP 연결 (C2 통신) | `evt.dir = <`, CIDR 사설대역 제외, `falcoctl` 제외 |
| 4 | Container Reconnaissance | NOTICE | ISMS-P 2.11.4 | whoami, nmap, /proc 스캔 | `evt.dir = <` |
| 5 | Privilege Escalation | CRITICAL | ISMS-P 2.6.1, PCI-DSS 7.1 | setuid/setgid to root | `evt.dir = <`, `evt.arg.uid = 0 or evt.arg.euid = 0` |
| 6 | Write Monitored Directory | ERROR | ISMS-P 2.11.1 | /bin, /usr/bin 등 변조 | `evt.dir = <`, `O_WRONLY or O_RDWR` 플래그 검사 |

**Rule 3 사설 IP 필터**: K8s 클러스터 내부 통신(10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 127.0.0.0/8)을 제외해 오탐 방지.

**Rule 5 강화**: `user.uid != 0` 만으로는 부족 — `evt.arg.uid = 0 or evt.arg.euid = 0` 조건으로 실제 root 권한 획득 시도만 탐지.

**Rule 6 강화**: 읽기 전용 오픈은 제외, `O_WRONLY` / `O_RDWR` 플래그가 있는 쓰기 시도만 탐지.

### Falco 자체 보호 룰 (container.id = host)

| # | Rule | Priority | 탐지 대상 | 오탐 완화 조건 |
|---|------|----------|----------|--------------|
| 7 | Falco Tamper - Binary Write | CRITICAL | /usr/bin/falco, falcoctl 쓰기 시도 | `proc.pname not in (패키지 매니저)` + `loginuid != 4294967295` |
| 8 | Falco Tamper - Rules File Write | CRITICAL | /etc/falco/ 설정 변조 | `proc.pname not in (apt/ansible/helm)` + `loginuid != 4294967295` |
| 9 | Falco Tamper - Remove Immutability | CRITICAL | `chattr -i /usr/bin/falco` | — |
| 10 | Falco Tamper - Stop or Disable Service | CRITICAL | `systemctl stop/disable falco` | — |
| 11 | Falco Heartbeat Canary | NOTICE | /var/run/falco-heartbeat touch | `container.id = host or container.name = "falco-watchdog"` |

> **룰 레벨 오탐 완화**: Tamper 룰에 `proc.pname`(부모 프로세스) 조건과 `user.loginuid = 4294967295` 제외 조건을 추가해 패키지 업그레이드/배포 자동화로 인한 오탐을 1차 차단.

> **Heartbeat Canary 이중 경로**: `container.id = host` (호스트 systemd 서비스) 와 `container.name = "falco-watchdog"` (K8s DaemonSet) 을 모두 허용.

---

## Threat Classification

### AI Mode (`AI_ENDPOINT` 설정 시)

```
POST AI_ENDPOINT → { "severity": "low|medium|high", "reason": "...", "confidence": 0.85 }
```

- `confidence < AI_CONFIDENCE_THRESHOLD` (기본 0.6) → fallback으로 재분류 + `inc_ai(fallback=True)` 계상
- AI 타임아웃/오류 시 자동 fallback

### Fallback Mode (AI 미연결 또는 confidence 미달)

4가지 요소를 조합해서 severity를 결정:

| 요소 | 내용 |
|------|------|
| ① Falco Priority | Critical/Alert/Emergency → high, Error/Warning → medium, Notice → low |
| ② Rule Pattern | 키워드 boost: `privilege escalation`→high, `shell spawned`→medium 등 |
| ③ Context Score | root user(+1), prod NS(+1), 공격 도구(+2), 복합 위협 태그(+1) — score ≥ 3 → high |
| ④ Confidence 하향 | fallback confidence < `FALLBACK_CONFIDENCE_THRESHOLD`(기본 0.35) → severity 한 단계 하향 |

---

## False Positive Mitigation (오탐 완화 3중 레이어)

호스트 프로세스 오탐 문제를 세 단계로 완화합니다.

```
Falco 이벤트
  ▼
[Layer 1] Falco 룰 컨텍스트 조건
  - proc.pname 기반 부모 프로세스 화이트리스트
  - user.loginuid = 4294967295 제외 (커널/데몬 프로세스)
  ▼ (통과한 이벤트)
[Layer 2] FalsePositiveFilter (Response Server 2차 필터)
  - fp_score 계산 (0.0 = 실제 위협, 1.0 = 확실한 오탐)
  - fp_score >= 0.75 (FP_SUPPRESS_THRESHOLD) → action = fp_suppressed
  - fp_score >= 0.45 (FP_DOWNGRADE_THRESHOLD) → severity 한 단계 하향
  ▼ (억제되지 않은 이벤트)
[Layer 3] AI/Fallback Confidence 임계값
  - AI confidence < AI_CONFIDENCE_THRESHOLD → fallback 재분류
  - Fallback confidence < FALLBACK_CONFIDENCE_THRESHOLD → severity 하향
```

### fp_score 계산 기준

**호스트 이벤트** (`container.id = host`):

| 조건 | 가산점 |
|------|--------|
| 호스트 이벤트 기본 | +0.10 |
| `proc.name` ∈ 시스템 프로세스 셋 | +0.50 |
| `proc.pname` ∈ 시스템 프로세스 셋 | +0.30 |
| `user.loginuid = 4294967295` (데몬) | +0.25 |
| 정상 (프로세스, 경로) 패턴 매치 | +0.35 |

**컨테이너 이벤트**: 인프라/모니터링 이미지 (falco, prometheus, grafana 등) +0.20

**판정 예시**:
- `dpkg`(+0.50) + `apt-get`(부모, +0.30) + host(+0.10) = **0.90** → suppressed
- `python3`(알 수 없음) + loginuid=1001(사용자) + host(+0.10) = **0.10** → 실제 경보 유지

---

## Falco Hardening

### chattr +i 변조 방지 (`07-harden-falco.sh`)

```bash
./scripts/07-harden-falco.sh
```

Falco 바이너리, 룰 파일, 설정 파일에 `chattr +i`(immutable 플래그)를 설정해 root 권한으로도 덮어쓸 수 없게 잠금. Tamper 룰이 발화하면 시도 자체를 CRITICAL로 기록.

### Heartbeat Watchdog

`falco-watchdog` **K8s DaemonSet** (`manifests/falco-watchdog.yaml`) 이 30초마다 두 경로로 Falco 생존을 검증한다.

**경로 1 — Falco 파이프라인 전체 테스트 (Canary)**:

```
subprocess touch /var/run/falco-heartbeat (proc.name=touch)
  → Falco Heartbeat Canary 룰 발화
  → Sidekick → signing-proxy → Response Server /webhook
```

**경로 2 — Falco 프로세스 직접 확인**:

```
/proc 스캔 (hostPID=true) → Falco 프로세스 생존 확인
  → POST /api/v1/heartbeat {"falco_status": "running"|"stopped"}
  → HeartbeatMonitor.record_watchdog() 갱신
```

DaemonSet 배포:

```bash
kubectl apply -f manifests/falco-watchdog.yaml
```

HeartbeatMonitor가 백그라운드에서 주기적으로 감시:

| 조건 | 동작 |
|------|------|
| 이벤트 스트림 `HEARTBEAT_SILENCE_THRESHOLD`(기본 90s) 초과 | CRITICAL 로그 + `compliance_falco_silence_total` 증가 |
| Watchdog heartbeat `threshold × 2` 초과 | CRITICAL 로그 (watchdog 서비스 장애 의심) |
| Watchdog에서 `falco_status=stopped` 수신 | 즉시 CRITICAL |

> **OPA/Gatekeeper 구현 시 주의**: falco-watchdog 은 호스트 `/var/run` 에 쓰기 위해 `runAsUser: 0` 으로 실행된다. Gatekeeper non-root 정책 적용 시 `compliance-system` 네임스페이스 또는 `falco-watchdog` Pod에 예외 Constraint 추가 필요.

---

## Webhook Security

### Signing Proxy (`08-setup-signing-proxy.sh`)

```
Falco → localhost:5001 (Signing Proxy) → localhost:5000/webhook (Response Server)
```

- Falco → Signing Proxy: 평문 HTTP (루프백 전용)
- Signing Proxy → Response Server: `X-Webhook-Signature: sha256=<HMAC>` + `X-Webhook-Timestamp` 헤더 추가

```bash
./scripts/08-setup-signing-proxy.sh   # 키 생성, 서비스 등록, K8s Secret 주입
```

### WebhookSecurity 미들웨어 (3계층)

| 순서 | 계층 | 동작 |
|------|------|------|
| ① | Token Bucket Rate Limit | IP당 burst `RATE_LIMIT_CAPACITY`(기본 100), 지속 `RATE_LIMIT_REFILL_RATE`(기본 3 req/s) — 초과 시 429 |
| ② | IP Whitelist | `WEBHOOK_IP_WHITELIST` 설정 시 CIDR 기반 필터링 — 차단 시 403 |
| ③ | HMAC-SHA256 검증 | 서명 불일치 또는 타임스탬프 ±5분 초과 시 401 (replay 방지) |

`WEBHOOK_HMAC_REQUIRED=true` (기본): 서명 없는 요청 즉시 거부 (hard mode)
`WEBHOOK_HMAC_REQUIRED=false`: 서명 헤더가 있으면 검증, 없으면 통과 (soft mode)

### 보안 개선 사항 요약

| 식별자 | 위치 | 내용 |
|--------|------|------|
| HIGH #4 | `handlers/http.py` | POST `/api/v1/heartbeat` — `X-Watchdog-Token` 헤더 인증 추가 |
| HIGH #5 | `handlers/http.py` | DELETE `/api/v1/isolations` — `Authorization: Bearer API_TOKEN` 인증 추가 |
| HIGH #6 | `handlers/http.py` | CORS `Access-Control-Allow-Origin: *` → `ALLOWED_ORIGINS` 화이트리스트 + `Vary: Origin` |
| MEDIUM #7 | `handlers/http.py` | GET `/api/v1/events?limit` — 최대 500건 상한 (`_MAX_EVENT_LIMIT`) 추가 |
| MEDIUM #8 | `core/processor.py` | `container_id` hex 형식 검증 (12~64자) — K8s API 남용 및 캐시 오염 방지 |

---

## REST API Reference

| Method | Path | 인증 | Description |
|--------|------|------|-------------|
| POST | `/webhook` | HMAC (WebhookSecurity) | Falco Sidekick 이벤트 수신 |
| GET | `/healthz` | 없음 | Health check |
| GET | `/readyz` | 없음 | Readiness check |
| GET | `/metrics` | 없음 | Prometheus 메트릭 |
| GET | `/api/v1/events` | 없음 | 이벤트 목록 (`?severity=`, `?namespace=`, `?limit=`, 최대 500건) |
| GET | `/api/v1/events/summary` | 없음 | 대시보드용 집계 (severity/rule/namespace/action별) |
| GET | `/api/v1/events/:id` | 없음 | 단일 이벤트 상세 |
| GET | `/api/v1/isolations` | 없음 | 활성 격리 NetworkPolicy 목록 (`?namespace=` 필터 지원) |
| DELETE | `/api/v1/isolations/:ns/:name` | Bearer `API_TOKEN` | 격리 해제 |
| POST | `/api/v1/heartbeat` | `X-Watchdog-Token` | Watchdog 생존 신호 수신 (falco_status 포함) |
| GET | `/api/v1/falco/status` | 없음 | Falco heartbeat / 침묵 탐지 상태 조회 (healthy 시 200, silenced 시 503) |

### API 인증 상세

**DELETE `/api/v1/isolations/:ns/:name`** — Bearer 토큰 인증 (`[HIGH #5]`)

```
Authorization: Bearer <API_TOKEN>
```

`API_TOKEN` 미설정 시 503, 토큰 불일치 시 401. 타이밍 공격 방지를 위해 `hmac.compare_digest` 사용.

**POST `/api/v1/heartbeat`** — Watchdog 전용 토큰 인증 (`[HIGH #4]`)

```
X-Watchdog-Token: <HEARTBEAT_TOKEN>
```

`HEARTBEAT_TOKEN` 미설정 시 503, 토큰 불일치 시 401. `falco-watchdog` DaemonSet에서만 호출.

**CORS** — 와일드카드 금지, 환경변수 화이트리스트 (`[HIGH #6]`)

요청 `Origin` 헤더가 `ALLOWED_ORIGINS`에 없으면 브라우저 CORS 차단. `Vary: Origin` 헤더로 프록시 캐시 오염 방지.

---

## Prometheus Metrics

| Metric | Type | Description |
|--------|------|-------------|
| `compliance_falco_events_total{severity}` | counter | 심각도별 이벤트 수 |
| `compliance_falco_events_by_rule_total{rule}` | counter | 룰별 이벤트 수 |
| `compliance_falco_events_by_namespace_total{namespace}` | counter | NS별 이벤트 수 |
| `compliance_response_actions_total{action}` | counter | 대응 조치별 카운트 |
| `compliance_network_isolations_total` | counter | 자동 격리 성공 수 |
| `compliance_network_isolation_errors_total` | counter | 격리 실패 수 |
| `compliance_ai_requests_total` | counter | AI 분류 요청 수 |
| `compliance_ai_errors_total` | counter | AI 분류 실패 수 |
| `compliance_ai_fallbacks_total` | counter | AI confidence 미달 포함 fallback 수 |
| `compliance_ai_latency_seconds` | histogram | AI 응답 시간 |
| `compliance_fp_suppressed_total{rule}` | counter | 룰별 FP 억제 이벤트 수 |
| `compliance_fp_downgraded_total` | counter | FP 필터로 severity 하향된 이벤트 수 |
| `compliance_webhook_rejected_total{status,reason}` | counter | HTTP 상태코드별 거부 수 (hmac_failed/ip_blocked/body_too_large/rate_limited) |
| `compliance_webhook_rejected_by_reason_total{reason}` | counter | 정규화된 사유별 거부 수 (고카디널리티 방지용 레이블) |
| `compliance_hmac_mode` | gauge | HMAC 강제 모드 (1=hard/필수, 0=soft/선택) |
| `compliance_falco_silence_total` | counter | 침묵 감지 누적 횟수 |
| `compliance_falco_is_silenced` | gauge | 현재 침묵 상태 (0=정상, 1=침묵) |
| `compliance_falco_last_event_age_seconds` | gauge | 마지막 이벤트 경과 시간 |
| `compliance_server_uptime_seconds` | gauge | 서버 가동 시간 |

---

## Environment Variables

| 변수 | 기본값 | 설명 |
|------|--------|------|
| `SERVER_PORT` | `5000` | HTTP 리슨 포트 |
| `LOG_LEVEL` | `INFO` | 로그 레벨 (DEBUG/INFO/WARNING/ERROR/CRITICAL) |
| `AI_ENDPOINT` | `` | AI 분류 모듈 URL (미설정 시 fallback) |
| `AI_TIMEOUT` | `5` | AI 요청 타임아웃(초) |
| `AI_CONFIDENCE_THRESHOLD` | `0.6` | 이 미만이면 fallback 재분류 |
| `FALLBACK_CONFIDENCE_THRESHOLD` | `0.35` | Fallback 이 미만이면 severity 하향 |
| `FP_SUPPRESS_THRESHOLD` | `0.75` | fp_score 이상이면 fp_suppressed |
| `FP_DOWNGRADE_THRESHOLD` | `0.45` | fp_score 이상이면 severity 하향 |
| `AUTO_ISOLATE` | `true` | HIGH 이벤트 자동 NetworkPolicy 격리 |
| `EVENT_STORE_SIZE` | `2000` | 인메모리 이벤트 링 버퍼 크기 |
| `HEARTBEAT_SILENCE_THRESHOLD` | `90` | 이벤트 침묵 경보 임계값(초) |
| `HEARTBEAT_CHECK_INTERVAL` | `30` | 침묵 감시 체크 주기(초) |
| `WEBHOOK_SECRET` | `` | HMAC 공유 비밀키 |
| `WEBHOOK_HMAC_REQUIRED` | `true` | true이면 서명 없는 요청 거부 (hard mode 기본) |
| `WEBHOOK_IP_WHITELIST` | `` | 허용 IP/CIDR 목록 (콤마 구분) |
| `RATE_LIMIT_CAPACITY` | `100` | IP당 burst 허용 요청 수 |
| `RATE_LIMIT_REFILL_RATE` | `3.0` | IP당 초당 충전 속도 (지속 RPS) |
| `API_TOKEN` | `` | REST API 관리 작업용 Bearer 토큰 (DELETE /isolations 등) — 미설정 시 503 |
| `HEARTBEAT_TOKEN` | `` | Watchdog heartbeat 전용 인증 토큰 (`X-Watchdog-Token` 헤더) — 미설정 시 503 |
| `ALLOWED_ORIGINS` | `http://localhost:3000` | CORS 허용 오리진 목록 (콤마 구분) |

---

## Quick Start

```bash
# 전체 배포 (kind cluster + Falco + Response Server)
./scripts/00-deploy-all.sh

# 단계별 배포
./scripts/01-setup-cluster.sh          # kind 클러스터 생성
./scripts/02-deploy-falco.sh           # Falco + Sidekick Helm 배포 (modern_ebpf, driver.enabled=true)
./scripts/03-deploy-response-server.sh # Docker build + K8s 배포

# Falco 보호 강화 (권장)
./scripts/07-harden-falco.sh           # chattr +i 변조 방지
./scripts/08-setup-signing-proxy.sh    # HMAC Signing Proxy 설치

# Heartbeat Watchdog 배포 (Falco 침묵 탐지)
kubectl apply -f manifests/falco-watchdog.yaml

# 검증
./scripts/04-run-tests.sh              # 공격 시뮬레이션
./scripts/06-attack-demo.sh            # 졸업심사 데모 (다단계 공격)

# API 접근
kubectl port-forward -n compliance-system svc/response-server 5000:5000
curl localhost:5000/api/v1/events/summary
curl localhost:5000/metrics
curl localhost:5000/api/v1/events?severity=high
curl localhost:5000/api/v1/falco/status   # Falco 생존 상태 확인
```

---

## Tests

```bash
cd response-server

# 단위 테스트 20개 (클러스터 불필요)
python3 tests/test_all.py

# 통합 테스트 (클러스터 불필요, 실제 HTTP 서버 기동)
python3 tests/test_integration.py
```

**단위 테스트 커버리지**:
- FalcoEvent 파싱 (3개)
- ThreatClassifier fallback 분류 (4개) + confidence 임계값 (2개)
- EventStore CRUD / 필터 / 링 버퍼 / 요약 (4개)
- MetricsStore Prometheus 렌더링 + FP 카운터 (2개)
- FalsePositiveFilter 억제 / 정상 공격 / downgrade / 임계값 (5개)

---

## Integration Points

| From → To | Interface | Description |
|-----------|-----------|-------------|
| Falco → Signing Proxy | HTTP POST (localhost) | Falco http_output |
| Signing Proxy → Response Server | HTTP POST + HMAC 헤더 | 서명된 이벤트 전달 |
| Response Server → AI Module | HTTP POST (`AI_ENDPOINT`) | 위협 분류 (C 파트 담당) |
| Response Server → K8s API | HTTPS | NetworkPolicy CRUD + pod 메타 조회 |
| Response Server → Prometheus | HTTP GET `/metrics` | 메트릭 스크래핑 |
| Prometheus → Grafana | PromQL | 대시보드 시각화 (C 파트 담당) |
| Response Server → Dashboard | HTTP GET `/api/v1/*` | 이벤트 조회 API |
| Watchdog DaemonSet → Response Server | HTTP POST `/api/v1/heartbeat` | Falco 생존 신호 (30s 주기) |
| Watchdog DaemonSet → Falco (via file) | touch `/var/run/falco-heartbeat` | Canary 룰 트리거 — 파이프라인 전체 테스트 |

---

## Changelog

### 2026-04-28

#### 버그 수정

| 파일 | 수정 내용 |
|------|----------|
| `falco/values.yaml` | `driver.enabled: false → true` — 비활성화 상태로 커밋돼 있어 Falco가 시스콜을 전혀 수집하지 못하던 문제 수정 |
| `falco/values.yaml` | `load_plugins: ["k8s-audit", "json"] → []` — 두 플러그인 모두 별도 설치 필요. 없으면 Falco 기동 실패 |
| `falco/values.yaml` | Rule 3 (Outbound Connection) exclusion에 `falcoctl` 추가 — falcoctl 정상 통신이 오탐으로 잡히던 문제 수정 |
| `manifests/prometheus-integration.yaml` | ServiceMonitor `port: metrics → http` — Service 포트 이름(`http`)과 불일치로 Prometheus 스크레이핑 실패하던 문제 수정 |
| `manifests/prometheus-integration.yaml` | relabel_config 주소 구성 버그 수정 — 어노테이션 포트만 `__address__`에 쓰던 문제를 `pod_ip:port` 조합으로 수정; 폴백 포트 `8080 → 5000` |

#### Falco 룰 강화 (`falco/compliance-rules.yaml` — `values.yaml` 동기화)

| 룰 | 변경 내용 |
|----|----------|
| Rules 1~6 전체 | `evt.dir = <` 추가 — syscall 반환(완료) 시점에만 발화, 이중 발화 방지 |
| Rule 3 (Outbound Connection) | `fd.ip != "0.0.0.0"` → CIDR 사설대역 필터 (10/8, 172.16/12, 192.168/16, 127/8 제외) + `falcoctl` 추가 |
| Rule 5 (Privilege Escalation) | `evt.arg.uid = 0 or evt.arg.euid = 0` 조건 추가 — 실제 root 권한 획득 시도만 탐지 |
| Rule 6 (Write Monitored Dir) | `O_WRONLY or O_RDWR` 플래그 검사 추가 — 읽기 전용 오픈 오탐 제거 |
| Heartbeat Canary | `container.id = host` → `(container.id = host or container.name = "falco-watchdog")` + `proc.name`에 `python3` 추가 |

#### 신규 추가

| 파일 | 내용 |
|------|------|
| `manifests/falco-watchdog.yaml` | Falco Heartbeat Watchdog K8s DaemonSet 신규 구현. 30초 주기로 Canary 파일 touch + /proc 스캔 + Response Server HTTP heartbeat 전송. 기존 README에 언급만 있고 구현체가 없었던 컴포넌트. |
