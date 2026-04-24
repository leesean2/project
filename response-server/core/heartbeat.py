"""
Falco Heartbeat Monitor — 침묵 탐지 (Silence Detection)

동작 원리:
  1. Falco 이벤트가 webhook으로 수신될 때마다 last_event_time 갱신
  2. "Falco Heartbeat Canary" 룰 이벤트 수신 시 last_canary_time 갱신
     (Falco → http_output → Response Server 전체 파이프라인이 살아있음을 의미)
  3. falco-watchdog systemd 서비스가 POST /api/v1/heartbeat 전송 시
     last_watchdog_time 갱신 (Falco 프로세스 생존 여부 직접 확인 경로)
  4. 백그라운드 스레드가 check_interval마다 silence_threshold 초과 여부 검사
  5. 임계값 초과 시 CRITICAL 로그 + Prometheus 메트릭 증가
"""

import logging
import threading
import time
from typing import Optional

logger = logging.getLogger("heartbeat")

HEARTBEAT_RULE = "Falco Heartbeat Canary"


class HeartbeatMonitor:
    """
    Falco 이벤트 스트림의 침묵을 감지하는 모니터.

    silence_threshold 초 동안 이벤트가 없으면 CRITICAL 경보.
    watchdog heartbeat가 silence_threshold * 2 초 동안 없으면 별도 경보.
    """

    def __init__(
        self,
        metrics,
        silence_threshold: int = 90,
        check_interval: int = 30,
    ):
        self._metrics = metrics
        self._silence_threshold = silence_threshold
        self._check_interval = check_interval
        self._lock = threading.Lock()

        now = time.monotonic()
        # 서버 시작 직후 false-positive 방지: 처음 threshold 만큼 유예
        self._last_event_time: float = now
        self._last_canary_time: Optional[float] = None
        self._last_watchdog_time: Optional[float] = None
        self._last_watchdog_falco_status: str = "unknown"

        self._event_silenced: bool = False
        self._watchdog_silenced: bool = False
        self._thread: Optional[threading.Thread] = None

    # ─── Public API ───────────────────────────────────────

    def record_event(self, rule_name: str = "") -> None:
        """Falco webhook 이벤트 수신 시 호출. 모든 이벤트에 대해 호출."""
        with self._lock:
            self._last_event_time = time.monotonic()
            if rule_name == HEARTBEAT_RULE:
                self._last_canary_time = time.monotonic()
                logger.debug("Heartbeat canary received via Falco pipeline")

    def record_watchdog(self, falco_status: str = "unknown") -> None:
        """POST /api/v1/heartbeat 수신 시 호출 (watchdog 직접 경로)."""
        with self._lock:
            self._last_watchdog_time = time.monotonic()
            self._last_watchdog_falco_status = falco_status
            logger.debug("Watchdog heartbeat received (falco=%s)", falco_status)

        if falco_status == "stopped":
            logger.critical(
                "FALCO SERVICE DOWN: watchdog reports falco-modern-bpf is stopped!"
            )
            self._metrics.inc_falco_silence()

    def get_status(self) -> dict:
        """현재 heartbeat 상태를 딕셔너리로 반환 (REST API용)."""
        with self._lock:
            now = time.monotonic()
            event_age = now - self._last_event_time
            canary_age = (
                now - self._last_canary_time
                if self._last_canary_time is not None
                else None
            )
            watchdog_age = (
                now - self._last_watchdog_time
                if self._last_watchdog_time is not None
                else None
            )
            return {
                "status": "silenced" if self._event_silenced else "healthy",
                "last_event_age_seconds": round(event_age, 1),
                "last_canary_age_seconds": (
                    round(canary_age, 1) if canary_age is not None else None
                ),
                "last_watchdog_age_seconds": (
                    round(watchdog_age, 1) if watchdog_age is not None else None
                ),
                "watchdog_falco_status": self._last_watchdog_falco_status,
                "silence_threshold_seconds": self._silence_threshold,
                "watchdog_silence_threshold_seconds": self._silence_threshold * 2,
                "event_silenced": self._event_silenced,
                "watchdog_silenced": self._watchdog_silenced,
            }

    def start(self) -> None:
        """백그라운드 침묵 감시 스레드 시작."""
        self._thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="heartbeat-monitor"
        )
        self._thread.start()
        logger.info(
            "HeartbeatMonitor started (silence_threshold=%ds, check_interval=%ds)",
            self._silence_threshold,
            self._check_interval,
        )

    # ─── Internal ─────────────────────────────────────────

    def _monitor_loop(self) -> None:
        while True:
            time.sleep(self._check_interval)
            self._check_silence()

    def _check_silence(self) -> None:
        """
        [MEDIUM #7] Race Condition 수정:
        기존 코드는 lock 안에서 상태를 읽은 뒤 lock 밖에서 상태를 변경했음.
        → 읽기와 쓰기 사이에 다른 스레드가 상태를 바꾸면 불일치 발생.

        수정: 상태 읽기 → 새 상태 계산 → 쓰기를 하나의 lock 블록 안에서 수행.
        로그와 메트릭 업데이트만 lock 밖으로 분리 (I/O는 lock 밖이 원칙).
        """
        # 1단계: lock 안에서 현재 상태 스냅샷 + 새 상태 계산
        with self._lock:
            now = time.monotonic()
            event_age = now - self._last_event_time
            watchdog_age = (
                now - self._last_watchdog_time
                if self._last_watchdog_time is not None
                else None
            )

            # 이벤트 침묵 상태 계산
            prev_event_silenced = self._event_silenced
            new_event_silenced = event_age > self._silence_threshold
            self._event_silenced = new_event_silenced

            # watchdog 침묵 상태 계산
            prev_watchdog_silenced = self._watchdog_silenced
            new_watchdog_silenced = (
                watchdog_age is not None
                and watchdog_age > self._silence_threshold * 2
            )
            self._watchdog_silenced = new_watchdog_silenced

            # 메트릭 업데이트 (lock 안에서 gauge만 업데이트)
            self._metrics.set_falco_last_event_age(event_age)

        # 2단계: lock 밖에서 로그 + 카운터 메트릭 (I/O가 lock 안에 있으면 데드락 위험)
        if new_event_silenced and not prev_event_silenced:
            logger.critical(
                "FALCO SILENCE DETECTED: No events for %.0fs "
                "(threshold=%ds). Falco may be killed or compromised!",
                event_age,
                self._silence_threshold,
            )
            self._metrics.inc_falco_silence()
            self._metrics.set_falco_silenced(True)

        elif not new_event_silenced and prev_event_silenced:
            logger.info("Falco event stream resumed after silence (%.0fs)", event_age)
            self._metrics.set_falco_silenced(False)

        elif new_event_silenced:
            logger.warning("Falco still silent: %.0fs without events", event_age)

        if new_watchdog_silenced and not prev_watchdog_silenced:
            logger.critical(
                "FALCO WATCHDOG MISSING: No watchdog heartbeat for %.0fs! "
                "Watchdog service may be stopped.",
                watchdog_age,
            )
        elif not new_watchdog_silenced and prev_watchdog_silenced:
            logger.info("Watchdog heartbeat resumed")
