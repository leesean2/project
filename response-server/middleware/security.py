"""
Webhook 위조 공격 완화 미들웨어

3계층 방어:
  1. HMAC-SHA256 서명 검증 + 타임스탬프 재전송(replay) 방지
  2. 소스 IP 화이트리스트 (CIDR 지원)
  3. 토큰 버킷(token bucket) 속도 제한 (IP당)

서명 형식 (GitHub 스타일):
  X-Webhook-Signature: sha256=<HMAC-SHA256(secret, "{timestamp}.{body}")>
  X-Webhook-Timestamp: <Unix timestamp>
"""

import hashlib
import hmac
import ipaddress
import logging
import threading
import time
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("security")

# 서명 관련 상수
_SIG_HEADER = "X-Webhook-Signature"
_TS_HEADER = "X-Webhook-Timestamp"
_TIMESTAMP_MAX_SKEW = 300   # 5분 이내 타임스탬프만 허용 (replay 방지)


# ─── 토큰 버킷 ────────────────────────────────────────────

class _TokenBucket:
    """
    스레드 안전 토큰 버킷.

    capacity  : 최대 누적 토큰 (burst 허용량)
    refill_rate: 초당 충전 토큰 수 (지속 허용 RPS)
    """

    __slots__ = ("_capacity", "_refill_rate", "_tokens", "_last_refill", "_lock")

    def __init__(self, capacity: int, refill_rate: float):
        self._capacity = float(capacity)
        self._refill_rate = refill_rate
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._lock = threading.Lock()

    def consume(self, tokens: int = 1) -> bool:
        """토큰 1개 소모. 가능하면 True, 소진되면 False."""
        with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                self._capacity,
                self._tokens + elapsed * self._refill_rate,
            )
            self._last_refill = now
            if self._tokens >= tokens:
                self._tokens -= tokens
                return True
            return False

    @property
    def remaining(self) -> float:
        with self._lock:
            return self._tokens


# ─── 메인 보안 클래스 ──────────────────────────────────────

class WebhookSecurity:
    """
    Webhook 요청에 대한 3계층 보안 미들웨어.

    validate() 호출 → (allowed: bool, http_status: int, reason: str)
    """

    def __init__(
        self,
        secret: str,
        hmac_required: bool = True,
        ip_whitelist: Optional[List[str]] = None,
        rate_limit_capacity: int = 100,
        rate_limit_refill_rate: float = 3.0,
    ):
        """
        Args:
            secret            : HMAC-SHA256 공유 비밀키
            hmac_required     : True이면 서명 없는 요청 거부
            ip_whitelist      : 허용 IP 목록 (CIDR 표기 지원, None이면 비활성)
            rate_limit_capacity   : IP당 burst 허용 요청 수
            rate_limit_refill_rate: IP당 초당 충전 속도 (지속 RPS)
        """
        self._secret = secret.encode("utf-8") if secret else b""
        self._hmac_enabled = bool(secret)
        self._hmac_required = hmac_required and bool(secret)

        self._buckets: Dict[str, _TokenBucket] = {}
        self._buckets_lock = threading.Lock()
        self._rl_capacity = rate_limit_capacity
        self._rl_refill = rate_limit_refill_rate

        self._whitelist: List[
            ipaddress.IPv4Network | ipaddress.IPv6Network
        ] = []
        if ip_whitelist:
            for entry in ip_whitelist:
                entry = entry.strip()
                if not entry:
                    continue
                try:
                    self._whitelist.append(
                        ipaddress.ip_network(entry, strict=False)
                    )
                except ValueError:
                    logger.warning("Invalid IP/CIDR in whitelist: %r", entry)

        self._log_startup_warnings(secret, hmac_required)

    def _log_startup_warnings(self, secret: str, hmac_required: bool) -> None:
        if not secret and hmac_required:
            logger.error(
                "WEBHOOK_SECRET 미설정 + HMAC_REQUIRED=true → "
                "모든 webhook 요청이 거부됩니다. "
                "08-setup-signing-proxy.sh 를 먼저 실행하세요."
            )
        elif not secret:
            logger.warning(
                "WEBHOOK_SECRET 미설정 — HMAC 검증 비활성화됨. "
                "프로덕션에서는 반드시 서명을 사용하세요."
            )

        if not self._whitelist:
            logger.info("IP whitelist 비활성화 (WEBHOOK_IP_WHITELIST 미설정)")
        else:
            nets = [str(n) for n in self._whitelist]
            logger.info("IP whitelist 활성화: %s", ", ".join(nets))

        logger.info(
            "Rate limit: burst=%d, refill=%.1f req/s",
            self._rl_capacity,
            self._rl_refill,
        )
        logger.info(
            "HMAC: enabled=%s, required=%s",
            self._hmac_enabled,
            self._hmac_required,
        )

    # ─── 공개 API ──────────────────────────────────────────

    def validate(
        self,
        remote_addr: str,
        headers: Dict[str, str],
        body: bytes,
    ) -> Tuple[bool, int, str]:
        """
        Webhook 요청 유효성 검사.

        Returns:
            (allowed, http_status, reason)
            http_status: 200=OK, 401=HMAC실패, 403=IP차단, 429=속도초과
        """
        client_ip = self._extract_client_ip(remote_addr, headers)

        # ① 속도 제한 (가장 저렴한 검사를 먼저)
        if not self._check_rate_limit(client_ip):
            logger.warning("Rate limit exceeded: ip=%s", client_ip)
            return False, 429, f"Too Many Requests from {client_ip}"

        # ② IP 화이트리스트
        if self._whitelist and not self._is_allowed_ip(client_ip):
            logger.warning("Blocked source IP: %s", client_ip)
            return False, 403, f"Source IP {client_ip} not in whitelist"

        # ③ HMAC 서명 검증
        if self._hmac_required:
            ok, reason = self._verify_hmac(headers, body)
            if not ok:
                logger.warning("HMAC failed: ip=%s reason=%s", client_ip, reason)
                return False, 401, reason
        elif self._hmac_enabled:
            # 서명 헤더가 있으면 검증, 없으면 패스 (soft mode)
            if _SIG_HEADER in headers:
                ok, reason = self._verify_hmac(headers, body)
                if not ok:
                    logger.warning("HMAC failed (soft): ip=%s reason=%s", client_ip, reason)
                    return False, 401, reason

        return True, 200, "ok"

    def remaining_tokens(self, remote_addr: str, headers: Dict[str, str]) -> float:
        """현재 IP의 잔여 토큰 수 반환 (응답 헤더 표시용)."""
        ip = self._extract_client_ip(remote_addr, headers)
        with self._buckets_lock:
            bucket = self._buckets.get(ip)
        return bucket.remaining if bucket else float(self._rl_capacity)

    # ─── 내부 구현 ─────────────────────────────────────────

    def _extract_client_ip(self, remote_addr: str, headers: Dict[str, str]) -> str:
        """
        실제 클라이언트 IP 추출.
        서명 프록시가 X-Forwarded-For: 127.0.0.1 을 추가하므로 이를 우선.
        """
        xff = headers.get("X-Forwarded-For", "").split(",")[0].strip()
        if xff:
            return xff
        # remote_addr 에서 포트 제거 ("127.0.0.1:12345" → "127.0.0.1")
        addr = remote_addr.strip()
        if addr.startswith("["):
            # IPv6: "[::1]:12345"
            bracket_end = addr.find("]")
            if bracket_end != -1:
                return addr[1:bracket_end]
        elif ":" in addr:
            return addr.rsplit(":", 1)[0]
        return addr

    def _is_allowed_ip(self, ip: str) -> bool:
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in self._whitelist)
        except ValueError:
            logger.error("Cannot parse IP for whitelist check: %r", ip)
            return False

    def _check_rate_limit(self, ip: str) -> bool:
        with self._buckets_lock:
            if ip not in self._buckets:
                self._buckets[ip] = _TokenBucket(
                    self._rl_capacity, self._rl_refill
                )
            bucket = self._buckets[ip]
        return bucket.consume()

    def _verify_hmac(
        self, headers: Dict[str, str], body: bytes
    ) -> Tuple[bool, str]:
        """
        HMAC-SHA256 서명 검증.

        서명 형식: X-Webhook-Signature: sha256=<hex>
        서명 대상: "{X-Webhook-Timestamp}.{request_body}"
        타임스탬프: ±5분 허용 (replay 방지)
        """
        sig_header = headers.get(_SIG_HEADER, "")
        ts_header = headers.get(_TS_HEADER, "")

        if not sig_header:
            return False, f"Missing {_SIG_HEADER} header"
        if not ts_header:
            return False, f"Missing {_TS_HEADER} header"

        # 타임스탬프 범위 검사
        try:
            ts = int(ts_header)
        except ValueError:
            return False, f"Invalid {_TS_HEADER} value: {ts_header!r}"

        skew = abs(int(time.time()) - ts)
        if skew > _TIMESTAMP_MAX_SKEW:
            return False, (
                f"Timestamp skew too large: {skew}s > {_TIMESTAMP_MAX_SKEW}s "
                "(possible replay attack)"
            )

        # 서명 형식 확인
        if not sig_header.startswith("sha256="):
            return False, f"Signature must start with 'sha256=', got: {sig_header[:20]!r}"

        received_hex = sig_header[len("sha256="):]

        # 예상 서명 계산: HMAC-SHA256(secret, timestamp + "." + body)
        signed_payload = ts_header.encode("utf-8") + b"." + body
        expected_hex = hmac.new(
            self._secret, signed_payload, hashlib.sha256
        ).hexdigest()

        # 타이밍 공격 방지: compare_digest 사용
        if not hmac.compare_digest(expected_hex, received_hex):
            return False, "HMAC signature mismatch"

        return True, "ok"
