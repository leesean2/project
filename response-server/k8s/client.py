"""
Minimal Kubernetes API client using service account credentials.

No external dependencies — uses urllib from stdlib.
Handles:
- NetworkPolicy create / list / delete (auto-isolation)
- Pod label lookup (for NetworkPolicy targeting)
"""

import json
import logging
import re
import ssl
import threading
import time
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("kube-client")

# Namespaces that should never have pods isolated
SYSTEM_NAMESPACES = frozenset({
    "kube-system", "kube-public", "kube-node-lease",
    "falco", "compliance-system", "monitoring",
    "gatekeeper-system",
})

# [LOW #11] Service Account 토큰 캐시 TTL (초)
# K8s SA 토큰은 기본 1시간마다 갱신되므로 55분(3300초)마다 재읽기
_TOKEN_TTL: int = 3300

# [HIGH] K8s 리소스 이름 유효성 검증 정규식
# namespace: DNS 레이블 (소문자 영숫자 + -, 최대 63자)
# pod/policy 이름: DNS 서브도메인 (소문자 영숫자 + - + ., 최대 253자)
# URL 경로에 삽입되므로 슬래시·점점·공백 등 경로 조작 문자를 차단.
_K8S_NAMESPACE_RE = re.compile(r'^[a-z0-9][a-z0-9\-]{0,61}[a-z0-9]$|^[a-z0-9]$')
_K8S_NAME_RE = re.compile(r'^[a-z0-9][a-z0-9\-\.]{0,251}[a-z0-9]$|^[a-z0-9]$')


def _valid_k8s_namespace(name: str) -> bool:
    return bool(name) and bool(_K8S_NAMESPACE_RE.match(name))


def _valid_k8s_name(name: str) -> bool:
    return bool(name) and bool(_K8S_NAME_RE.match(name))


class KubeClient:
    """Kubernetes API client using in-cluster service account."""

    def __init__(self):
        self.api_server = "https://kubernetes.default.svc"
        self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        self.ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self._token: Optional[str] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None
        # [LOW #11] 토큰 만료 추적
        self._token_fetched_at: float = 0.0
        # [MEDIUM #9] 컨테이너 캐시 Race Condition 방지 Lock
        self._cache_lock = threading.Lock()
        self._container_cache: dict = {}
        self._cache_timestamp: float = 0.0

    # ─── Internal Helpers ─────────────────────────────────

    def _get_token(self) -> str:
        """
        [LOW #11] Service Account 토큰 TTL 기반 갱신.

        K8s SA 토큰은 기본 1시간마다 교체되므로 _TOKEN_TTL(3300초)마다
        파일을 다시 읽어 만료된 토큰으로 인한 K8s API 인증 실패를 방지.
        """
        now = time.time()
        if self._token is None or (now - self._token_fetched_at) > _TOKEN_TTL:
            try:
                with open(self.token_path) as f:
                    self._token = f.read().strip()
                self._token_fetched_at = now
                logger.debug("Service account token refreshed")
            except FileNotFoundError:
                logger.warning("No service account token found (outside cluster?)")
                self._token = ""
        return self._token

    def _get_ssl_ctx(self) -> ssl.SSLContext:
        if self._ssl_ctx is None:
            try:
                self._ssl_ctx = ssl.create_default_context(cafile=self.ca_path)
            except FileNotFoundError:
                raise RuntimeError(
                    "서비스 어카운트 CA 인증서를 찾을 수 없습니다. "
                    "클러스터 내부에서 실행 중인지 확인하세요."
                )
            except ssl.SSLError as e:
                raise RuntimeError(
                    f"CA 인증서 로딩 실패 (ssl): {type(e).__name__}. "
                    "인증서 파일이 유효한지 확인하세요."
                ) from e
        return self._ssl_ctx

    def _request(self, method: str, url: str, body: Optional[bytes] = None,
                 timeout: int = 10) -> Optional[dict]:
        """Generic API request. Returns parsed JSON or None on error."""
        headers = {
            "Authorization": f"Bearer {self._get_token()}",
            "Content-Type": "application/json",
        }
        req = urllib.request.Request(url, data=body, method=method, headers=headers)

        try:
            with urllib.request.urlopen(req, context=self._get_ssl_ctx(),
                                        timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            # [정보 노출 방지] 응답 본문 200자 제한, URL에서 민감한 경로 제거
            error_body = e.read().decode("utf-8", errors="replace")
            url_path = urllib.parse.urlparse(url).path if url else ""
            logger.error("K8s API %s %s → %d: %s", method, url_path, e.code, error_body[:200])
            return None
        except Exception as e:
            # [MEDIUM] 전체 URL 대신 경로만 로그에 기록하여 내부 서버 주소 노출 방지
            url_path = urllib.parse.urlparse(url).path if url else ""
            logger.error("K8s API %s %s → error: %s", method, url_path, e)
            return None

    # ─── Pod Operations ───────────────────────────────────

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict:
        """Fetch pod labels. Returns empty dict on failure."""
        # [HIGH] URL 경로 주입 방지 — K8s 이름 형식 검증
        if not _valid_k8s_namespace(namespace) or not _valid_k8s_name(pod_name):
            logger.warning(
                "Invalid namespace/pod_name for get_pod_labels: ns=%r pod=%r",
                namespace[:64], pod_name[:64],
            )
            return {}
        url = f"{self.api_server}/api/v1/namespaces/{namespace}/pods/{pod_name}"
        result = self._request("GET", url, timeout=5)
        if result:
            return result.get("metadata", {}).get("labels", {})
        return {}

    # ─── NetworkPolicy Operations ─────────────────────────

    def create_isolation_policy(self, namespace: str, pod_name: str,
                                 labels: dict, reason: str = "") -> Optional[str]:
        """
        Create a deny-all NetworkPolicy to isolate a pod.
        Returns the policy name on success, None on failure.
        """
        # [HIGH] URL 경로 주입 방지 — K8s 이름 형식 검증
        if not _valid_k8s_namespace(namespace) or not _valid_k8s_name(pod_name):
            logger.warning(
                "Invalid namespace/pod_name for isolation: ns=%r pod=%r",
                namespace[:64], pod_name[:64],
            )
            return None

        if namespace in SYSTEM_NAMESPACES:
            logger.warning("Refusing to isolate pod in system namespace: %s", namespace)
            return None

        # Build match labels from pod labels
        match_labels = self._select_match_labels(labels, pod_name)

        policy_name = f"isolate-{pod_name[:45]}-{int(time.time())}"

        policy = {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {
                "name": policy_name,
                "namespace": namespace,
                "labels": {
                    "managed-by": "compliance-response-server",
                    "action": "auto-isolate",
                    "triggered-by": "falco",
                    "target-pod": pod_name[:63],
                },
                "annotations": {
                    "compliance.platform/reason": reason or "Falco runtime threat detected",
                    "compliance.platform/created-at": datetime.now(timezone.utc).isoformat(),
                    "compliance.platform/target-pod": pod_name,
                },
            },
            "spec": {
                "podSelector": {"matchLabels": match_labels},
                "policyTypes": ["Ingress", "Egress"],
                "ingress": [],  # empty = deny all
                "egress": [],
            },
        }

        url = (f"{self.api_server}/apis/networking.k8s.io/v1"
               f"/namespaces/{namespace}/networkpolicies")

        result = self._request("POST", url, json.dumps(policy).encode("utf-8"))
        if result and result.get("metadata", {}).get("name"):
            created_name = result["metadata"]["name"]
            logger.info(
                "NetworkPolicy created: %s in %s (target: %s, labels: %s)",
                created_name, namespace, pod_name, match_labels,
            )
            return created_name

        logger.error("Failed to create NetworkPolicy for %s/%s", namespace, pod_name)
        return None

    def list_isolation_policies(self, namespace: str = "") -> list:
        """List all auto-isolation NetworkPolicies."""
        label_selector = "managed-by=compliance-response-server"
        if namespace:
            url = (f"{self.api_server}/apis/networking.k8s.io/v1"
                   f"/namespaces/{namespace}/networkpolicies"
                   f"?labelSelector={label_selector}")
        else:
            url = (f"{self.api_server}/apis/networking.k8s.io/v1"
                   f"/networkpolicies?labelSelector={label_selector}")

        result = self._request("GET", url)
        if result and "items" in result:
            return [
                {
                    "name": item["metadata"]["name"],
                    "namespace": item["metadata"]["namespace"],
                    "target_pod": item["metadata"].get("annotations", {}).get(
                        "compliance.platform/target-pod", ""),
                    "created_at": item["metadata"].get("annotations", {}).get(
                        "compliance.platform/created-at", ""),
                    "reason": item["metadata"].get("annotations", {}).get(
                        "compliance.platform/reason", ""),
                }
                for item in result["items"]
            ]
        return []

    def delete_isolation_policy(self, namespace: str, policy_name: str) -> bool:
        """Delete an isolation NetworkPolicy (un-isolate a pod)."""
        # [HIGH] URL 경로 주입 방지 — K8s 이름 형식 검증
        if not _valid_k8s_namespace(namespace) or not _valid_k8s_name(policy_name):
            logger.warning(
                "Invalid namespace/policy_name for delete: ns=%r policy=%r",
                namespace[:64], policy_name[:64],
            )
            return False
        url = (f"{self.api_server}/apis/networking.k8s.io/v1"
               f"/namespaces/{namespace}/networkpolicies/{policy_name}")

        result = self._request("DELETE", url)
        if result is not None:
            logger.info("NetworkPolicy deleted: %s/%s", namespace, policy_name)
            return True
        return False

    def delete_all_isolation_policies(self, namespace: str) -> int:
        """Delete all isolation policies in a namespace. Returns count deleted."""
        policies = self.list_isolation_policies(namespace)
        deleted = 0
        for p in policies:
            if self.delete_isolation_policy(p["namespace"], p["name"]):
                deleted += 1
        return deleted

    # ─── Helpers ──────────────────────────────────────────

    @staticmethod
    def _select_match_labels(labels: dict, pod_name: str) -> dict:
        """Pick the best labels for NetworkPolicy podSelector."""
        if not labels:
            return {"compliance-isolate": pod_name[:63]}

        # Prefer well-known label keys
        preferred_keys = [
            "app",
            "app.kubernetes.io/name",
            "app.kubernetes.io/instance",
            "name",
        ]
        for key in preferred_keys:
            if key in labels:
                return {key: labels[key]}

        # Fallback: first label
        first_key = next(iter(labels))
        return {first_key: labels[first_key]}

    # ─── Container → Pod Resolution ─────────────────────

    def resolve_container_to_pod(self, container_id: str) -> dict:
        """
        Find which Pod owns a given container ID.
        Searches all pods across all namespaces.
        Returns {"namespace": ..., "pod_name": ..., "labels": ...} or empty dict.

        [MEDIUM #9] _cache_lock으로 캐시 읽기/쓰기를 보호하여
        멀티스레드(webhook 비동기 처리) 환경의 Race Condition 방지.
        캐시 초기화와 갱신 모두 락 안에서 수행.
        """
        if not container_id or container_id in ("host", "<NA>"):
            return {}

        now = time.time()

        with self._cache_lock:
            # 캐시 만료 시 갱신 (락 안에서 수행하여 중복 갱신 방지)
            if now - self._cache_timestamp > 30:
                self._refresh_container_cache_locked()
                self._cache_timestamp = now

            # Short container IDs: Falco often gives 12-char prefix
            result = self._lookup_cache_locked(container_id)
            if result:
                return result

        # 캐시 미스 — 락 밖에서 잠깐 대기 후 1회 강제 갱신
        # (다른 스레드의 갱신과 중복될 수 있으나 락으로 내부 보호됨)
        with self._cache_lock:
            if now - self._cache_timestamp > 2:
                self._refresh_container_cache_locked()
                self._cache_timestamp = now
            result = self._lookup_cache_locked(container_id)
            if result:
                return result

        logger.debug("Container %s not found in any pod", container_id)
        return {}

    def _lookup_cache_locked(self, container_id: str) -> dict:
        """
        캐시에서 container_id 조회. 반드시 _cache_lock 보유 상태에서 호출.
        12자 prefix 매칭 지원 (Falco short ID 대응).
        """
        for cached_id, info in self._container_cache.items():
            if cached_id.startswith(container_id) or container_id.startswith(cached_id):
                return info
        return {}

    def _refresh_container_cache_locked(self):
        """
        전체 Pod 목록을 조회해 container_id → pod 매핑 캐시 재구성.
        반드시 _cache_lock 보유 상태에서 호출.
        """
        self._refresh_container_cache()

    def _refresh_container_cache(self):
        """
        Fetch all pods and build container_id → pod mapping.
        [MEDIUM #9] 새 캐시를 로컬에 빌드한 뒤 한 번에 교체하여
        부분 갱신 중 다른 스레드가 불완전한 캐시를 읽는 것을 방지.
        """
        url = f"{self.api_server}/api/v1/pods"
        result = self._request("GET", url, timeout=10)
        if not result or "items" not in result:
            return

        new_cache = {}
        for pod in result["items"]:
            metadata = pod.get("metadata", {})
            ns = metadata.get("namespace", "")
            pod_name = metadata.get("name", "")
            labels = metadata.get("labels", {})
            status = pod.get("status", {})

            # containerStatuses has the container IDs
            for cs in status.get("containerStatuses", []):
                cid = cs.get("containerID", "")
                # Format: "containerd://abc123..." or "docker://abc123..."
                if "://" in cid:
                    cid = cid.split("://", 1)[1]
                if cid:
                    new_cache[cid] = {
                        "namespace": ns,
                        "pod_name": pod_name,
                        "labels": labels,
                        "container_name": cs.get("name", ""),
                        "image": cs.get("image", ""),
                    }

            # Also check initContainerStatuses
            for cs in status.get("initContainerStatuses", []):
                cid = cs.get("containerID", "")
                if "://" in cid:
                    cid = cid.split("://", 1)[1]
                if cid:
                    new_cache[cid] = {
                        "namespace": ns,
                        "pod_name": pod_name,
                        "labels": labels,
                        "container_name": cs.get("name", ""),
                        "image": cs.get("image", ""),
                    }

        # 한 번에 교체 (atomic assignment in CPython GIL 보장)
        self._container_cache = new_cache
        logger.debug("Container cache refreshed: %d containers", len(new_cache))

    def is_in_cluster(self) -> bool:
        """Check if running inside a Kubernetes cluster."""
        try:
            with open(self.token_path):
                return True
        except FileNotFoundError:
            return False
