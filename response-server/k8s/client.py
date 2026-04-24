"""
Minimal Kubernetes API client using service account credentials.

No external dependencies — uses urllib from stdlib.
Handles:
- NetworkPolicy create / list / delete (auto-isolation)
- Pod label lookup (for NetworkPolicy targeting)
"""

import json
import logging
import ssl
import time
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


class KubeClient:
    """Kubernetes API client using in-cluster service account."""

    def __init__(self):
        self.api_server = "https://kubernetes.default.svc"
        self.token_path = "/var/run/secrets/kubernetes.io/serviceaccount/token"
        self.ca_path = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
        self._token: Optional[str] = None
        self._ssl_ctx: Optional[ssl.SSLContext] = None

    # ─── Internal Helpers ─────────────────────────────────

    def _get_token(self) -> str:
        if self._token is None:
            try:
                with open(self.token_path) as f:
                    self._token = f.read().strip()
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
                f"서비스 어카운트 CA 인증서를 찾을 수 없습니다: {self.ca_path}. "
                "클러스터 내부에서 실행 중인지 확인하세요."
            )
        except ssl.SSLError as e:
            raise RuntimeError(
                f"CA 인증서 로딩 실패: {e}. "
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
            error_body = e.read().decode("utf-8", errors="replace")
            logger.error("K8s API %s %s → %d: %s", method, url, e.code, error_body[:500])
            return None
        except Exception as e:
            logger.error("K8s API %s %s → error: %s", method, url, e)
            return None

    # ─── Pod Operations ───────────────────────────────────

    def get_pod_labels(self, namespace: str, pod_name: str) -> dict:
        """Fetch pod labels. Returns empty dict on failure."""
        if not namespace or not pod_name:
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

        Uses a cache to avoid hammering the API on every event.
        """
        if not container_id or container_id in ("host", "<NA>"):
            return {}

        # Check cache first
        if not hasattr(self, '_container_cache'):
            self._container_cache = {}       # container_id -> {ns, pod, labels}
            self._cache_timestamp = 0

        # Refresh cache every 30 seconds
        now = time.time()
        if now - self._cache_timestamp > 30:
            self._refresh_container_cache()
            self._cache_timestamp = now

        # Short container IDs: Falco often gives 12-char prefix
        for cached_id, info in self._container_cache.items():
            if cached_id.startswith(container_id) or container_id.startswith(cached_id):
                return info

        # Cache miss — force refresh once
        if now - self._cache_timestamp > 2:
            self._refresh_container_cache()
            self._cache_timestamp = now
            for cached_id, info in self._container_cache.items():
                if cached_id.startswith(container_id) or container_id.startswith(cached_id):
                    return info

        logger.debug("Container %s not found in any pod", container_id)
        return {}

    def _refresh_container_cache(self):
        """Fetch all pods and build container_id → pod mapping."""
        url = f"{self.api_server}/api/v1/pods"
        result = self._request("GET", url, timeout=10)
        if not result or "items" not in result:
            return

        cache = {}
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
                    cache[cid] = {
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
                    cache[cid] = {
                        "namespace": ns,
                        "pod_name": pod_name,
                        "labels": labels,
                        "container_name": cs.get("name", ""),
                        "image": cs.get("image", ""),
                    }

        self._container_cache = cache
        logger.debug("Container cache refreshed: %d containers", len(cache))

    def is_in_cluster(self) -> bool:
        """Check if running inside a Kubernetes cluster."""
        try:
            with open(self.token_path):
                return True
        except FileNotFoundError:
            return False
