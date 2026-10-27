"""带重试、退避与限流的 HTTP 客户端。

所有采集器共用本模块，统一处理超时、429/5xx 重试、指数退避与
User-Agent 声明（遵守站点使用条款）。

**访问原则（硬约束）**

- 只访问公开、无需登录即可获取的内容。
- 不发送 Cookie、不做会话持久化、不携带任何内容站点的认证凭证。
- 不绕过付费墙、登录验证或任何访问控制。
- IEEE Xplore 只使用官方公开 API 获取**元数据**（标题 / 摘要 / 作者 /
  DOI / 出版日期），不抓取全文；arXiv 使用官方 Atom API，其预印本本就
  公开免费。
- 唯一使用凭证的地方是 LLM API 与 SMTP 发信，二者与内容采集无关。
"""

from __future__ import annotations

import logging
import random
import time
from typing import Any, Mapping, Optional

import requests

logger = logging.getLogger(__name__)

__all__ = ["HttpClient", "HttpError", "DEFAULT_USER_AGENT"]

DEFAULT_USER_AGENT = (
    "SignalIntelBot/1.0 (+https://example.org/signalintel; "
    "core-network signaling security research digest)"
)

#: 触发重试的 HTTP 状态码
RETRYABLE_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

#: 命中这些状态码说明是服务端限流（而非瞬时故障），退避时间要更长
RATE_LIMIT_STATUS = frozenset({429, 503})

#: 部分服务（如 arXiv）在后端降级时会返回 400 且**携带合法响应体**，
#: 这属于临时故障而非请求参数错误，需要重试。
TRANSIENT_STATUS = frozenset({400})


class HttpError(RuntimeError):
    """HTTP 请求失败（重试耗尽后抛出）。"""

    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class HttpClient:
    """带重试与限流的 HTTP 客户端。

    :param base_delay: 首次退避秒数
    :param max_delay: 退避上限秒数
    :param jitter: 是否加入随机抖动（避免多实例同步重试）
    """

    def __init__(
        self,
        timeout: float = 30.0,
        max_retries: int = 3,
        base_delay: float = 1.0,
        max_delay: float = 30.0,
        user_agent: str = DEFAULT_USER_AGENT,
        min_interval: float = 0.0,
        jitter: bool = True,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.base_delay = base_delay
        self.max_delay = max_delay
        self.user_agent = user_agent
        self.min_interval = min_interval
        self.jitter = jitter
        self.session = session or requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        # 明确禁用 Cookie 持久化：本系统只访问公开内容，不做任何登录，
        # 不携带任何会话凭证，避免越过访问控制或触发付费墙。
        self.session.cookies.clear()
        self.session.auth = None
        self._last_request_ts = 0.0

    # ------------------------------------------------------------------

    def _throttle(self) -> None:
        """保证两次请求之间的最小间隔。"""
        if self.min_interval <= 0:
            return
        elapsed = time.monotonic() - self._last_request_ts
        if elapsed < self.min_interval:
            time.sleep(self.min_interval - elapsed)

    def _backoff(self, attempt: int, rate_limited: bool = False) -> float:
        """指数退避。命中限流时退避时间加倍。

        arXiv 等服务在限流时会返回 503（Varnish），普通的 1s/2s 退避
        不够，需要更长的等待。
        """
        delay = min(self.max_delay, self.base_delay * (2 ** (attempt - 1)))
        if rate_limited:
            delay = min(self.max_delay, delay * 3)
        else:
            # 连接层错误（TLS 抖动等）退避可短一些，但要保留抖动避免同步重试
            delay = min(self.max_delay, delay)
        if self.jitter:
            delay += random.uniform(0, delay * 0.25)
        return delay

    # ------------------------------------------------------------------

    def get(
        self,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
        allow_error: bool = False,
    ) -> requests.Response:
        """执行 GET 请求，失败时按指数退避重试。

        :param allow_error: 为 ``True`` 时，4xx（不可重试状态码）也返回响应对象
            而不抛异常。某些服务（如 arXiv）会在错误状态码下返回**合法响应体**，
            调用方需要自行检查内容。
        """
        try:
            return self.request(
                "GET", url, params=params, headers=headers, timeout=timeout
            )
        except HttpError:
            if not allow_error:
                raise
            response = self.session.get(
                url,
                params=params,
                headers=headers,
                timeout=timeout if timeout is not None else self.timeout,
            )
            self._last_request_ts = time.monotonic()
            return response

    def post(
        self,
        url: str,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        """执行 POST 请求。"""
        return self.request(
            "POST", url, json=json, data=data, headers=headers, timeout=timeout
        )

    def request(
        self,
        method: str,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        json: Optional[Any] = None,
        data: Optional[Any] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> requests.Response:
        """执行 HTTP 请求并处理重试。

        重试触发条件：连接异常、超时、可重试状态码（408/425/429/5xx）。
        4xx（除 429）不重试，直接抛出。
        """
        effective_timeout = timeout if timeout is not None else self.timeout
        last_error: Optional[str] = None
        rate_limited = False

        for attempt in range(1, self.max_retries + 1):
            self._throttle()
            try:
                response = self.session.request(
                    method,
                    url,
                    params=params,
                    json=json,
                    data=data,
                    headers=headers,
                    timeout=effective_timeout,
                )
            except requests.RequestException as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                rate_limited = False
                logger.warning(
                    "请求异常 (%s/%s) %s: %s", attempt, self.max_retries, url, last_error
                )
            else:
                if response.status_code < 400:
                    self._last_request_ts = time.monotonic()
                    return response
                if response.status_code not in RETRYABLE_STATUS:
                    self._last_request_ts = time.monotonic()
                    # 记录响应体前 200 字符，便于定位 API 参数错误
                    body_snippet = ""
                    try:
                        body_snippet = response.text[:200].replace("\n", " ")
                    except Exception:  # noqa: BLE001
                        pass
                    raise HttpError(
                        f"HTTP {response.status_code}: {url} | {body_snippet}",
                        response.status_code,
                    )
                last_error = f"HTTP {response.status_code}"
                rate_limited = response.status_code in RATE_LIMIT_STATUS
                logger.warning(
                    "可重试状态码 (%s/%s) %s: %s%s",
                    attempt,
                    self.max_retries,
                    url,
                    response.status_code,
                    "（疑似限流）" if rate_limited else "",
                )
                retry_after = response.headers.get("Retry-After")
                if retry_after:
                    try:
                        wait = float(retry_after)
                        # Retry-After: 0 表示「立即重试」，对限流场景反而有害，
                        # 至少等待一个退避周期
                        if wait <= 0:
                            wait = self._backoff(attempt, rate_limited)
                        else:
                            wait = min(self.max_delay, wait)
                        logger.info("按 Retry-After 等待 %.1fs 后重试 %s", wait, url)
                        time.sleep(wait)
                        self._last_request_ts = time.monotonic()
                        continue
                    except ValueError:
                        pass

            if attempt < self.max_retries:
                delay = self._backoff(attempt, rate_limited)
                logger.info("退避 %.1fs 后重试 %s", delay, url)
                time.sleep(delay)

        self._last_request_ts = time.monotonic()
        raise HttpError(f"重试 {self.max_retries} 次后仍失败: {url} ({last_error})")

    def get_json(
        self,
        url: str,
        params: Optional[Mapping[str, Any]] = None,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> Any:
        """GET 并解析 JSON。"""
        response = self.get(url, params=params, headers=headers, timeout=timeout)
        try:
            return response.json()
        except ValueError as exc:
            raise HttpError(f"响应不是合法 JSON: {url}") from exc

    def get_text(
        self,
        url: str,
        headers: Optional[Mapping[str, str]] = None,
        timeout: Optional[float] = None,
    ) -> str:
        """GET 并返回文本。"""
        response = self.get(url, headers=headers, timeout=timeout)
        response.encoding = response.encoding or "utf-8"
        return response.text

    def close(self) -> None:
        try:
            self.session.close()
        except Exception:  # noqa: BLE001
            pass
