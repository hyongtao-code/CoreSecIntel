"""arXiv 采集器。

使用 arXiv 官方 Atom API（``export.arxiv.org/api/query``），检索通信网络、
安全、协议攻击相关预印本。API 返回 Atom XML（标准库解析，无需第三方依赖）。

arXiv 的 Atom 字段语义：

- ``published`` 是**首次提交**时间（论文真正的新鲜度依据）
- ``updated`` 是**最近修改**时间（可能是同日小修，不可当作发布时间）

两者分别写入 ``first_published_at`` 与 ``updated_at``，避免把「网页最近更新」
误判为「最近一周的新论文」。
"""

from __future__ import annotations

import logging
import re
import time
import xml.etree.ElementTree as ET
from datetime import datetime
from typing import Any, Optional

from signalintel.collectors.base import (
    BaseCollector,
    CollectorConfig,
    CollectorError,
    CollectorResult,
)
from signalintel.models import IntelItem
from signalintel.processors.deduplicate import extract_cve_ids
from signalintel.utils.dates import parse_date_string
from signalintel.utils.http import TRANSIENT_STATUS, HttpError

logger = logging.getLogger(__name__)

__all__ = ["ArxivCollector"]

API_URL = "https://export.arxiv.org/api/query"

#: arXiv 官方 API 使用条款要求：同一 IP 之间的请求间隔不少于 3 秒，
#: 否则会返回 503/429（Varnish 限流）。见
#: https://info.arxiv.org/help/api/tou.html
REQUEST_INTERVAL_SECONDS = 3.5

#: arXiv 经代理/跨网访问时首字节可能很慢（实测可达 40+ 秒），
#: 30 秒的默认超时会把限流响应误判成网络超时，因此放宽。
REQUEST_TIMEOUT_SECONDS = 120.0

#: Atom 命名空间
NS_ATOM = "{http://www.w3.org/2005/Atom}"
NS_ARXIV = "{http://arxiv.org/schemas/atom}"

#: 默认检索式：信令协议 + 安全研究
DEFAULT_QUERY = (
    '(all:"signaling" OR all:"SS7" OR all:"Diameter" OR all:"GTP" OR '
    'all:"PFCP" OR all:"SIP" OR all:"IMS" OR all:"5G core" OR '
    'all:"mobile core network") AND '
    '(all:"security" OR all:"attack" OR all:"vulnerability" OR '
    'all:"fuzzing" OR all:"privacy" OR all:"intrusion detection")'
)


class ArxivCollector(BaseCollector):
    """arXiv 预印本采集器。"""

    default_trust = 0.85
    default_source_type = "paper"
    default_content_type = "preprint"

    def __init__(self, config: CollectorConfig, http_client: Any = None) -> None:
        super().__init__(config, http_client=http_client)
        self.request_interval = float(
            self.config.params.get("request_interval", REQUEST_INTERVAL_SECONDS)
        )
        self.request_timeout = float(
            self.config.params.get("request_timeout", REQUEST_TIMEOUT_SECONDS)
        )
        #: 上次请求时间戳，用于保证请求间隔
        self._last_request_ts = 0.0

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        query = str(self.config.params.get("query") or DEFAULT_QUERY)
        max_results = int(self.config.params.get("max_results") or 50)
        page_size = min(max_results, 100)

        result = CollectorResult(source_name=self.source_name)
        errors: list[str] = []
        request_count = 0

        for offset in range(0, max_results, page_size):
            params = {
                "search_query": query,
                "start": offset,
                "max_results": page_size,
                "sortBy": "submittedDate",
                "sortOrder": "descending",
            }

            raw_text = self._fetch_page(params, offset // page_size + 1, errors)
            if raw_text is None:
                break
            request_count += 1

            entries = self._extract_entries(raw_text)
            if entries is None:
                errors.append("arXiv 返回内容不是合法 Atom XML")
                break

            for entry in entries:
                item = self._parse_entry(entry)
                if item is None:
                    continue
                self._route(item, start, end, result)

            if len(entries) < page_size:
                break

        result.errors = errors
        return result

    # ------------------------------------------------------------------

    def _fetch_page(
        self, params: dict[str, Any], page_no: int, errors: list[str]
    ) -> Optional[str]:
        """抓取一页 Atom 内容，失败时退避重试。

        arXiv 的官方使用条款要求请求间隔不少于 3 秒，否则返回 503/429；
        后端降级时还可能返回 400（且带合法响应体）。这些都属于临时故障，
        退避后重试通常可以恢复。
        """
        max_attempts = 4
        for attempt in range(1, max_attempts + 1):
            if self._last_request_ts > 0:
                elapsed = time.monotonic() - self._last_request_ts
                if elapsed < self.request_interval:
                    time.sleep(self.request_interval - elapsed)

            try:
                response = self.http.get(
                    API_URL,
                    params=params,
                    headers={"Accept": "application/atom+xml"},
                    timeout=self.request_timeout,
                    allow_error=True,
                )
                self._last_request_ts = time.monotonic()
                raw_text = response.text
                # arXiv 后端降级时可能返回 400/503，且**响应体仍是合法 Atom**。
                # 只要能解析出 entry 就直接使用，不浪费一次重试。
                if response.status_code >= 400:
                    if self._extract_entries(raw_text):
                        logger.warning(
                            "arXiv 返回 %s 但响应体含有效条目，直接采用",
                            response.status_code,
                        )
                        return raw_text
                    raise HttpError(
                        f"HTTP {response.status_code}: {API_URL}",
                        response.status_code,
                    )
                return raw_text
            except HttpError as exc:
                status = getattr(exc, "status_code", None)
                transient = status in TRANSIENT_STATUS or status in {
                    429,
                    500,
                    502,
                    503,
                    504,
                }
                if not transient or attempt == max_attempts:
                    errors.append(f"arXiv 第 {page_no} 页请求失败: {exc}")
                    return None
                wait = min(120.0, self.request_interval * (2 ** (attempt - 1)) * 3)
                logger.warning(
                    "arXiv 返回 %s（第 %s/%s 次），退避 %.1fs 后重试第 %s 页",
                    status,
                    attempt,
                    max_attempts,
                    wait,
                    page_no,
                )
                time.sleep(wait)
        return None

    # ------------------------------------------------------------------

    @staticmethod
    def _extract_entries(raw_text: str) -> Optional[list[ET.Element]]:
        """从 Atom XML 中提取 entry 节点列表。"""
        try:
            root = ET.fromstring(raw_text.strip())
        except ET.ParseError:
            return None
        entries = root.findall(f"{NS_ATOM}entry")
        if entries:
            return list(entries)
        # 容错：无命名空间的 feed
        return [node for node in root if node.tag.split("}")[-1] == "entry"]

    def _parse_entry(self, entry: ET.Element) -> Optional[IntelItem]:
        """解析单个 Atom entry。"""
        title = _clean(self._text(entry, "title"))
        if not title:
            return None

        arxiv_id = self._text(entry, "id").strip()
        url = arxiv_id if arxiv_id.startswith("http") else f"https://arxiv.org/abs/{arxiv_id}"

        # 优先取 rel=alternate 的 link
        for link in entry.findall(f"{NS_ATOM}link"):
            if link.attrib.get("rel") == "alternate" and link.attrib.get("href"):
                url = link.attrib["href"]
                break

        published = parse_date_string(self._text(entry, "published"))
        updated = parse_date_string(self._text(entry, "updated"))

        authors: list[str] = []
        for author in entry.findall(f"{NS_ATOM}author"):
            name = _clean(self._text(author, "name"))
            if name:
                authors.append(name)

        abstract = _clean(self._text(entry, "summary"))

        doi_node = entry.find(f"{NS_ARXIV}doi")
        doi = doi_node.text.strip() if doi_node is not None and doi_node.text else None

        # 期刊引用信息（若已被正式发表）
        journal_ref = self._text(entry, "journal_ref").strip()

        return self._base_item(
            title=title,
            url=url,
            abstract=abstract,
            authors=authors,
            content_type="preprint",
            is_preprint=True,
            first_published_at=published,
            published_at=published,
            updated_at=updated,
            doi=doi,
            cve_ids=extract_cve_ids(f"{title} {abstract}"),
            raw={"arxiv_id": arxiv_id, "journal_ref": journal_ref},
        )

    @staticmethod
    def _text(node: ET.Element, name: str) -> str:
        """读取子节点文本（兼容有无命名空间）。"""
        for child in node:
            if child.tag.split("}")[-1] == name:
                return child.text or ""
        return ""


def _clean(text: Optional[str]) -> str:
    """压缩空白。"""
    if not text:
        return ""
    return re.sub(r"\s+", " ", str(text)).strip()
