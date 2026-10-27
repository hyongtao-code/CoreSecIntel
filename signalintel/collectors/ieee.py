"""IEEE Xplore 采集器。

需要申请 API Key（免费注册，见 https://ieeexploreapi.ieee.org/），
通过环境变量 ``IEEE_API_KEY`` 或 ``config/sources.yaml`` 中的 ``api_key_env``
配置。未配置 Key 时该来源自动跳过，不影响其它来源。

**只取元数据，不取全文。**

本采集器只调用官方公开检索接口 ``ieeexploreapi.ieee.org/api/v1/search/articles``，
拿到的仅是题录信息：标题、摘要、作者、DOI、出版日期、会议/期刊名、文档链接。

不做的事：

- 不登录 IEEE Xplore，不携带任何会话 Cookie；
- 不请求 ``documentLink`` 指向的全文页面，不下载 PDF；
- 不尝试绕过 IEEE 的访问控制或付费墙。

IEEE 的全文多数需要订阅，登录后也无法免费获取，因此**采集到的摘要即摘要**——
报告里明确标注「未提及全文」类字段，保持与原文可追溯且不越界。

IEEE 返回的 ``publicationDate`` 是正式出版日期；``doi`` 用于跨来源去重。
"""

from __future__ import annotations

import logging
import os
import re
from datetime import datetime
from typing import Any, Optional

from signalintel.collectors.base import (
    BaseCollector,
    CollectorConfig,
    CollectorResult,
)
from signalintel.models import IntelItem
from signalintel.processors.deduplicate import extract_cve_ids, normalize_doi
from signalintel.utils.dates import parse_date_string
from signalintel.utils.http import HttpError

logger = logging.getLogger(__name__)

__all__ = ["IeeeCollector"]

API_URL = "https://ieeexploreapi.ieee.org/api/v1/search/articles"

#: 默认检索式
DEFAULT_QUERY = (
    '("signaling security" OR "core network security" OR "SS7" OR "Diameter" '
    'OR "GTP-C" OR "PFCP" OR "SIP" OR "5G core") AND '
    '("vulnerability" OR "attack" OR "fuzzing" OR "intrusion detection" OR "privacy")'
)


class IeeeCollector(BaseCollector):
    """IEEE Xplore 论文采集器。"""

    default_trust = 0.92
    default_source_type = "paper"
    default_content_type = "paper"

    def __init__(self, config: CollectorConfig, http_client: Any = None) -> None:
        super().__init__(config, http_client=http_client)
        # api_key 优先取配置，其次取环境变量
        env_name = str(config.params.get("api_key_env") or "IEEE_API_KEY")
        self._api_key = config.api_key or os.environ.get(env_name)

    @property
    def available(self) -> bool:
        return bool(self._api_key)

    def unavailable_reason(self) -> str:
        env_name = str(self.config.params.get("api_key_env") or "IEEE_API_KEY")
        return f"未配置 IEEE API Key（请设置环境变量 {env_name}）"

    # ------------------------------------------------------------------

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        query = str(self.config.params.get("query") or DEFAULT_QUERY)
        max_items = int(self.config.params.get("max_items") or 50)
        page_size = min(100, max_items)

        headers = {
            "Accept": "application/json",
            "X-Api-Key": self._api_key or "",
        }

        result = CollectorResult(source_name=self.source_name)
        errors: list[str] = []
        start_index = 1

        while len(result.items) < max_items:
            params = {
                "querytext": query,
                "start_record": start_index,
                "max_records": page_size,
                "sort": "publication_date",
                "sort_order": "desc",
            }
            try:
                payload = self.http.get_json(API_URL, params=params, headers=headers)
            except HttpError as exc:
                errors.append(f"IEEE Xplore 请求失败: {exc}")
                break

            documents = self._extract_documents(payload)
            if not documents:
                break

            for raw in documents:
                if len(result.items) >= max_items:
                    break
                item = self._parse_document(raw)
                if item is None:
                    continue
                self._route(item, start, end, result)

            if len(documents) < page_size:
                break
            start_index += page_size

        result.errors = errors
        return result

    # ------------------------------------------------------------------

    @staticmethod
    def _extract_documents(payload: Any) -> list[dict[str, Any]]:
        if not isinstance(payload, dict):
            return []
        response = payload.get("response", {})
        if not isinstance(response, dict):
            return []
        documents = response.get("documents", [])
        return list(documents) if isinstance(documents, list) else []

    def _parse_document(self, raw: dict[str, Any]) -> Optional[IntelItem]:
        title = _clean(raw.get("title"))
        if not title:
            return None

        published = parse_date_string(raw.get("publicationDate"))
        authors: list[str] = []
        for author in raw.get("authors") or []:
            if isinstance(author, dict):
                name = _clean(author.get("authorName"))
                if name:
                    authors.append(name)
            elif isinstance(author, str) and author.strip():
                authors.append(_clean(author))

        doi = normalize_doi(raw.get("doi"))
        # 只使用 API 返回的摘要；不请求 documentLink 指向的全文
        abstract = _clean(raw.get("abstract"))
        # 优先给 DOI 解析页（公开、稳定），其次才是 documentLink
        url = f"https://doi.org/{doi}" if doi else (raw.get("documentLink") or "")
        content_type = "paper"

        return self._base_item(
            title=title,
            url=url,
            abstract=abstract,
            authors=authors,
            content_type=content_type,
            doi=doi,
            cve_ids=extract_cve_ids(f"{title} {abstract}"),
            published_at=published,
            first_published_at=published,
            raw={
                "publication_title": raw.get("publicationTitle"),
                "content_type": raw.get("contentType"),
                "is_open_access": raw.get("isOpenAccess"),
            },
        )


def _clean(text: Optional[str]) -> str:
    return re.sub(r"\s+", " ", str(text)).strip() if text else ""
