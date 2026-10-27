"""Semantic Scholar 采集器。

使用 Semantic Scholar Graph API 检索论文、摘要、作者与相关研究。
官方文档建议在请求头中带上 ``x-api-key``（免费密钥，可选）。
"""

from __future__ import annotations

import logging
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

__all__ = ["SemanticScholarCollector"]

API_URL = "https://api.semanticscholar.org/graph/v1/paper/search"

#: 默认检索式
DEFAULT_QUERY = (
    "signaling security core network Diameter GTP-C SS7 SIP 5G core "
    "vulnerability attack fuzzing privacy roaming"
)

#: publicationTypes 到内容类型的映射
_TYPE_MAP = {
    "JournalArticle": "paper",
    "Conference": "paper",
    "ConferencePaper": "paper",
    "Book": "paper",
    "BookSection": "paper",
    "Review": "paper",
    "Study": "paper",
    "Preprint": "preprint",
    "Report": "report",
    "TechReport": "report",
    "Patent": "other",
    "Dataset": "dataset",
}


class SemanticScholarCollector(BaseCollector):
    """Semantic Scholar 论文采集器。"""

    default_trust = 0.85
    default_source_type = "paper"
    default_content_type = "paper"

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        query = str(self.config.params.get("query") or DEFAULT_QUERY)
        limit = int(self.config.params.get("limit") or 50)
        max_items = int(self.config.params.get("max_items") or 100)
        page_size = min(100, limit)

        headers: dict[str, str] = {}
        if self.config.api_key:
            headers["x-api-key"] = self.config.api_key

        result = CollectorResult(source_name=self.source_name)
        errors: list[str] = []
        offset = 0

        while len(result.items) < max_items:
            params = {
                "query": query,
                "limit": page_size,
                "offset": offset,
                "fields": (
                    "title,abstract,authors,year,publicationDate,externalIds,"
                    "url,venue,publicationTypes,openAccessPdf"
                ),
            }
            try:
                payload = self.http.get_json(API_URL, params=params, headers=headers)
            except HttpError as exc:
                errors.append(f"Semantic Scholar 第 {offset // page_size + 1} 页请求失败: {exc}")
                break

            data = payload.get("data", []) if isinstance(payload, dict) else []
            if not data:
                break

            for raw in data:
                if len(result.items) >= max_items:
                    break
                item = self._parse_item(raw)
                if item is None:
                    continue
                self._route(item, start, end, result)

            if len(data) < page_size:
                break
            offset += page_size

        result.errors = errors
        return result

    # ------------------------------------------------------------------

    def _parse_item(self, raw: dict[str, Any]) -> Optional[IntelItem]:
        title = _clean(raw.get("title"))
        if not title:
            return None

        published = parse_date_string(raw.get("publicationDate"))
        if published is None and raw.get("year"):
            try:
                published = datetime(int(raw["year"]), 1, 1).astimezone()
            except (TypeError, ValueError):
                published = None

        authors: list[str] = []
        for author in raw.get("authors") or []:
            if isinstance(author, dict) and author.get("name"):
                authors.append(_clean(author["name"]))

        external = raw.get("externalIds") or {}
        doi = normalize_doi(external.get("DOI")) if isinstance(external, dict) else None
        arxiv_id = external.get("ArXiv") if isinstance(external, dict) else None

        types = raw.get("publicationTypes") or []
        content_type = "paper"
        for candidate in types:
            mapped = _TYPE_MAP.get(str(candidate))
            if mapped:
                content_type = mapped
                break

        url = raw.get("url") or ""
        if not url and arxiv_id:
            url = f"https://arxiv.org/abs/{arxiv_id}"

        abstract = _clean(raw.get("abstract"))

        return self._base_item(
            title=title,
            url=url,
            abstract=abstract,
            authors=authors,
            content_type=content_type,
            is_preprint=content_type == "preprint",
            doi=doi,
            cve_ids=extract_cve_ids(f"{title} {abstract}"),
            published_at=published,
            first_published_at=published,
            raw={"arxiv_id": arxiv_id, "venue": raw.get("venue")},
        )


def _clean(text: Optional[str]) -> str:
    return re.sub(r"\s+", " ", str(text)).strip() if text else ""
