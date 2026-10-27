"""Crossref REST API 采集器。

Crossref 是 DOI 元数据的权威来源，用于补充论文的 DOI、出版日期、作者与
期刊信息。它按 ``from-pub-date`` / ``until-pub-date`` 做时间范围过滤，
与其它来源的时间窗口保持一致。
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

__all__ = ["CrossrefCollector"]

API_URL = "https://api.crossref.org/works"

#: 默认检索式
DEFAULT_QUERY = (
    "signaling security telecom core network diameter GTP-C SS7 SIP "
    "5G core vulnerability attack fuzzing roaming"
)

#: JATS / XML 标签
_TAG_RE = re.compile(r"<[^>]+>")

#: Crossref 出版类型到本系统内容类型的映射
_TYPE_MAP = {
    "journal-article": "paper",
    "proceedings-article": "paper",
    "posted-content": "preprint",
    "book-chapter": "paper",
    "book": "report",
    "report": "report",
    "reference-entry": "reference",
    "dataset": "dataset",
    "component": "other",
    "dissertation": "paper",
    "standard": "standard",
    "other": "other",
}


class CrossrefCollector(BaseCollector):
    """Crossref 论文元数据采集器。"""

    default_trust = 0.9
    default_source_type = "paper"
    default_content_type = "paper"

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        query = str(self.config.params.get("query") or DEFAULT_QUERY)
        rows = int(self.config.params.get("rows") or 50)
        max_items = int(self.config.params.get("max_items") or 100)

        params = {
            "query.bibliographic": query,
            "filter": (
                f"from-pub-date:{start.strftime('%Y-%m-%d')},"
                f"until-pub-date:{end.strftime('%Y-%m-%d')}"
            ),
            "rows": rows,
            "sort": "published",
            "order": "desc",
            "select": (
                "DOI,title,abstract,author,published,issued,created,"
                "URL,publisher,type,container-title,subject"
            ),
            "mailto": str(self.config.params.get("mailto") or ""),
        }
        params = {key: value for key, value in params.items() if value != ""}

        result = CollectorResult(source_name=self.source_name)
        errors: list[str] = []

        try:
            payload = self.http.get_json(API_URL, params=params)
        except HttpError as exc:
            errors.append(f"Crossref 请求失败: {exc}")
            result.errors = errors
            return result

        message = payload.get("message", {}) if isinstance(payload, dict) else {}
        raw_items = message.get("items", []) if isinstance(message, dict) else []

        for raw in raw_items or []:
            if len(result.items) >= max_items:
                break
            item = self._parse_item(raw)
            if item is None:
                continue
            self._route(item, start, end, result)

        result.errors = errors
        return result

    # ------------------------------------------------------------------

    def _parse_item(self, raw: dict[str, Any]) -> Optional[IntelItem]:
        """解析 Crossref 条目。"""
        doi = normalize_doi(raw.get("DOI"))
        titles = raw.get("title") or []
        title = _clean(titles[0]) if isinstance(titles, list) and titles else ""
        if not title and not doi:
            return None

        published = self._extract_date(raw, "published") or self._extract_date(raw, "issued")
        first_published = self._extract_date(raw, "created") or published

        authors: list[str] = []
        for author in raw.get("author") or []:
            if not isinstance(author, dict):
                continue
            name = _clean(
                " ".join(
                    part for part in (author.get("given"), author.get("family")) if part
                )
            )
            if name:
                authors.append(name)

        url = raw.get("URL") or (f"https://doi.org/{doi}" if doi else "")
        abstract = _clean(_strip_tags(raw.get("abstract")))
        cr_type = str(raw.get("type") or "").lower()
        content_type = _TYPE_MAP.get(cr_type, "paper")
        is_preprint = content_type == "preprint"

        return self._base_item(
            title=title,
            url=url,
            abstract=abstract,
            authors=authors,
            content_type=content_type,
            is_preprint=is_preprint,
            doi=doi,
            cve_ids=extract_cve_ids(f"{title} {abstract}"),
            published_at=published,
            first_published_at=first_published,
            raw={"publisher": raw.get("publisher"), "type": cr_type},
        )

    @staticmethod
    def _extract_date(raw: dict[str, Any], key: str) -> Optional[datetime]:
        """从 ``{"date-parts": [[y, m, d]]}`` 结构中提取日期。"""
        node = raw.get(key)
        if not isinstance(node, dict):
            return None
        parts = node.get("date-parts")
        if not isinstance(parts, list) or not parts:
            return None
        first = parts[0]
        if not isinstance(first, list) or not first:
            return None
        try:
            year = int(first[0])
            month = int(first[1]) if len(first) > 1 else 1
            day = int(first[2]) if len(first) > 2 else 1
        except (TypeError, ValueError):
            return None
        try:
            return datetime(year, month, day).astimezone()
        except ValueError:
            return None


def _clean(text: Optional[str]) -> str:
    return re.sub(r"\s+", " ", str(text)).strip() if text else ""


def _strip_tags(text: Optional[str]) -> str:
    """去掉 JATS/XML 标签，保留纯文本。"""
    if not text:
        return ""
    without_tags = _TAG_RE.sub(" ", str(text))
    return re.sub(r"\s+", " ", without_tags).strip()
