"""RSS / Atom 采集器。

支持 RSS 2.0、RSS 1.0 (RDF) 与 Atom 三种格式，无需第三方依赖，
使用标准库 ``xml.etree.ElementTree`` 解析。

时间字段：RSS 用 ``pubDate``（RFC-822），Atom 用 ``published`` / ``updated``。
Atom 中 ``updated`` 仅作为网页更新时间记录，不参与时间窗口判定。
"""

from __future__ import annotations

import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from html import unescape
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
from signalintel.utils.http import HttpError

logger = logging.getLogger(__name__)

__all__ = ["RssCollector"]

#: 常见命名空间
NS_ATOM = "{http://www.w3.org/2005/Atom}"
NS_CONTENT = "{http://purl.org/rss/1.0/modules/content/}"
NS_DC = "{http://purl.org/dc/elements/1.1/}"

#: HTML 标签
_HTML_TAG_RE = re.compile(r"<[^>]+>")

#: 允许在摘要中保留的换行结构
_BLOCK_END_RE = re.compile(r"</(p|div|li|tr|h[1-6]|br)\s*/?>", re.IGNORECASE)


class RssCollector(BaseCollector):
    """RSS / Atom 订阅源采集器。"""

    default_trust = 0.7
    default_source_type = "news"
    default_content_type = "news"

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        url = self.config.url
        if not url:
            raise CollectorError(f"来源 {self.source_name} 未配置 URL")

        try:
            raw_text = self.http.get_text(url)
        except HttpError as exc:
            raise CollectorError(f"来源 {self.source_name} 请求失败: {exc}") from exc

        entries = self._parse_feed(raw_text)
        if entries is None:
            raise CollectorError(f"来源 {self.source_name} 的 XML 解析失败")

        result = CollectorResult(source_name=self.source_name)
        for entry in entries:
            item = self._parse_entry(entry)
            if item is None:
                continue
            self._route(item, start, end, result)

        return result

    # ------------------------------------------------------------------

    def _parse_feed(self, raw_text: str) -> Optional[list[dict[str, Any]]]:
        """解析 feed，返回统一的 entry 字典列表。"""
        try:
            root = ET.fromstring(raw_text.strip())
        except ET.ParseError:
            return None

        tag = root.tag.split("}")[-1].lower()

        if tag == "feed":  # Atom
            return [self._atom_entry(node) for node in root.findall(f"{NS_ATOM}entry")]

        if tag == "rss":
            channel = root.find("channel")
            if channel is None:
                return []
            return [self._rss_item(node) for node in channel.findall("item")]

        if tag == "rdf":  # RSS 1.0
            items = root.findall(f"{NS_CONTENT}item") or root.findall("item")
            return [self._rss_item(node) for node in items]

        # 兜底：直接找 item / entry
        entries = root.iter()
        found = [
            node
            for node in entries
            if node.tag.split("}")[-1].lower() in {"item", "entry"}
        ]
        return [self._rss_item(node) for node in found]

    @staticmethod
    def _text(node: ET.Element, *names: str) -> str:
        """按顺序查找子节点文本（兼容命名空间）。"""
        for name in names:
            for child in node:
                if child.tag.split("}")[-1].lower() == name.lower():
                    if child.text:
                        return child.text
                    # Atom link 使用 href 属性
                    href = child.attrib.get("href")
                    if href:
                        return href
        return ""

    def _rss_item(self, node: ET.Element) -> dict[str, Any]:
        """RSS item → 统一字典。"""
        return {
            "title": self._text(node, "title"),
            "url": self._text(node, "link", "guid"),
            "description": self._text(node, "description", "encoded", "summary"),
            "published": self._text(node, "pubDate", "date", "published"),
            "updated": self._text(node, "lastBuildDate", "updated", "modified"),
            "author": self._text(node, "author", "creator"),
        }

    def _atom_entry(self, node: ET.Element) -> dict[str, Any]:
        """Atom entry → 统一字典。"""
        link = ""
        for child in node:
            if child.tag.split("}")[-1].lower() == "link":
                rel = child.attrib.get("rel", "alternate")
                if rel == "alternate":
                    link = child.attrib.get("href", "")
                    break
        if not link:
            link = self._text(node, "link", "id")

        return {
            "title": self._text(node, "title"),
            "url": link,
            "description": self._text(node, "summary", "content", "description"),
            "published": self._text(node, "published", "issued"),
            "updated": self._text(node, "updated", "modified"),
            "author": self._text(node, "author", "creator"),
        }

    def _parse_entry(self, entry: dict[str, Any]) -> Optional[IntelItem]:
        title = _clean_html(entry.get("title", ""))
        if not title:
            return None

        url = (entry.get("url") or "").strip()
        abstract = _clean_html(entry.get("description", ""))
        published = parse_date_string(entry.get("published"))
        updated = parse_date_string(entry.get("updated"))

        authors: list[str] = []
        author = _clean_html(entry.get("author", ""))
        if author:
            authors.append(author)

        return self._base_item(
            title=title,
            url=url,
            abstract=abstract,
            authors=authors,
            content_type="news",
            cve_ids=extract_cve_ids(f"{title} {abstract}"),
            published_at=published,
            first_published_at=published,
            updated_at=updated,
        )


def _clean_html(text: Optional[str]) -> str:
    """去除 HTML 标签并反转义实体，压缩空白。"""
    if not text:
        return ""
    content = str(text)
    content = _BLOCK_END_RE.sub("\n", content)
    content = _HTML_TAG_RE.sub(" ", content)
    content = unescape(content)
    content = re.sub(r"[ \t\r\f\v]+", " ", content)
    content = re.sub(r"\n\s*\n+", "\n", content)
    return content.strip()
