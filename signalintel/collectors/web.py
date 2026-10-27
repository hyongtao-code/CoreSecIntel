"""通用网页采集器。

用于没有 API / RSS 的来源（部分安全厂商公告、3GPP / ITU-T 更新等）。

约束与实现要点：

- 遵守 ``robots.txt``（可配置关闭，但默认开启）。
- 遵守访问频率限制（``min_interval``）。
- 解析配置指定的 CSS 选择器提取标题、正文与发布时间。
- **无法获取可靠发布时间时**，条目的 ``published_at`` 保持 ``None``，
  由上层标记为「发布时间待核实」并默认排除在主报告之外。
- 不执行网页中的任何脚本，不绕过付费墙或登录验证。
"""

from __future__ import annotations

import logging
import re
import urllib.robotparser
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
from signalintel.utils.http import DEFAULT_USER_AGENT, HttpError

logger = logging.getLogger(__name__)

__all__ = ["WebCollector"]

try:
    from bs4 import BeautifulSoup
except ImportError:  # pragma: no cover
    BeautifulSoup = None  # type: ignore[assignment]


class WebCollector(BaseCollector):
    """通用网页采集器（支持 CSS 选择器）。"""

    default_trust = 0.55
    default_source_type = "news"
    default_content_type = "news"

    def __init__(
        self,
        config: CollectorConfig,
        http_client: Any = None,
        respect_robots: bool = True,
        user_agent: str = DEFAULT_USER_AGENT,
    ) -> None:
        super().__init__(config, http_client=http_client)
        self.respect_robots = respect_robots
        self.user_agent = user_agent
        self._robots_cache: dict[str, Optional[urllib.robotparser.RobotFileParser]] = {}

    # ------------------------------------------------------------------

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        if BeautifulSoup is None:
            raise CollectorError("缺少 bs4 依赖，无法使用网页采集器")

        url = self.config.url
        if not url:
            raise CollectorError(f"来源 {self.source_name} 未配置 URL")

        if self.respect_robots and not self._robots_allowed(url):
            raise CollectorError(f"来源 {self.source_name} 被 robots.txt 禁止抓取")

        try:
            raw_html = self.http.get_text(url)
        except HttpError as exc:
            raise CollectorError(f"来源 {self.source_name} 请求失败: {exc}") from exc

        try:
            soup = BeautifulSoup(raw_html, "html.parser")
        except Exception as exc:  # noqa: BLE001
            raise CollectorError(f"来源 {self.source_name} HTML 解析失败: {exc}") from exc

        item = self._extract(soup, url)
        if item is None:
            raise CollectorError(f"来源 {self.source_name} 未能提取到有效内容")

        result = CollectorResult(source_name=self.source_name)
        self._route(item, start, end, result)
        return result

    # ------------------------------------------------------------------

    def _extract(self, soup: Any, url: str) -> Optional[IntelItem]:
        """按配置的选择器提取内容。"""
        title_node = self._select(soup, self.config.title_selector)
        content_node = self._select(soup, self.config.content_selector)

        title = title_node.get_text(" ", strip=True) if title_node else ""
        if not title and soup.title and soup.title.string:
            title = soup.title.string.strip()
        if not title:
            title = f"{self.source_name} 公告"

        if content_node is not None:
            body = content_node.get_text("\n", strip=True)
        else:
            body = self._extract_body(soup)

        published = None
        date_node = self._select(soup, self.config.date_selector)
        if date_node is not None:
            published = self._parse_date(date_node)

        if published is None:
            published = self._parse_meta_date(soup)

        return self._base_item(
            title=title,
            url=url,
            abstract=body,
            authors=[],
            content_type=self.config.extra.get("content_type", "news"),
            cve_ids=extract_cve_ids(f"{title} {body}"),
            published_at=published,
            first_published_at=published,
        )

    @staticmethod
    def _select(soup: Any, selector: Optional[str]) -> Any:
        """执行 CSS 选择器，失败时返回 None。"""
        if not selector:
            return None
        try:
            return soup.select_one(selector)
        except Exception:  # noqa: BLE001 - 无效选择器不应中断采集
            logger.warning("无效的 CSS 选择器: %s", selector)
            return None

    @staticmethod
    def _extract_body(soup: Any) -> str:
        """未指定正文选择器时，退化为主内容区域。"""
        for tag in ("article", "main"):
            node = soup.find(tag)
            if node is not None:
                return node.get_text("\n", strip=True)
        body = soup.find("body")
        return body.get_text("\n", strip=True) if body else ""

    @staticmethod
    def _parse_date(node: Any) -> Optional[datetime]:
        """从日期节点解析时间（优先 datetime 属性，其次文本）。"""
        raw = node.get("datetime") or node.get("content") or node.get_text(strip=True)
        if not raw:
            return None
        return parse_date_string(str(raw))

    @staticmethod
    def _parse_meta_date(soup: Any) -> Optional[datetime]:
        """从 ``<meta>`` 标签的常见时间属性中解析。"""
        selectors = (
            {"property": "article:published_time"},
            {"name": "article:published_time"},
            {"property": "og:published_time"},
            {"name": "publish-date"},
            {"name": "date"},
            {"name": "DC.date.issued"},
            {"itemprop": "datePublished"},
        )
        for attrs in selectors:
            node = soup.find("meta", attrs=attrs)
            if node is not None and node.get("content"):
                parsed = parse_date_string(node["content"])
                if parsed is not None:
                    return parsed
        return None

    # ------------------------------------------------------------------

    def _robots_allowed(self, url: str) -> bool:
        """检查 robots.txt 是否允许抓取。"""
        try:
            from urllib.parse import urlsplit

            parts = urlsplit(url)
            root = f"{parts.scheme}://{parts.netloc}"
        except ValueError:
            return True

        parser = self._robots_cache.get(root)
        if parser is None:
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(f"{root}/robots.txt")
            try:
                response = self.http.get(f"{root}/robots.txt", timeout=10)
                parser.parse(response.text.splitlines())
            except Exception:  # noqa: BLE001 - robots 不可达时按允许处理
                logger.info("无法获取 %s 的 robots.txt，按允许处理", root)
                parser = None
            self._robots_cache[root] = parser

        if parser is None:
            return True
        try:
            return parser.can_fetch(self.user_agent, url)
        except Exception:  # noqa: BLE001
            return True
