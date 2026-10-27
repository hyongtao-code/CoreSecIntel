"""NVD / CVE 漏洞数据采集器。

使用 NVD 2.0 API 检索最近发布的漏洞。

**重要**：NVD 的 ``keywordSearch`` 参数对多个关键词是「与」关系，
一次传入多个关键词会要求漏洞同时命中全部关键词，导致结果几乎为空。
因此本采集器对每个关键词**分别发起查询**再合并去重。

NVD 的时间字段语义严格区分：

- ``published``：漏洞**首次公开**时间（进入报告的依据）
- ``lastModified``：NVD 记录的**最后修改**时间（不可当作发布时间）

漏洞的公开时间、披露时间与修复时间含义不同，报告中只使用
``published`` 作为「首次公开时间」，避免混淆。
"""

from __future__ import annotations

import logging
import re
import time
from datetime import datetime
from typing import Any, Optional

from signalintel.collectors.base import (
    BaseCollector,
    CollectorConfig,
    CollectorResult,
)
from signalintel.models import IntelItem
from signalintel.processors.deduplicate import extract_cve_ids, normalize_url
from signalintel.utils.dates import parse_date_string
from signalintel.utils.http import HttpError

logger = logging.getLogger(__name__)

__all__ = ["NvdCollector"]

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

#: 默认关键词（电信核心网 / 信令相关）
DEFAULT_KEYWORDS: tuple[str, ...] = (
    "SS7",
    "MAP",
    "Diameter",
    "GTP-C",
    "GTP-U",
    "PFCP",
    "SIP",
    "IMS",
    "TCAP",
    "SCCP",
    "NGAP",
    "NAS",
    "telecom",
    "mobile network",
    "core network",
    "signaling",
    "signalling",
    "roaming",
    "5G",
    "LTE",
)


class NvdCollector(BaseCollector):
    """NVD 漏洞采集器。"""

    default_trust = 0.95
    default_source_type = "vulnerability"
    default_content_type = "vulnerability"

    #: NVD 官方限流：未使用 API Key 时为 5 次 / 30 秒。
    #: 逐关键词查询时必须主动限速，否则会收到 HTTP 429。
    RATE_LIMIT_SECONDS = 6.5

    def __init__(self, config: CollectorConfig, http_client: Any = None) -> None:
        super().__init__(config, http_client=http_client)
        # 允许测试或特殊场景覆盖限流间隔（0 表示不限速）
        self.rate_limit_seconds = float(
            self.config.params.get("rate_limit_seconds", self.RATE_LIMIT_SECONDS)
        )

    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        keywords = self.config.params.get("keywords") or DEFAULT_KEYWORDS
        if isinstance(keywords, str):
            keywords = [keywords]
        keywords = [str(k).strip() for k in keywords if str(k).strip()]

        max_items = int(self.config.params.get("max_items") or 100)
        page_size = min(2000, max(1, int(self.config.params.get("page_size") or 200)))

        result = CollectorResult(source_name=self.source_name)
        errors: list[str] = []
        seen_cves: set[str] = set()
        request_count = 0

        # NVD 要求 pubStartDate/pubEndDate 使用 ISO-8601 且带毫秒
        pub_start = start.astimezone().strftime("%Y-%m-%dT%H:%M:%S.000")
        pub_end = end.astimezone().strftime("%Y-%m-%dT%H:%M:%S.000")

        for keyword in keywords:
            if len(result.items) >= max_items:
                break

            # NVD 限流保护：每次请求之间留出间隔
            if request_count and self.rate_limit_seconds > 0:
                time.sleep(self.rate_limit_seconds)

            start_index = 0
            while len(result.items) < max_items:
                params: dict[str, Any] = {
                    "pubStartDate": pub_start,
                    "pubEndDate": pub_end,
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                    "keywordSearch": keyword,
                }
                try:
                    payload = self.http.get_json(API_URL, params=params)
                    request_count += 1
                except HttpError as exc:
                    errors.append(
                        f"关键词「{keyword}」第 {start_index // page_size + 1} 页请求失败: {exc}"
                    )
                    break

                vulnerabilities = (
                    payload.get("vulnerabilities", []) if isinstance(payload, dict) else []
                )
                if not vulnerabilities:
                    break

                new_in_batch = 0
                for raw in vulnerabilities:
                    if len(result.items) >= max_items:
                        break
                    item = self._parse_vulnerability(raw)
                    if item is None:
                        continue
                    cve_id = item.cve_ids[0] if item.cve_ids else ""
                    if cve_id and cve_id in seen_cves:
                        continue
                    if cve_id:
                        seen_cves.add(cve_id)
                    new_in_batch += 1
                    self._route(item, start, end, result)

                if len(vulnerabilities) < page_size or new_in_batch == 0:
                    break
                start_index += page_size

        result.errors = errors
        logger.info(
            "NVD 采集完成：%s 个关键词，命中 %s 条漏洞",
            len(keywords),
            len(result.items),
        )
        return result

    # ------------------------------------------------------------------

    def _parse_vulnerability(self, raw: dict[str, Any]) -> Optional[IntelItem]:
        cve = raw.get("cve") if isinstance(raw, dict) else None
        if not isinstance(cve, dict):
            return None

        cve_id = str(cve.get("id") or "").strip()
        if not cve_id:
            return None

        description = ""
        for desc in cve.get("descriptions", []) or []:
            if isinstance(desc, dict) and desc.get("lang") == "en":
                description = _clean(desc.get("value"))
                break
        if not description:
            descriptions = cve.get("descriptions", []) or []
            if descriptions and isinstance(descriptions[0], dict):
                description = _clean(descriptions[0].get("value"))

        published = parse_date_string(cve.get("published"))
        last_modified = parse_date_string(cve.get("lastModified"))

        references = cve.get("references", []) or []
        url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
        for ref in references:
            if isinstance(ref, dict) and ref.get("url"):
                url = ref["url"]
                break

        cvss = self._extract_cvss(cve)
        title = f"{cve_id}: {self._short_title(description)}"

        return self._base_item(
            title=title,
            url=url,
            abstract=description,
            authors=[],
            content_type="vulnerability",
            cve_ids=extract_cve_ids(f"{cve_id} {description}"),
            published_at=published,
            first_published_at=published,
            updated_at=last_modified,
            raw={"cvss": cvss, "last_modified": cve.get("lastModified")},
        )

    @staticmethod
    def _extract_cvss(cve: dict[str, Any]) -> Optional[float]:
        """提取 CVSS 基础评分（不同版本指标结构不同，逐个尝试）。"""
        metrics = cve.get("metrics", {})
        if not isinstance(metrics, dict):
            return None
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key)
            if not isinstance(entries, list) or not entries:
                continue
            for entry in entries:
                if not isinstance(entry, dict):
                    continue
                data = entry.get("cvssData")
                if isinstance(data, dict):
                    score = data.get("baseScore")
                    if isinstance(score, (int, float)):
                        return float(score)
        return None

    @staticmethod
    def _short_title(description: str, max_length: int = 120) -> str:
        """从描述中截取简短标题。"""
        if not description:
            return "未提供描述"
        text = description.strip()
        if len(text) <= max_length:
            return text
        return text[: max_length - 1].rstrip() + "…"


def _clean(text: Optional[str]) -> str:
    return re.sub(r"\s+", " ", str(text)).strip() if text else ""
