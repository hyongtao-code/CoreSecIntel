"""文件化归档。

**不依赖数据库**：每期报告存为一个目录::

    data/archive/
      2026-10-19/
        report.html     # 完整 HTML 报告
        meta.json       # 统计、条目摘要、主题等元数据

设计取舍：

- 一年 52 期 = 52 个目录，纯文件，任何编辑器都能直接看、直接备份。
- 元数据用 JSON，HTTP 页面直接读取，无需解析 HTML。
- 单期自包含：删除一个目录就是删除一期，不影响其它期。
"""

from __future__ import annotations

import json
import logging
import shutil
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from signalintel.models import IntelItem
from signalintel.reports.html_report import ReportData

logger = logging.getLogger(__name__)

__all__ = ["ArchivedReport", "ReportArchive"]

#: 单个目录中的文件名
REPORT_FILE = "report.html"
META_FILE = "meta.json"


@dataclass
class ArchivedReport:
    """一期已归档的报告。"""

    report_date: str
    path: Path
    meta_path: Path
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def item_count(self) -> int:
        return int(self.meta.get("item_count", 0))

    @property
    def subject(self) -> str:
        return str(self.meta.get("subject", ""))

    @property
    def html(self) -> str:
        """读取报告正文。"""
        try:
            return self.path.read_text(encoding="utf-8")
        except OSError:
            return ""

    @property
    def items(self) -> list[dict[str, Any]]:
        return list(self.meta.get("items", []))


class ReportArchive:
    """报告归档（纯文件系统）。"""

    def __init__(self, root: Path | str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------

    def period_dir(self, report_date: str) -> Path:
        """某期报告的目录。"""
        return self.root / report_date

    def save(
        self,
        data: ReportData,
        html: str,
        subject: str,
        extra: Optional[dict[str, Any]] = None,
    ) -> ArchivedReport:
        """保存一期报告。

        同日期重复保存会覆盖（重新生成时不会产生重复期）。
        """
        target = self.period_dir(data.report_date)
        target.mkdir(parents=True, exist_ok=True)

        report_path = target / REPORT_FILE
        report_path.write_text(html, encoding="utf-8")

        meta: dict[str, Any] = {
            "report_date": data.report_date,
            "subject": subject,
            "window_start": data.window_start.isoformat(),
            "window_end": data.window_end.isoformat(),
            "timezone": data.timezone,
            "sources_ok": data.sources_ok,
            "sources_failed": data.sources_failed,
            "candidates": data.candidates,
            "after_dedup": data.after_dedup,
            "after_filter": data.after_filter,
            "p1_count": data.p1_count,
            "p2_count": data.p2_count,
            "p3_count": data.p3_count,
            "pending_count": data.pending_count,
            "item_count": len(data.all_items),
            "observations": list(data.observations),
            "items": [_item_to_dict(item) for item in data.all_items],
        }
        if extra:
            meta.update(extra)

        meta_path = target / META_FILE
        meta_path.write_text(
            json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
        )

        logger.info("已归档: %s（%s 条）", data.report_date, meta["item_count"])
        return ArchivedReport(
            report_date=data.report_date,
            path=report_path,
            meta_path=meta_path,
            meta=meta,
        )

    # ------------------------------------------------------------------

    def list(self) -> list[ArchivedReport]:
        """列出全部归档，按日期倒序（最新在前）。"""
        if not self.root.exists():
            return []

        entries: list[ArchivedReport] = []
        for directory in self.root.iterdir():
            if not directory.is_dir():
                continue
            report_path = directory / REPORT_FILE
            meta_path = directory / META_FILE
            if not report_path.exists() or not meta_path.exists():
                continue
            entries.append(
                ArchivedReport(
                    report_date=directory.name,
                    path=report_path,
                    meta_path=meta_path,
                    meta=self._read_meta(meta_path),
                )
            )

        entries.sort(key=lambda e: e.report_date, reverse=True)
        return entries

    def get(self, report_date: str) -> Optional[ArchivedReport]:
        """按日期读取一期。"""
        target = self.period_dir(report_date)
        report_path = target / REPORT_FILE
        meta_path = target / META_FILE
        if not report_path.exists() or not meta_path.exists():
            return None
        return ArchivedReport(
            report_date=report_date,
            path=report_path,
            meta_path=meta_path,
            meta=self._read_meta(meta_path),
        )

    def latest(self) -> Optional[ArchivedReport]:
        """最新一期。"""
        entries = self.list()
        return entries[0] if entries else None

    def delete(self, report_date: str) -> bool:
        """删除一期。"""
        target = self.period_dir(report_date)
        if not target.exists():
            return False
        shutil.rmtree(target)
        return True

    # ------------------------------------------------------------------

    def page(
        self, page: int = 1, page_size: int = 10
    ) -> tuple[list[ArchivedReport], int, int, int]:
        """分页。

        :return: ``(当前页条目, 总数, 总页数, 实际页码)``。
            页码越界时钳制到有效范围（不会返回空白页）。
        """
        entries = self.list()
        total = len(entries)
        page_size = max(1, page_size)
        total_pages = max(1, (total + page_size - 1) // page_size)
        # 越界页码钳制到有效范围，避免翻页出现空白页
        page = max(1, min(page, total_pages))

        start = (page - 1) * page_size
        return entries[start : start + page_size], total, total_pages, page

    @staticmethod
    def _read_meta(meta_path: Path) -> dict[str, Any]:
        """读取元数据，损坏时返回空字典（不中断列表渲染）。"""
        try:
            data = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            logger.warning("归档元数据损坏，跳过: %s", meta_path)
            return {}
        return data if isinstance(data, dict) else {}


def _item_to_dict(item: IntelItem) -> dict[str, Any]:
    """条目 → 便于前端渲染的精简字典。"""
    return {
        "title": item.title,
        "title_cn": item.title_cn,
        "url": item.url,
        "source": item.source,
        "source_type": item.source_type,
        "content_type": item.content_type,
        "priority": item.priority,
        "score": item.score,
        "published_at": item.published_at.isoformat() if item.published_at else None,
        "doi": item.doi,
        "cve_ids": list(item.cve_ids),
        "summary_cn": item.summary_cn,
        "attack_surface": item.attack_surface,
        "technique": item.technique,
        "impact": item.impact,
        "significance": item.significance,
        "recommendations": item.recommendations,
        "confidence_note": item.confidence_note,
        "is_preprint": item.is_preprint,
    }
