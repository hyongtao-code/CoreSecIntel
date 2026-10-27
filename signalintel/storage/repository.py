"""数据访问层（Repository）。

封装 items / runs / sent_reports 三张表的读写，
上层业务代码不直接写 SQL。
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any, Optional

from signalintel.models import IntelItem
from signalintel.storage.database import Database
from signalintel.utils.dates import parse_date_string
from signalintel.utils.patterns import PROTOCOL_RE  # noqa: F401 - 供下游复用

logger = logging.getLogger(__name__)

__all__ = ["Repository", "RunRecord"]


class RunRecord:
    """一次任务运行的记录。"""

    def __init__(self, run_id: int, **kwargs: Any) -> None:
        self.run_id = run_id
        self.started_at = kwargs.get("started_at")
        self.finished_at = kwargs.get("finished_at")
        self.window_start = kwargs.get("window_start")
        self.window_end = kwargs.get("window_end")
        self.timezone = kwargs.get("timezone")
        self.mode = kwargs.get("mode")
        self.status = kwargs.get("status")
        self.sources_ok = kwargs.get("sources_ok", 0)
        self.sources_failed = kwargs.get("sources_failed", 0)
        self.candidates = kwargs.get("candidates", 0)
        self.after_dedup = kwargs.get("after_dedup", 0)
        self.after_filter = kwargs.get("after_filter", 0)
        self.p1_count = kwargs.get("p1_count", 0)
        self.p2_count = kwargs.get("p2_count", 0)
        self.p3_count = kwargs.get("p3_count", 0)
        self.pending_count = kwargs.get("pending_count", 0)
        self.report_path = kwargs.get("report_path")
        self.email_sent = kwargs.get("email_sent", 0)
        self.error = kwargs.get("error")

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "window_start": self.window_start,
            "window_end": self.window_end,
            "timezone": self.timezone,
            "mode": self.mode,
            "status": self.status,
            "sources_ok": self.sources_ok,
            "sources_failed": self.sources_failed,
            "candidates": self.candidates,
            "after_dedup": self.after_dedup,
            "after_filter": self.after_filter,
            "p1_count": self.p1_count,
            "p2_count": self.p2_count,
            "p3_count": self.p3_count,
            "pending_count": self.pending_count,
            "report_path": self.report_path,
            "email_sent": self.email_sent,
            "error": self.error,
        }


class Repository:
    """数据访问层。"""

    def __init__(self, db: Database) -> None:
        self.db = db

    # ------------------------------------------------------------------
    # items
    # ------------------------------------------------------------------

    def save_item(self, item: IntelItem, run_id: Optional[int] = None) -> int:
        """保存或更新一条内容，返回 item id。

        以 ``fingerprint``（DOI + CVE + 标题的哈希）作为唯一键，重复保存为更新。
        """
        now = datetime.now().astimezone().isoformat()
        payload = json.dumps(item.to_dict(), ensure_ascii=False)
        doi = item.doi.lower() if item.doi else None
        normalized_url = item.url.lower() if item.url else None

        existing = self.db.query_one(
            "SELECT id FROM items WHERE fingerprint = ?", (item.content_fingerprint,)
        )
        if existing:
            self.db.execute(
                """
                UPDATE items SET
                    title = ?, title_cn = ?, source = ?, source_type = ?,
                    content_type = ?, url = ?, abstract = ?, authors = ?,
                    cve_ids = ?, published_at = ?, first_published_at = ?,
                    updated_at = ?, collected_at = ?, priority = ?, score = ?,
                    score_reasons = ?, relevance_keywords = ?, summary_cn = ?,
                    attack_surface = ?, technique = ?, impact = ?,
                    significance = ?, recommendations = ?, confidence_note = ?,
                    is_preprint = ?, trust_score = ?, alternate_sources = ?,
                    payload = ?, run_id = ?, updated_at_db = ?
                WHERE id = ?
                """,
                (
                    item.title,
                    item.title_cn or None,
                    item.source,
                    item.source_type,
                    item.content_type,
                    item.url,
                    item.abstract,
                    json.dumps(item.authors, ensure_ascii=False),
                    json.dumps(item.cve_ids, ensure_ascii=False),
                    item.published_at.isoformat() if item.published_at else None,
                    item.first_published_at.isoformat() if item.first_published_at else None,
                    item.updated_at.isoformat() if item.updated_at else None,
                    item.collected_at.isoformat() if item.collected_at else None,
                    item.priority,
                    item.score,
                    json.dumps(item.score_reasons, ensure_ascii=False),
                    json.dumps(item.relevance_keywords, ensure_ascii=False),
                    item.summary_cn or None,
                    item.attack_surface or None,
                    item.technique or None,
                    item.impact or None,
                    item.significance or None,
                    item.recommendations or None,
                    item.confidence_note or None,
                    1 if item.is_preprint else 0,
                    item.trust_score,
                    json.dumps(
                        [link.to_dict() for link in item.alternate_sources],
                        ensure_ascii=False,
                    ),
                    payload,
                    run_id,
                    now,
                    existing["id"],
                ),
            )
            return int(existing["id"])

        cursor = self.db.execute(
            """
            INSERT INTO items (
                fingerprint, doi, normalized_url, title, title_cn, source,
                source_type, content_type, url, abstract, authors, cve_ids,
                published_at, first_published_at, updated_at, collected_at,
                priority, score, score_reasons, relevance_keywords, summary_cn,
                attack_surface, technique, impact, significance, recommendations,
                confidence_note, is_preprint, trust_score, alternate_sources,
                payload, run_id, created_at, updated_at_db
            ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            """,
            (
                item.content_fingerprint,
                doi,
                normalized_url,
                item.title,
                item.title_cn or None,
                item.source,
                item.source_type,
                item.content_type,
                item.url,
                item.abstract,
                json.dumps(item.authors, ensure_ascii=False),
                json.dumps(item.cve_ids, ensure_ascii=False),
                item.published_at.isoformat() if item.published_at else None,
                item.first_published_at.isoformat() if item.first_published_at else None,
                item.updated_at.isoformat() if item.updated_at else None,
                item.collected_at.isoformat() if item.collected_at else None,
                item.priority,
                item.score,
                json.dumps(item.score_reasons, ensure_ascii=False),
                json.dumps(item.relevance_keywords, ensure_ascii=False),
                item.summary_cn or None,
                item.attack_surface or None,
                item.technique or None,
                item.impact or None,
                item.significance or None,
                item.recommendations or None,
                item.confidence_note or None,
                1 if item.is_preprint else 0,
                item.trust_score,
                json.dumps(
                    [link.to_dict() for link in item.alternate_sources],
                    ensure_ascii=False,
                ),
                payload,
                run_id,
                now,
                now,
            ),
        )
        return int(cursor.lastrowid or 0)

    def save_items(self, items: list[IntelItem], run_id: Optional[int] = None) -> int:
        """批量保存，返回保存条数。"""
        count = 0
        for item in items:
            self.save_item(item, run_id=run_id)
            count += 1
        return count

    def get_item(self, item_id: int) -> Optional[IntelItem]:
        """按 id 读取条目。"""
        row = self.db.query_one("SELECT payload FROM items WHERE id = ?", (item_id,))
        if row is None or not row["payload"]:
            return None
        try:
            return IntelItem.from_dict(json.loads(row["payload"]))
        except (json.JSONDecodeError, TypeError, ValueError):
            logger.warning("条目 %s 的 payload 解析失败", item_id)
            return None

    def find_by_fingerprint(self, fingerprint: str) -> Optional[IntelItem]:
        """按指纹读取条目。"""
        row = self.db.query_one(
            "SELECT payload FROM items WHERE fingerprint = ?", (fingerprint,)
        )
        if row is None or not row["payload"]:
            return None
        try:
            return IntelItem.from_dict(json.loads(row["payload"]))
        except (json.JSONDecodeError, TypeError, ValueError):
            return None

    def get_unsummarized(self, limit: int = 50) -> list[IntelItem]:
        """读取尚未生成中文摘要的条目（用于「只生成摘要」调试模式）。"""
        rows = self.db.query(
            """
            SELECT payload FROM items
            WHERE (summary_cn IS NULL OR summary_cn = '')
            ORDER BY published_at DESC
            LIMIT ?
            """,
            (limit,),
        )
        return self._rows_to_items(rows)

    def get_items_in_window(
        self, start: datetime, end: datetime, limit: int = 200
    ) -> list[IntelItem]:
        """读取时间窗口内的条目。"""
        rows = self.db.query(
            """
            SELECT payload FROM items
            WHERE published_at >= ? AND published_at < ?
            ORDER BY published_at DESC
            LIMIT ?
            """,
            (start.isoformat(), end.isoformat(), limit),
        )
        return self._rows_to_items(rows)

    def get_reported_items(self) -> set[str]:
        """读取已纳入过报告的条目指纹集合（用于避免重复推送）。"""
        rows = self.db.query(
            "SELECT fingerprint FROM items WHERE priority IS NOT NULL AND score IS NOT NULL"
        )
        return {row["fingerprint"] for row in rows}

    @staticmethod
    def _rows_to_items(rows: list[Any]) -> list[IntelItem]:
        items: list[IntelItem] = []
        for row in rows:
            payload = row["payload"] if "payload" in row.keys() else None
            if not payload:
                continue
            try:
                items.append(IntelItem.from_dict(json.loads(payload)))
            except (json.JSONDecodeError, TypeError, ValueError):
                continue
        return items

    def count(self, table: str, where: str = "", params: tuple = ()) -> int:
        """统计表行数。"""
        return self.db.count(table, where=where, params=params)

    # ------------------------------------------------------------------
    # runs
    # ------------------------------------------------------------------

    def start_run(
        self,
        window_start: datetime,
        window_end: datetime,
        timezone: str,
        mode: str = "full",
    ) -> int:
        """记录一次任务开始。"""
        cursor = self.db.execute(
            """
            INSERT INTO runs (started_at, window_start, window_end, timezone, mode, status)
            VALUES (?,?,?,?,?,'running')
            """,
            (
                datetime.now().astimezone().isoformat(),
                window_start.isoformat(),
                window_end.isoformat(),
                timezone,
                mode,
            ),
        )
        return int(cursor.lastrowid or 0)

    def update_run(self, run_id: int, **fields: Any) -> None:
        """更新任务状态。"""
        if not fields:
            return
        allowed = {
            "finished_at",
            "status",
            "sources_ok",
            "sources_failed",
            "candidates",
            "after_dedup",
            "after_filter",
            "p1_count",
            "p2_count",
            "p3_count",
            "pending_count",
            "report_path",
            "email_sent",
            "error",
        }
        updates = {key: value for key, value in fields.items() if key in allowed}
        if not updates:
            return
        if "finished_at" not in updates:
            updates["finished_at"] = datetime.now().astimezone().isoformat()
        assignments = ", ".join(f"{key} = ?" for key in updates)
        params = tuple(updates.values()) + (run_id,)
        self.db.execute(f"UPDATE runs SET {assignments} WHERE id = ?", params)

    def get_last_run(self) -> Optional[RunRecord]:
        """读取最近一次任务记录。"""
        row = self.db.query_one("SELECT * FROM runs ORDER BY id DESC LIMIT 1")
        if row is None:
            return None
        return RunRecord(row["id"], **dict(row))

    def get_runs(self, limit: int = 10) -> list[RunRecord]:
        """读取最近若干次任务记录。"""
        rows = self.db.query("SELECT * FROM runs ORDER BY id DESC LIMIT ?", (limit,))
        return [RunRecord(row["id"], **dict(row)) for row in rows]

    # ------------------------------------------------------------------
    # sent_reports
    # ------------------------------------------------------------------

    def record_sent_report(
        self,
        run_id: Optional[int],
        report_date: str,
        subject: str,
        recipients: list[str],
        item_count: int,
        status: str,
        error: Optional[str] = None,
    ) -> int:
        """记录一次发送尝试。"""
        cursor = self.db.execute(
            """
            INSERT INTO sent_reports
                (run_id, report_date, subject, recipients, item_count, sent_at, status, error)
            VALUES (?,?,?,?,?,?,?,?)
            """,
            (
                run_id,
                report_date,
                subject,
                json.dumps(recipients, ensure_ascii=False),
                item_count,
                datetime.now().astimezone().isoformat(),
                status,
                error,
            ),
        )
        return int(cursor.lastrowid or 0)

    def was_report_sent(self, report_date: str) -> bool:
        """指定日期的报告是否已成功发送。"""
        row = self.db.query_one(
            "SELECT id FROM sent_reports WHERE report_date = ? AND status = 'sent' LIMIT 1",
            (report_date,),
        )
        return row is not None

    def get_sent_reports(self, limit: int = 20) -> list[dict[str, Any]]:
        """读取最近的发送记录。"""
        rows = self.db.query(
            "SELECT * FROM sent_reports ORDER BY id DESC LIMIT ?", (limit,)
        )
        results: list[dict[str, Any]] = []
        for row in rows:
            data = dict(row)
            try:
                data["recipients"] = json.loads(data.get("recipients") or "[]")
            except json.JSONDecodeError:
                data["recipients"] = []
            results.append(data)
        return results
