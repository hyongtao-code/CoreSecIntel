"""SQLite 数据库初始化与迁移。

数据库保存三类信息：

1. ``items``：已采集内容的全量记录（含大模型摘要结果），用于增量处理与去重
2. ``runs``：每次任务的状态记录（时间窗口、各阶段统计、错误）
3. ``sent_reports``：已发送报告的记录，避免重复推送

迁移机制：按版本号顺序执行迁移脚本，``schema_version`` 记录当前版本。
"""

from __future__ import annotations

import logging
import sqlite3
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)

__all__ = ["Database", "MIGRATIONS", "CURRENT_SCHEMA_VERSION"]


#: 迁移列表，按顺序执行。每个元素是 (版本号, SQL 语句列表)
MIGRATIONS: list[tuple[int, list[str]]] = [
    (
        1,
        [
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version INTEGER NOT NULL,
                applied_at TEXT NOT NULL
            )
            """,
            """
            CREATE TABLE IF NOT EXISTS items (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                fingerprint TEXT NOT NULL UNIQUE,
                doi TEXT,
                normalized_url TEXT,
                title TEXT NOT NULL,
                title_cn TEXT,
                source TEXT NOT NULL,
                source_type TEXT NOT NULL,
                content_type TEXT NOT NULL,
                url TEXT NOT NULL,
                abstract TEXT,
                authors TEXT,
                cve_ids TEXT,
                published_at TEXT,
                first_published_at TEXT,
                updated_at TEXT,
                collected_at TEXT,
                priority TEXT,
                score REAL,
                score_reasons TEXT,
                relevance_keywords TEXT,
                summary_cn TEXT,
                attack_surface TEXT,
                technique TEXT,
                impact TEXT,
                significance TEXT,
                recommendations TEXT,
                confidence_note TEXT,
                is_preprint INTEGER DEFAULT 0,
                trust_score REAL DEFAULT 0.5,
                alternate_sources TEXT,
                payload TEXT,
                run_id INTEGER,
                created_at TEXT NOT NULL,
                updated_at_db TEXT NOT NULL
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_items_doi ON items(doi)",
            "CREATE INDEX IF NOT EXISTS idx_items_published ON items(published_at)",
            "CREATE INDEX IF NOT EXISTS idx_items_priority ON items(priority)",
            "CREATE INDEX IF NOT EXISTS idx_items_score ON items(score)",
            "CREATE INDEX IF NOT EXISTS idx_items_run ON items(run_id)",
            """
            CREATE TABLE IF NOT EXISTS runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                started_at TEXT NOT NULL,
                finished_at TEXT,
                window_start TEXT NOT NULL,
                window_end TEXT NOT NULL,
                timezone TEXT NOT NULL,
                mode TEXT,
                status TEXT NOT NULL DEFAULT 'running',
                sources_ok INTEGER DEFAULT 0,
                sources_failed INTEGER DEFAULT 0,
                candidates INTEGER DEFAULT 0,
                after_dedup INTEGER DEFAULT 0,
                after_filter INTEGER DEFAULT 0,
                p1_count INTEGER DEFAULT 0,
                p2_count INTEGER DEFAULT 0,
                p3_count INTEGER DEFAULT 0,
                pending_count INTEGER DEFAULT 0,
                report_path TEXT,
                email_sent INTEGER DEFAULT 0,
                error TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_runs_started ON runs(started_at)",
            """
            CREATE TABLE IF NOT EXISTS sent_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER,
                report_date TEXT NOT NULL,
                subject TEXT NOT NULL,
                recipients TEXT NOT NULL,
                item_count INTEGER DEFAULT 0,
                sent_at TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT
            )
            """,
            "CREATE INDEX IF NOT EXISTS idx_sent_date ON sent_reports(report_date)",
        ],
    ),
]


#: 当前 schema 版本
CURRENT_SCHEMA_VERSION = max(version for version, _ in MIGRATIONS)


class Database:
    """SQLite 数据库封装。"""

    def __init__(self, path: Path | str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    # ------------------------------------------------------------------

    @property
    def connection(self) -> sqlite3.Connection:
        """惰性打开连接。"""
        if self._conn is None:
            self._conn = sqlite3.connect(str(self.path), timeout=30.0)
            self._conn.row_factory = sqlite3.Row
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=30000")
        return self._conn

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            finally:
                self._conn = None

    def __enter__(self) -> "Database":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    # ------------------------------------------------------------------

    def migrate(self) -> int:
        """执行未应用的迁移，返回当前 schema 版本。"""
        conn = self.connection
        current = self.current_version()

        for version, statements in MIGRATIONS:
            if version <= current:
                continue
            logger.info("应用数据库迁移 v%s", version)
            with conn:
                for statement in statements:
                    conn.execute(statement)
                conn.execute(
                    "INSERT INTO schema_version (version, applied_at) VALUES (?, datetime('now'))",
                    (version,),
                )
        return self.current_version()

    def current_version(self) -> int:
        """读取当前 schema 版本。"""
        conn = self.connection
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
        ).fetchone()
        if row is None:
            return 0
        result = conn.execute("SELECT MAX(version) AS v FROM schema_version").fetchone()
        return int(result["v"]) if result and result["v"] is not None else 0

    def is_initialized(self) -> bool:
        """数据库是否已完成初始化。"""
        row = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='items'"
        ).fetchone()
        return row is not None

    # ------------------------------------------------------------------

    def execute(self, sql: str, params: tuple = ()) -> sqlite3.Cursor:
        """执行写入语句并提交。"""
        conn = self.connection
        with conn:
            return conn.execute(sql, params)

    def query(self, sql: str, params: tuple = ()) -> list[sqlite3.Row]:
        """执行查询。"""
        return list(self.connection.execute(sql, params).fetchall())

    def query_one(self, sql: str, params: tuple = ()) -> Optional[sqlite3.Row]:
        """执行单行查询。"""
        return self.connection.execute(sql, params).fetchone()

    def count(self, table: str, where: str = "", params: tuple = ()) -> int:
        """统计表行数。"""
        clause = f" WHERE {where}" if where else ""
        row = self.connection.execute(
            f"SELECT COUNT(*) AS c FROM {table}{clause}", params
        ).fetchone()
        return int(row["c"]) if row else 0
