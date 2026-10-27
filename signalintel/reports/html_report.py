"""HTML 报告渲染。

- 使用 Jinja2 模板（``reports/templates/email.html``）。
- 所有外部内容经过 ``|e`` 转义，防止 HTML 注入。
- 链接统一经过 :func:`safe_url` 过滤，非 http/https 协议会被丢弃。
- 表格布局 + 内联样式，兼容 Outlook / Gmail / 移动端客户端。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from signalintel.models import IntelItem

logger = logging.getLogger(__name__)

__all__ = [
    "ReportBuilder",
    "ReportData",
    "build_subject",
    "render_html",
    "safe_url",
]

#: 模板目录
TEMPLATE_DIR = Path(__file__).resolve().parent / "templates"

#: 允许的链接协议
ALLOWED_SCHEMES = ("http", "https")


def safe_url(url: Optional[str]) -> str:
    """过滤不安全链接协议，返回空串表示不可用。"""
    if not url:
        return ""
    text = str(url).strip()
    if not text:
        return ""
    lowered = text.lower()
    if lowered.startswith("//"):
        return ""
    if "://" not in text:
        # 相对路径或无协议的地址不允许出现在外链中
        return ""
    scheme = lowered.split("://", 1)[0]
    if scheme not in ALLOWED_SCHEMES:
        return ""
    return text


@dataclass
class ReportData:
    """报告数据。"""

    window_start: datetime
    window_end: datetime
    timezone: str = "Asia/Shanghai"

    # 统计
    sources_ok: int = 0
    sources_failed: int = 0
    candidates: int = 0
    after_dedup: int = 0
    after_filter: int = 0
    p1_count: int = 0
    p2_count: int = 0
    p3_count: int = 0
    pending_count: int = 0

    # 内容
    p1_items: list[IntelItem] = field(default_factory=list)
    p2_items: list[IntelItem] = field(default_factory=list)
    p3_items: list[IntelItem] = field(default_factory=list)

    # 技术观察
    observations: list[str] = field(default_factory=list)

    # 报告日期（YYYY-MM-DD）
    report_date: str = ""

    @property
    def total_items(self) -> int:
        return len(self.p1_items) + len(self.p2_items) + len(self.p3_items)

    @property
    def paper_count(self) -> int:
        """论文类条目数量。"""
        return sum(
            1
            for item in (self.p1_items + self.p2_items + self.p3_items)
            if item.source_type == "paper" or item.content_type in {"paper", "preprint"}
        )

    @property
    def intel_count(self) -> int:
        """安全情报（非论文）条目数量。"""
        return self.total_items - self.paper_count

    @property
    def all_items(self) -> list[IntelItem]:
        return list(self.p1_items) + list(self.p2_items) + list(self.p3_items)


def build_subject(
    report_date: str,
    paper_count: int,
    intel_count: int,
    prefix: str = "【核心网信令安全周报】",
) -> str:
    """构造邮件主题。"""
    return (
        f"{prefix}{report_date}"
        f"｜{paper_count} 篇论文 · {intel_count} 条安全情报"
    )


# ---------------------------------------------------------------------------
# 模板渲染
# ---------------------------------------------------------------------------


def _get_jinja_env() -> Any:
    """构造 Jinja2 环境（自动转义）。"""
    try:
        from jinja2 import Environment, FileSystemLoader, select_autoescape
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError("缺少 Jinja2 依赖，无法生成 HTML 报告") from exc

    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html", "xml"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["safe_url"] = safe_url
    return env


def render_html(data: ReportData) -> str:
    """渲染报告 HTML。"""
    env = _get_jinja_env()
    template = env.get_template("email.html")
    return template.render(
        r=data,
        report_date=data.report_date,
        window_start=data.window_start.strftime("%Y-%m-%d"),
        window_end=data.window_end.strftime("%Y-%m-%d"),
        window_start_full=data.window_start.strftime("%Y-%m-%d %H:%M"),
        window_end_full=data.window_end.strftime("%Y-%m-%d %H:%M"),
        total_items=data.total_items,
        paper_count=data.paper_count,
        intel_count=data.intel_count,
        safe_url=safe_url,
        generated_at=datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
    )


class ReportBuilder:
    """报告构建器（渲染并写入磁盘）。"""

    def __init__(self, output_dir: Optional[Path] = None) -> None:
        self.output_dir = Path(output_dir) if output_dir else Path("data/reports")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def build(self, data: ReportData) -> Path:
        """渲染报告并写入文件，返回文件路径。"""
        html = render_html(data)
        filename = f"signalintel-report-{data.report_date or 'latest'}.html"
        path = self.output_dir / filename
        path.write_text(html, encoding="utf-8")
        logger.info("报告已生成: %s", path)
        return path
