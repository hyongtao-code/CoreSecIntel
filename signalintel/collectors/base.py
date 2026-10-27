"""采集器基类与统一契约。

每个数据源实现一个适配器，继承 :class:`BaseCollector`，输出
:class:`~signalintel.models.IntelItem`。新增来源只需增加适配器 + YAML 配置，
无需修改核心处理流程。

单个来源故障通过 :class:`CollectorError` 隔离，由上层调度器捕获，
不影响其它来源与整体任务。
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from signalintel.models import IntelItem
from signalintel.utils.dates import ensure_aware
from signalintel.utils.http import HttpClient

logger = logging.getLogger(__name__)

__all__ = [
    "BaseCollector",
    "CollectorConfig",
    "CollectorError",
    "CollectorResult",
]


class CollectorError(RuntimeError):
    """采集器执行失败（已隔离，不影响其它来源）。"""


@dataclass
class CollectorConfig:
    """采集器配置。

    :param name: 来源名称（用于报告展示）
    :param kind: 适配器类型标识，对应 ``collectors`` 模块中的类名
    :param url: RSS / 网页来源的地址
    :param api_key: 需要密钥的来源（IEEE Xplore 等）
    :param params: 附加到请求的参数或查询词
    :param enabled: 是否启用
    :param trust: 来源可信度基准值（0-1）
    """

    name: str
    #: 报告中展示的来源名称（缺省等于 ``name``），例如 arXiv / IEEE Xplore
    display_name: Optional[str] = None
    kind: str = ""
    url: Optional[str] = None
    api_key: Optional[str] = None
    params: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True
    trust: float = 0.6
    limit: int = 100
    max_items: int = 50
    title_selector: Optional[str] = None
    date_selector: Optional[str] = None
    content_selector: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class CollectorResult:
    """单个采集器的执行结果。"""

    source_name: str
    items: list[IntelItem] = field(default_factory=list)
    #: 缺少可靠发布时间、无法判定是否落在时间窗口内的条目。
    #: 这些条目会被标记为「发布时间待核实」，默认不进入主报告。
    pending_items: list[IntelItem] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    skipped: bool = False
    skip_reason: str = ""

    @property
    def item_count(self) -> int:
        return len(self.items)

    @property
    def all_items(self) -> list[IntelItem]:
        """窗口内条目 + 待核实条目。"""
        return list(self.items) + list(self.pending_items)


class BaseCollector(ABC):
    """采集器基类。"""

    #: 来源默认可信度
    default_trust: float = 0.6
    #: 来源类型（paper / news / vulnerability / report）
    default_source_type: str = "news"
    #: 内容类型
    default_content_type: str = "news"

    def __init__(
        self,
        config: CollectorConfig,
        http_client: Optional[HttpClient] = None,
    ) -> None:
        self.config = config
        self.http = http_client or HttpClient()
        self.source_name = config.display_name or config.name or self.__class__.__name__

    # ------------------------------------------------------------------

    @property
    def available(self) -> bool:
        """该来源当前是否可用（例如缺少必需的 API Key）。"""
        return True

    @abstractmethod
    def collect(self, start: datetime, end: datetime) -> CollectorResult:
        """在 ``[start, end)`` 窗口内采集内容。"""

    # ------------------------------------------------------------------

    def run(self, start: datetime, end: datetime) -> CollectorResult:
        """执行采集，隔离异常，保证上层拿到的永远是 ``CollectorResult``。"""
        result = CollectorResult(source_name=self.source_name)
        if not self.available:
            result.skipped = True
            result.skip_reason = self.unavailable_reason()
            logger.info("跳过来源 %s：%s", self.source_name, result.skip_reason)
            return result

        import time

        started = time.monotonic()
        try:
            inner = self.collect(start, end)
        except CollectorError as exc:
            logger.warning("来源 %s 采集失败: %s", self.source_name, exc)
            result.errors.append(str(exc))
            result.duration_seconds = time.monotonic() - started
            return result
        except Exception as exc:  # noqa: BLE001 - 隔离所有来源级故障
            logger.exception("来源 %s 采集失败", self.source_name)
            result.errors.append(f"{type(exc).__name__}: {exc}")
            result.duration_seconds = time.monotonic() - started
            return result

        result.items = inner.items
        result.pending_items = inner.pending_items
        result.errors.extend(inner.errors)
        result.duration_seconds = time.monotonic() - started
        logger.info(
            "来源 %s 采集完成：%d 条，耗时 %.1fs",
            self.source_name,
            len(result.items),
            result.duration_seconds,
        )
        return result

    def unavailable_reason(self) -> str:
        """来源不可用的原因说明。"""
        return "来源未配置"

    # ------------------------------------------------------------------

    def _base_item(self, **kwargs: Any) -> IntelItem:
        """构造带来源默认值的条目。"""
        kwargs.setdefault("source", self.source_name)
        kwargs.setdefault("source_type", self.default_source_type)
        kwargs.setdefault("content_type", self.default_content_type)
        kwargs.setdefault("trust_score", self.config.trust or self.default_trust)
        kwargs.setdefault("collected_at", datetime.now().astimezone())
        return IntelItem(**kwargs)

    def _route(
        self,
        item: IntelItem,
        start: datetime,
        end: datetime,
        result: CollectorResult,
    ) -> None:
        """按时间窗口归类条目。

        - 有可靠发布时间且落在窗口内 → ``result.items``（进入主报告候选）
        - 有可靠发布时间但不在窗口内 → 丢弃
        - 缺少可靠发布时间 → ``result.pending_items``（标记「发布时间待核实」，
          默认不进入主报告）
        """
        if item.effective_published_at is None:
            result.pending_items.append(item)
            return
        if self._in_window(item, start, end):
            result.items.append(item)

    def _in_window(
        self,
        item: IntelItem,
        start: datetime,
        end: datetime,
        tz_name: str = "Asia/Shanghai",
    ) -> bool:
        """判断条目是否落在时间窗口内。

        缺少可靠发布时间的条目默认不进入主报告（返回 ``False``）。
        """
        published = item.effective_published_at
        if published is None:
            return False
        published = ensure_aware(published, tz_name)
        start = ensure_aware(start, tz_name)
        end = ensure_aware(end, tz_name)
        assert published is not None and start is not None and end is not None
        return start <= published < end
