"""采集器注册表与调度。

按 ``config/sources.yaml`` 的配置实例化采集器，逐个执行并隔离故障。
新增数据源只需：

1. 在 ``collectors/`` 下实现一个继承 ``BaseCollector`` 的适配器；
2. 在本文件的 ``COLLECTOR_REGISTRY`` 中注册；
3. 在 ``config/sources.yaml`` 中启用。
"""

from __future__ import annotations

import logging
import os
from datetime import datetime
from typing import Any, Callable, Optional

from signalintel.collectors.arxiv import ArxivCollector
from signalintel.collectors.base import (
    BaseCollector,
    CollectorConfig,
    CollectorError,
    CollectorResult,
)
from signalintel.collectors.crossref import CrossrefCollector
from signalintel.collectors.ieee import IeeeCollector
from signalintel.collectors.nvd import NvdCollector
from signalintel.collectors.rss import RssCollector
from signalintel.collectors.semantic_scholar import SemanticScholarCollector
from signalintel.collectors.web import WebCollector
from signalintel.utils.http import HttpClient

logger = logging.getLogger(__name__)

__all__ = ["COLLECTOR_REGISTRY", "build_collector", "build_collectors", "run_collectors"]


#: 适配器类型 → 实现类
COLLECTOR_REGISTRY: dict[str, type[BaseCollector]] = {
    "arxiv": ArxivCollector,
    "crossref": CrossrefCollector,
    "semantic_scholar": SemanticScholarCollector,
    "ieee": IeeeCollector,
    "nvd": NvdCollector,
    "rss": RssCollector,
    "web": WebCollector,
}


def _resolve_api_key(name: str, params: dict[str, Any]) -> Optional[str]:
    """按 ``api_key_env`` 从环境变量读取密钥。"""
    env_name = params.get("api_key_env")
    if not env_name:
        return None
    return os.environ.get(str(env_name))


def build_collector(
    source_name: str,
    spec: dict[str, Any],
    http_client: Optional[HttpClient] = None,
) -> Optional[BaseCollector]:
    """根据 YAML 配置构造采集器实例。

    ``spec`` 支持的键::

        type: rss            # 适配器类型
        enabled: true
        display_name: 名称
        url: https://...
        trust: 0.7
        params: {...}
        api_key_env: IEEE_API_KEY
        title_selector / date_selector / content_selector  # web 专用
    """
    params = dict(spec.get("params") or {})
    kind = str(spec.get("type") or spec.get("kind") or "").strip()

    collector_class = COLLECTOR_REGISTRY.get(kind)
    if collector_class is None:
        logger.warning("未知的数据源类型 %r（来源 %s），已跳过", kind, source_name)
        return None

    api_key = _resolve_api_key(source_name, params)
    if api_key:
        params.setdefault("api_key_env", spec.get("api_key_env") or "")

    config = CollectorConfig(
        name=source_name,
        display_name=spec.get("display_name") or spec.get("name") or source_name,
        kind=kind,
        url=spec.get("url"),
        api_key=api_key,
        params=params,
        enabled=bool(spec.get("enabled", True)),
        trust=float(spec.get("trust", 0.6)),
        limit=int(spec.get("limit", 100)),
        max_items=int(spec.get("max_items", 50)),
        title_selector=spec.get("title_selector"),
        date_selector=spec.get("date_selector"),
        content_selector=spec.get("content_selector"),
        extra=dict(spec.get("extra") or {}),
    )

    try:
        return collector_class(config, http_client=http_client)
    except TypeError:
        # 部分适配器不接受 http_client 参数
        return collector_class(config)


def build_collectors(
    sources: dict[str, Any],
    http_client: Optional[HttpClient] = None,
) -> list[BaseCollector]:
    """按配置构造全部启用的采集器。"""
    collectors: list[BaseCollector] = []
    for source_name, spec in (sources or {}).items():
        if not isinstance(spec, dict):
            continue
        if not spec.get("enabled", True):
            logger.info("来源 %s 已禁用", source_name)
            continue
        collector = build_collector(source_name, spec, http_client=http_client)
        if collector is not None:
            collectors.append(collector)
    return collectors


def run_collectors(
    collectors: list[BaseCollector],
    start: datetime,
    end: datetime,
) -> list[CollectorResult]:
    """依次执行采集，单个来源故障不影响其它来源。"""
    results: list[CollectorResult] = []
    for collector in collectors:
        try:
            results.append(collector.run(start, end))
        except Exception as exc:  # noqa: BLE001 - 最后的隔离防线
            logger.exception("来源 %s 出现未预期的异常", collector.source_name)
            results.append(
                CollectorResult(
                    source_name=collector.source_name,
                    errors=[f"{type(exc).__name__}: {exc}"],
                )
            )
    return results
