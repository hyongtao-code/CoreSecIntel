"""访问合规性测试。

这些测试守护 project.md 第十章「安全与合规要求」中的硬约束：

- 只访问公开且允许访问的数据源；
- 不绕过付费墙、登录验证或访问控制；
- 不在内容采集链路上携带任何认证凭证。
"""

from __future__ import annotations

import inspect
import re
from pathlib import Path

import pytest

from signalintel.collectors import base as collectors_base
from signalintel.collectors.ieee import IeeeCollector
from signalintel.collectors.nvd import NvdCollector
from signalintel.collectors.rss import RssCollector
from signalintel.collectors.web import WebCollector
from signalintel.utils.http import HttpClient

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SOURCE_ROOT = PROJECT_ROOT / "signalintel"


# ---------------------------------------------------------------------------
# HTTP 客户端
# ---------------------------------------------------------------------------


def test_http_client_does_not_persist_cookies():
    """HTTP 客户端不得持久化 Cookie（不做登录）。"""
    client = HttpClient()
    assert len(client.session.cookies) == 0
    assert client.session.auth is None


def test_http_client_sends_no_authorization_by_default():
    """默认请求头不含 Authorization。"""
    client = HttpClient()
    assert "Authorization" not in client.session.headers


def test_http_client_has_identifiable_user_agent():
    """必须声明可识别的 User-Agent，便于站点管理员联系。"""
    client = HttpClient()
    assert "SignalIntelBot" in client.session.headers["User-Agent"]


# ---------------------------------------------------------------------------
# 采集器：不得包含登录逻辑
# ---------------------------------------------------------------------------


def _collector_source_files() -> list[Path]:
    return sorted((SOURCE_ROOT / "collectors").glob("*.py"))


def test_no_collector_contains_login_calls():
    """采集器代码中不得出现 login / signin / session 认证调用。"""
    forbidden = re.compile(
        r"\b(?:requests\.Session\(\)|\.login\(|signin|sign_in|"
        r"cookies\s*=|auth\s*=\s*\(|Set-Cookie)",
        re.IGNORECASE,
    )
    for path in _collector_source_files():
        source = path.read_text(encoding="utf-8")
        # 去掉注释行后再检查，避免文档说明触发误报
        code_lines = [
            line for line in source.splitlines() if not line.strip().startswith("#")
        ]
        code = "\n".join(code_lines)
        match = forbidden.search(code)
        assert not match, f"{path.name} 中出现疑似登录逻辑: {match.group(0)!r}"


def test_no_collector_requests_pdf_or_fulltext():
    """不得请求 PDF / 全文下载地址。"""
    forbidden = re.compile(
        r"\.pdf|/fulltext|/full_text|/download/[^/]*(?:pdf|article)",
        re.IGNORECASE,
    )
    for path in _collector_source_files():
        source = path.read_text(encoding="utf-8")
        code = "\n".join(
            line for line in source.splitlines() if not line.strip().startswith("#")
        )
        match = forbidden.search(code)
        assert not match, f"{path.name} 中出现全文/PDF 请求: {match.group(0)!r}"


def test_web_collector_does_not_bypass_paywall():
    """网页采集器不得包含绕过付费墙的关键词。"""
    source = (SOURCE_ROOT / "collectors" / "web.py").read_text(encoding="utf-8")
    for keyword in ("sci-hub", "bypass_paywall", "shadow_library", "libgen"):
        assert keyword not in source.lower()


# ---------------------------------------------------------------------------
# IEEE：只取元数据
# ---------------------------------------------------------------------------


def test_ieee_only_calls_official_api():
    """IEEE 采集器只请求官方 API 端点。"""
    source = inspect.getsource(IeeeCollector)
    urls = set(re.findall(r"https?://[^\s\"'()]+", source))
    # 允许出现的域名：官方 API、DOI 解析、IEEE 文档链接
    for url in urls:
        assert any(
            host in url
            for host in (
                "ieeexploreapi.ieee.org",
                "doi.org",
                "ieeexplore.ieee.org",
            )
        ), f"IEEE 采集器出现了非官方域名: {url}"


def test_ieee_prefers_doi_link_over_document_link():
    """优先给出 DOI 解析页，不直接指向可能需要订阅的全文页。"""
    collector = IeeeCollector(
        collectors_base.CollectorConfig(name="ieee", api_key="k")
    )
    item = collector._parse_document(
        {
            "title": "SS7 Vulnerabilities",
            "doi": "10.1109/ICC.2026.9999",
            "documentLink": "https://ieeexplore.ieee.org/document/9999",
            "abstract": "A study.",
        }
    )
    assert item is not None
    assert item.url == "https://doi.org/10.1109/icc.2026.9999"


# ---------------------------------------------------------------------------
# 采集器异常隔离
# ---------------------------------------------------------------------------


def test_collector_run_isolates_exceptions():
    """单个来源故障不得影响其它来源。"""

    class ExplodingCollector(collectors_base.BaseCollector):
        def collect(self, start, end):
            raise RuntimeError("boom")

    collector = ExplodingCollector(collectors_base.CollectorConfig(name="boom"))
    result = collector.run(None, None)
    assert result.errors
    assert result.items == []


def test_web_collector_raises_collector_error_on_http_failure():
    """网页采集失败应转为 CollectorError，由上层隔离。"""

    class FailingHttp:
        def get(self, *args, **kwargs):
            from signalintel.utils.http import HttpError

            raise HttpError("down")

        def get_text(self, *args, **kwargs):
            from signalintel.utils.http import HttpError

            raise HttpError("down")

    collector = WebCollector(
        collectors_base.CollectorConfig(name="x", url="https://example.com"),
        http_client=FailingHttp(),
    )
    with pytest.raises(collectors_base.CollectorError):
        collector.collect(None, None)
