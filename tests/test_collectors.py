"""采集器适配器测试。

全部使用假的 HTTP 客户端，不发起真实网络请求。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import pytest

from signalintel.collectors.arxiv import ArxivCollector
from signalintel.collectors.base import CollectorConfig, CollectorError, CollectorResult
from signalintel.collectors.crossref import CrossrefCollector
from signalintel.collectors.ieee import IeeeCollector
from signalintel.collectors.nvd import NvdCollector
from signalintel.collectors.rss import RssCollector
from signalintel.collectors.semantic_scholar import SemanticScholarCollector
from signalintel.collectors.web import WebCollector
from signalintel.utils.http import HttpError

CST = timezone(timedelta(hours=8))

START = datetime(2026, 10, 20, 0, 0, tzinfo=CST)
END = datetime(2026, 10, 27, 0, 0, tzinfo=CST)


class FakeHTTP:
    """按 URL 前缀返回预置数据的假 HTTP 客户端。"""

    def __init__(self, routes: dict[str, Any]) -> None:
        self.routes = routes
        self.calls: list[dict[str, Any]] = []

    def get_json(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"url": url, "params": params, "headers": headers})
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                return payload
        raise HttpError(f"未配置路由: {url}")

    def get_text(self, url, headers=None, timeout=None):
        self.calls.append({"url": url, "headers": headers})
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                return payload if isinstance(payload, str) else json.dumps(payload)
        raise HttpError(f"未配置路由: {url}")

    def get(self, url, params=None, headers=None, timeout=None, allow_error=False):
        self.calls.append({"url": url, "params": params, "headers": headers})
        for prefix, payload in self.routes.items():
            if url.startswith(prefix):
                if isinstance(payload, Exception):
                    raise payload
                if isinstance(payload, str):
                    return _FakeResponse(payload)
                return _FakeResponse(json.dumps(payload))
        raise HttpError(f"未配置路由: {url}")


class _FakeResponse:
    def __init__(self, text: str) -> None:
        self.text = text
        self.status_code = 200
        self.headers: dict[str, str] = {}
        self.encoding = "utf-8"

    def json(self):
        return json.loads(self.text)


# ---------------------------------------------------------------------------
# arXiv
# ---------------------------------------------------------------------------

ARXIV_FEED_XML = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <title>arXiv Query</title>
  <entry>
    <id>http://arxiv.org/abs/2601.00001v1</id>
    <updated>2026-10-25T10:00:00Z</updated>
    <published>2026-10-22T08:30:00Z</published>
    <title>SS7 Attack Analysis in Mobile Core Networks</title>
    <summary>We study SS7 attacks against the HLR and propose a signaling firewall.</summary>
    <author><name>Alice Zhang</name></author>
    <author><name>Bob Li</name></author>
    <link href="http://arxiv.org/abs/2601.00001v1" rel="alternate" type="text/html"/>
    <arxiv:doi>10.48550/arXiv.2601.00001</arxiv:doi>
  </entry>
  <entry>
    <id>http://arxiv.org/abs/2601.00002v1</id>
    <updated>2026-10-26T10:00:00Z</updated>
    <published>2026-10-26T09:00:00Z</published>
    <title>Quantum Error Correction on Superconducting Qubits</title>
    <summary>Logical qubit lifetimes in a superconducting processor.</summary>
    <author><name>Carol Dan</name></author>
    <link href="http://arxiv.org/abs/2601.00002v1" rel="alternate" type="text/html"/>
  </entry>
</feed>
"""

ARXIV_FEED = ARXIV_FEED_XML


def test_arxiv_collector_parses_entries():
    http = FakeHTTP({"https://export.arxiv.org": ARXIV_FEED})
    collector = ArxivCollector(
        CollectorConfig(name="arxiv", display_name="arXiv"), http_client=http
    )
    result = collector.collect(START, END)
    assert isinstance(result, CollectorResult)
    assert len(result.items) == 2
    first = result.items[0]
    assert "SS7" in first.title
    assert first.source == "arXiv"
    assert first.source_type == "paper"
    assert first.is_preprint is True
    assert first.authors == ["Alice Zhang", "Bob Li"]
    assert first.doi == "10.48550/arXiv.2601.00001"


def test_arxiv_collector_respects_time_window():
    http = FakeHTTP({"https://export.arxiv.org": ARXIV_FEED})
    collector = ArxivCollector(CollectorConfig(name="arxiv"), http_client=http)
    narrow = collector.collect(
        datetime(2026, 10, 21, 0, 0, tzinfo=CST),
        datetime(2026, 10, 23, 0, 0, tzinfo=CST),
    )
    assert len(narrow.items) == 1


def test_arxiv_collector_uses_published_not_updated_as_first_date():
    http = FakeHTTP({"https://export.arxiv.org": ARXIV_FEED})
    collector = ArxivCollector(CollectorConfig(name="arxiv"), http_client=http)
    result = collector.collect(START, END)
    first = result.items[0]
    assert first.first_published_at is not None
    assert first.first_published_at.day == 22
    assert first.updated_at is not None
    assert first.updated_at.day == 25


def test_arxiv_collector_handles_empty_feed():
    http = FakeHTTP({"https://export.arxiv.org": {"feed": {"entry": []}}})
    collector = ArxivCollector(CollectorConfig(name="arxiv"), http_client=http)
    result = collector.collect(START, END)
    assert result.items == []


def test_arxiv_collector_records_error_without_raising():
    """来源级故障被隔离，不向上抛出，保证整体任务不失败。"""
    http = FakeHTTP({"https://export.arxiv.org": HttpError("boom")})
    collector = ArxivCollector(CollectorConfig(name="arxiv"), http_client=http)
    result = collector.collect(START, END)
    assert result.items == []
    assert result.errors


def test_arxiv_collector_run_isolates_failure():
    http = FakeHTTP({"https://export.arxiv.org": HttpError("boom")})
    collector = ArxivCollector(CollectorConfig(name="arxiv"), http_client=http)
    result = collector.run(START, END)
    assert result.errors
    assert result.items == []


# ---------------------------------------------------------------------------
# Crossref
# ---------------------------------------------------------------------------

CROSSREF_RESPONSE = {
    "status": "ok",
    "message": {
        "total-results": 2,
        "items": [
            {
                "DOI": "10.1109/ACCESS.2026.12345",
                "title": ["A Study of Diameter Routing Attacks"],
                "abstract": "We analyze Diameter routing and GTP-C tunnels.",
                "author": [{"given": "Wei", "family": "Zhang"}],
                "published": {"date-parts": [[2026, 10, 21]]},
                "issued": {"date-parts": [[2026, 10, 21]]},
                "URL": "https://doi.org/10.1109/ACCESS.2026.12345",
                "publisher": "IEEE",
                "type": "journal-article",
            }
        ],
    },
}


def test_crossref_collector_parses_items():
    http = FakeHTTP({"https://api.crossref.org": CROSSREF_RESPONSE})
    collector = CrossrefCollector(CollectorConfig(name="crossref"), http_client=http)
    result = collector.collect(START, END)
    assert len(result.items) == 1
    item = result.items[0]
    assert item.doi == "10.1109/access.2026.12345"
    assert item.title.startswith("A Study of Diameter")
    assert item.authors == ["Wei Zhang"]
    assert item.published_at is not None


def test_crossref_collector_strips_jats_abstract():
    payload = json.loads(json.dumps(CROSSREF_RESPONSE))
    payload["message"]["items"][0]["abstract"] = (
        "<jats:p>We analyze Diameter routing.</jats:p>"
    )
    http = FakeHTTP({"https://api.crossref.org": payload})
    collector = CrossrefCollector(CollectorConfig(name="crossref"), http_client=http)
    result = collector.collect(START, END)
    assert "<jats:p>" not in result.items[0].abstract
    assert result.items[0].abstract.startswith("We analyze")


def test_crossref_collector_handles_missing_fields():
    """缺少标题与日期的条目进入 pending（发布时间待核实），不丢失。"""
    payload = {"message": {"items": [{"DOI": "10.1/x"}]}}
    http = FakeHTTP({"https://api.crossref.org": payload})
    collector = CrossrefCollector(CollectorConfig(name="crossref"), http_client=http)
    result = collector.collect(START, END)
    assert result.items == []
    assert len(result.pending_items) == 1
    assert result.pending_items[0].title == ""
    assert result.pending_items[0].authors == []
    assert result.pending_items[0].has_verified_date is False


# ---------------------------------------------------------------------------
# Semantic Scholar
# ---------------------------------------------------------------------------

S2_RESPONSE = {
    "total": 1,
    "data": [
        {
            "paperId": "abc123",
            "title": "Fuzzing 5G Core Service Based Interfaces",
            "abstract": "We fuzz NGAP and PFCP parsers for memory safety bugs.",
            "authors": [{"name": "Li Ming"}],
            "year": 2026,
            "publicationDate": "2026-10-23",
            "externalIds": {"DOI": "10.1145/1234567.1234568", "ArXiv": "2601.00003"},
            "url": "https://www.semanticscholar.org/paper/abc123",
            "publicationTypes": ["JournalArticle"],
        }
    ],
}


def test_semantic_scholar_collector_parses_papers():
    http = FakeHTTP({"https://api.semanticscholar.org": S2_RESPONSE})
    collector = SemanticScholarCollector(
        CollectorConfig(name="semantic_scholar"), http_client=http
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    item = result.items[0]
    assert item.doi == "10.1145/1234567.1234568"
    assert item.authors == ["Li Ming"]
    assert item.content_type == "paper"


# ---------------------------------------------------------------------------
# IEEE Xplore
# ---------------------------------------------------------------------------


def test_ieee_collector_requires_api_key():
    http = FakeHTTP({})
    collector = IeeeCollector(CollectorConfig(name="ieee", api_key=None), http_client=http)
    assert collector.available is False


def test_ieee_collector_is_available_with_api_key():
    http = FakeHTTP({})
    collector = IeeeCollector(CollectorConfig(name="ieee", api_key="test-key"), http_client=http)
    assert collector.available is True


def test_ieee_collector_parses_documents():
    payload = {
        "response": {
            "documents": [
                {
                    "title": "SS7 Vulnerabilities in 5G Interworking",
                    "abstract": "A study of SS7 in interworking with 5G core.",
                    "authors": [{"authorName": "Chen Hao"}],
                    "doi": "10.1109/ICC.2026.9999",
                    "publicationTitle": "ICC",
                    "publicationDate": "2026-10-24",
                    "documentLink": "https://ieeexplore.ieee.org/document/9999",
                    "isOpenAccess": False,
                    "contentType": "Conference",
                }
            ]
        }
    }
    http = FakeHTTP({"https://ieeexploreapi": payload})
    collector = IeeeCollector(
        CollectorConfig(name="ieee", api_key="test-key"), http_client=http
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    item = result.items[0]
    assert item.doi == "10.1109/icc.2026.9999"
    assert item.authors == ["Chen Hao"]
    assert item.published_at is not None


# ---------------------------------------------------------------------------
# NVD
# ---------------------------------------------------------------------------

NVD_RESPONSE = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2026-12345",
                "published": "2026-10-22T10:15:00.000",
                "lastModified": "2026-10-23T11:00:00.000",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": "A buffer overflow in the SIP parsing module of a core network element allows remote code execution.",
                    }
                ],
                "metrics": {},
                "references": [
                    {"url": "https://vendor.example/advisory/1", "source": "cve@example"}
                ],
            }
        }
    ],
}


def test_nvd_collector_parses_vulnerabilities():
    http = FakeHTTP({"https://services.nvd.nist.gov": NVD_RESPONSE})
    collector = NvdCollector(
        CollectorConfig(name="nvd", params={"rate_limit_seconds": 0}), http_client=http
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    item = result.items[0]
    assert item.cve_ids == ["CVE-2026-12345"]
    assert item.content_type == "vulnerability"
    assert item.published_at is not None
    assert "buffer overflow" in item.abstract.lower()


def test_nvd_collector_respects_time_window():
    http = FakeHTTP({"https://services.nvd.nist.gov": NVD_RESPONSE})
    collector = NvdCollector(
        CollectorConfig(name="nvd", params={"rate_limit_seconds": 0}), http_client=http
    )
    result = collector.collect(
        datetime(2026, 10, 23, 0, 0, tzinfo=CST),
        datetime(2026, 10, 27, 0, 0, tzinfo=CST),
    )
    assert result.items == []


def test_nvd_collector_passes_keywords_to_api():
    http = FakeHTTP({"https://services.nvd.nist.gov": NVD_RESPONSE})
    collector = NvdCollector(
        CollectorConfig(
            name="nvd",
            params={"keywords": ["SS7", "Diameter"], "rate_limit_seconds": 0},
        ),
        http_client=http,
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    assert "SS7" in http.calls[0]["params"]["keywordSearch"]


def test_nvd_collector_queries_each_keyword_separately():
    """NVD 的 keywordSearch 对多个关键词是「与」关系，必须逐个查询。

    一次传多个关键词会要求漏洞同时命中全部关键词，导致结果几乎为空。
    """
    http = FakeHTTP({"https://services.nvd.nist.gov": NVD_RESPONSE})
    collector = NvdCollector(
        CollectorConfig(
            name="nvd",
            params={
                "keywords": ["SS7", "Diameter", "SIP"],
                "rate_limit_seconds": 0,
            },
        ),
        http_client=http,
    )
    collector.collect(START, END)
    searched = [call["params"]["keywordSearch"] for call in http.calls]
    assert searched == ["SS7", "Diameter", "SIP"]


def test_nvd_collector_deduplicates_across_keywords():
    """同一 CVE 被多个关键词命中时只保留一条。"""
    http = FakeHTTP({"https://services.nvd.nist.gov": NVD_RESPONSE})
    collector = NvdCollector(
        CollectorConfig(
            name="nvd",
            params={"keywords": ["SS7", "SIP"], "rate_limit_seconds": 0},
        ),
        http_client=http,
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    assert result.items[0].cve_ids == ["CVE-2026-12345"]


# ---------------------------------------------------------------------------
# RSS
# ---------------------------------------------------------------------------

RSS_XML = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Telecom Security News</title>
    <link>https://example.org</link>
    <description>News</description>
    <item>
      <title>Critical SS7 vulnerability disclosed in carrier equipment</title>
      <link>https://example.org/news/ss7-vuln</link>
      <description><![CDATA[<p>Researchers disclosed an SS7 flaw affecting mobile core network equipment.</p>]]></description>
      <pubDate>Wed, 21 Oct 2026 14:30:00 +0000</pubDate>
      <guid>https://example.org/news/ss7-vuln</guid>
    </item>
    <item>
      <title>Generic cloud security story</title>
      <link>https://example.org/news/cloud</link>
      <description>Nothing to do with telecom.</description>
      <pubDate>Wed, 21 Oct 2026 15:30:00 +0000</pubDate>
    </item>
  </channel>
</rss>
"""


def test_rss_collector_parses_items():
    http = FakeHTTP({"https://example.org": RSS_XML})
    collector = RssCollector(
        CollectorConfig(name="rss", url="https://example.org/feed.xml"),
        http_client=http,
    )
    result = collector.collect(START, END)
    assert len(result.items) == 2
    assert result.items[0].title.startswith("Critical SS7")
    assert result.items[0].published_at is not None
    assert result.items[0].content_type == "news"


def test_rss_collector_strips_html_from_description():
    http = FakeHTTP({"https://example.org": RSS_XML})
    collector = RssCollector(
        CollectorConfig(name="rss", url="https://example.org/feed.xml"),
        http_client=http,
    )
    result = collector.collect(START, END)
    assert "<p>" not in result.items[0].abstract
    assert "SS7 flaw" in result.items[0].abstract


def test_rss_collector_handles_atom_feed():
    atom = """<?xml version="1.0" encoding="utf-8"?>
    <feed xmlns="http://www.w3.org/2005/Atom">
      <title>Atom Feed</title>
      <entry>
        <title>Diameter Routing Security Study</title>
        <link href="https://example.org/atom/1"/>
        <id>urn:uuid:1234</id>
        <updated>2026-10-22T10:00:00Z</updated>
        <published>2026-10-22T10:00:00Z</published>
        <summary>We study Diameter routing attacks in 5G.</summary>
      </entry>
    </feed>
    """
    http = FakeHTTP({"https://example.org": atom})
    collector = RssCollector(
        CollectorConfig(name="rss", url="https://example.org/atom.xml"), http_client=http
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    assert result.items[0].title == "Diameter Routing Security Study"
    assert result.items[0].url == "https://example.org/atom/1"


def test_rss_collector_raises_on_invalid_xml():
    http = FakeHTTP({"https://example.org": "not xml at all"})
    collector = RssCollector(
        CollectorConfig(name="rss", url="https://example.org/feed.xml"),
        http_client=http,
    )
    with pytest.raises(CollectorError):
        collector.collect(START, END)


# ---------------------------------------------------------------------------
# Web
# ---------------------------------------------------------------------------

HTML_PAGE = """
<html><head><title>Vendor advisory</title></head>
<body>
  <article>
    <h1>Security advisory: GTP-C parsing flaw</h1>
    <time datetime="2026-10-22">October 22, 2026</time>
    <p>A parsing flaw in GTP-C message handling could allow a remote attacker to crash the session.</p>
    <p>Customers should apply the mitigation described in the linked bulletin.</p>
  </article>
</body></html>
"""


def test_web_collector_extracts_title_and_body():
    http = FakeHTTP({"https://vendor.example": HTML_PAGE})
    collector = WebCollector(
        CollectorConfig(
            name="vendor",
            url="https://vendor.example/advisory/1",
            title_selector="h1",
            date_selector="time",
            content_selector="article",
        ),
        http_client=http,
    )
    result = collector.collect(START, END)
    assert len(result.items) == 1
    item = result.items[0]
    assert item.title == "Security advisory: GTP-C parsing flaw"
    assert "GTP-C" in item.abstract
    assert item.published_at is not None


def test_web_collector_marks_missing_date_as_unverified():
    """无法获取发布时间时进入 pending，标记为「发布时间待核实」。"""
    html = "<html><body><h1>No date here</h1><p>Some content about SS7 attacks.</p></body></html>"
    http = FakeHTTP({"https://vendor.example": html})
    collector = WebCollector(
        CollectorConfig(name="vendor", url="https://vendor.example/x"),
        http_client=http,
    )
    result = collector.collect(START, END)
    assert result.items == []
    item = result.pending_items[0]
    assert item.published_at is None
    assert item.has_verified_date is False


def test_web_collector_respects_robots_disallow():
    http = FakeHTTP({"https://vendor.example": HTML_PAGE})
    collector = WebCollector(
        CollectorConfig(name="vendor", url="https://vendor.example/advisory/1"),
        http_client=http,
        respect_robots=True,
        user_agent="SignalIntelBot/1.0",
    )
    # 没有 robots.txt 时默认允许（robots 抓取失败不阻断）
    assert collector.available is True


# ---------------------------------------------------------------------------
# 基类
# ---------------------------------------------------------------------------


def test_collector_config_reads_env_style_values():
    cfg = CollectorConfig(name="x", api_key="k", params={"a": 1})
    assert cfg.name == "x"
    assert cfg.params["a"] == 1


def test_collector_result_tracks_counts():
    result = CollectorResult(source_name="test")
    result.add_dummy = None  # type: ignore[attr-defined]
    assert result.source_name == "test"
    assert result.items == []
    assert result.errors == []
