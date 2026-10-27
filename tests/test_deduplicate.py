"""去重与事件合并相关测试。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from signalintel.models import IntelItem, SourceLink
from signalintel.processors.deduplicate import (
    Deduplicator,
    extract_cve_ids,
    normalize_doi,
    normalize_title,
    normalize_url,
    title_similarity,
)

CST = timezone(timedelta(hours=8))


def _item(**kwargs) -> IntelItem:
    base = dict(
        source="arXiv",
        source_type="paper",
        title="SS7 Attack Analysis in Mobile Core Networks",
        url="https://arxiv.org/abs/2601.00001",
        published_at=datetime(2026, 10, 20, 8, 0, tzinfo=CST),
    )
    base.update(kwargs)
    return IntelItem(**base)


# --------------------------------------------------------------------------
# URL 规范化
# --------------------------------------------------------------------------


def test_normalize_url_removes_tracking_query_and_fragment():
    url = "https://Example.com/Path/?utm_source=rss&utm_medium=feed&id=42#section"
    assert normalize_url(url) == "https://example.com/Path?id=42"


def test_normalize_url_strips_trailing_slash_and_default_ports():
    assert normalize_url("https://example.com:443/news/") == "https://example.com/news"
    assert normalize_url("http://example.com:80/news") == "https://example.com/news"


def test_normalize_url_treats_http_and_https_as_same_resource():
    """http/https 视为同一资源，这是去重所需的语义。"""
    assert normalize_url("http://example.com/news") == normalize_url(
        "https://example.com/news"
    )


def test_normalize_url_removes_www_prefix():
    assert normalize_url("https://www.example.com/a") == "https://example.com/a"


def test_normalize_url_handles_empty():
    assert normalize_url("") == ""
    assert normalize_url(None) == ""


# --------------------------------------------------------------------------
# DOI / CVE
# --------------------------------------------------------------------------


def test_normalize_doi_strips_url_prefix():
    assert normalize_doi("https://doi.org/10.1109/ACCESS.2026.12345") == "10.1109/access.2026.12345"
    assert normalize_doi("doi:10.1145/3290607.3299036") == "10.1145/3290607.3299036"


def test_normalize_doi_returns_none_for_empty():
    assert normalize_doi("") is None
    assert normalize_doi(None) is None


def test_extract_cve_ids_finds_multiple():
    text = "See CVE-2026-12345 and cve-2026-99999 plus CVE-2026-1234."
    ids = extract_cve_ids(text)
    assert "CVE-2026-12345" in ids
    assert "CVE-2026-99999" in ids
    assert "CVE-2026-1234" in ids


def test_extract_cve_ids_normalizes_case():
    assert extract_cve_ids("cve-2026-12345") == ["CVE-2026-12345"]


def test_extract_cve_ids_returns_empty_when_absent():
    assert extract_cve_ids("nothing here") == []


# --------------------------------------------------------------------------
# 标题相似度
# --------------------------------------------------------------------------


def test_normalize_title_lowercases_and_strips_punctuation():
    assert normalize_title("SS7 Attacks: A Study!") == "ss7 attacks a study"


def test_title_similarity_identical_titles_high():
    a = "A Novel SS7 Attack Against Mobile Core Networks"
    b = "A novel SS7 attack against mobile core networks"
    assert title_similarity(a, b) >= 0.95


def test_title_similarity_different_titles_low():
    a = "A Novel SS7 Attack Against Mobile Core Networks"
    b = "Quantum Error Correction on Silicon Qubits"
    assert title_similarity(a, b) < 0.4


def test_title_similarity_is_symmetric():
    a = "Diameter Routing Attacks in 5G"
    b = "Attacks on Diameter Routing in 5G Networks"
    assert title_similarity(a, b) == title_similarity(b, a)


def test_title_similarity_handles_empty():
    assert title_similarity("", "abc") == 0.0
    assert title_similarity("abc", "") == 0.0


# --------------------------------------------------------------------------
# 去重器
# --------------------------------------------------------------------------


def test_deduplicator_keeps_first_and_drops_same_doi():
    dedup = Deduplicator()
    first = _item(doi="10.1109/ACCESS.2026.12345")
    second = _item(
        source="IEEE Xplore",
        title="Totally Different Title About Diameter",
        url="https://ieeexplore.ieee.org/document/12345678",
        doi="10.1109/ACCESS.2026.12345",
    )
    assert dedup.add(first) is True
    assert dedup.add(second) is False
    assert len(dedup.items) == 1


def test_deduplicator_keeps_first_and_drops_same_normalized_url():
    dedup = Deduplicator()
    first = _item(url="https://www.example.com/report/?utm_source=twitter")
    second = _item(
        source="Other",
        title="Another Title",
        url="https://example.com/report",
    )
    assert dedup.add(first) is True
    assert dedup.add(second) is False


def test_deduplicator_merges_same_cve_from_multiple_sources():
    dedup = Deduplicator()
    first = _item(
        source="NVD",
        source_type="vulnerability",
        title="CVE-2026-12345 in SIP stack",
        url="https://nvd.nist.gov/vuln/detail/CVE-2026-12345",
        cve_ids=["CVE-2026-12345"],
    )
    second = _item(
        source="The Hacker News",
        source_type="news",
        title="Critical flaw found in telecom SIP stack",
        url="https://thehackernews.com/2026/10/sip-flaw.html",
        cve_ids=["CVE-2026-12345"],
    )
    assert dedup.add(first) is True
    assert dedup.add(second) is False
    merged = dedup.items[0]
    assert len(merged.alternate_sources) == 1
    assert merged.alternate_sources[0].source == "The Hacker News"


def test_deduplicator_merges_similar_titles_into_one_event():
    dedup = Deduplicator()
    first = _item(
        source="Reuters",
        source_type="news",
        title="Major SS7 attack hits European carrier",
        url="https://reuters.com/tech/ss7-attack-2026",
    )
    second = _item(
        source="BleepingComputer",
        source_type="news",
        title="Major SS7 attack hits European carrier",
        url="https://bleepingcomputer.com/news/security/ss7-attack-2026/",
    )
    assert dedup.add(first) is True
    assert dedup.add(second) is False
    assert len(dedup.items) == 1
    assert len(dedup.items[0].alternate_sources) == 1


def test_deduplicator_keeps_distinct_items():
    dedup = Deduplicator()
    assert dedup.add(_item()) is True
    assert (
        dedup.add(
            _item(
                title="Diameter Routing Attacks in 5G Core Networks",
                url="https://arxiv.org/abs/2601.00002",
            )
        )
        is True
    )
    assert len(dedup.items) == 2


def test_deduplicator_prefers_item_with_richer_content_as_primary():
    dedup = Deduplicator()
    thin = _item(title="SS7 attacks in core network", abstract="short")
    rich = _item(
        source="arXiv",
        title="SS7 attacks in core network",
        abstract="A" * 500,
        url="https://arxiv.org/abs/2601.99999",
    )
    dedup.add(thin)
    dedup.add(rich)
    assert len(dedup.items) == 1
    assert len(dedup.items[0].abstract) == 500


def test_deduplicator_does_not_merge_when_no_shared_identifiers():
    dedup = Deduplicator()
    dedup.add(_item(title="Fuzzing Diameter Messages for Memory Bugs"))
    dedup.add(
        _item(
            title="Fuzzing SIP Message Parsers for Memory Bugs",
            url="https://arxiv.org/abs/2601.00003",
        )
    )
    assert len(dedup.items) == 2


def test_merged_item_keeps_all_source_links():
    dedup = Deduplicator()
    dedup.add(_item(cve_ids=["CVE-2026-12345"]))
    dedup.add(
        _item(
            source="Vendor",
            title="Vendor advisory for CVE-2026-12345",
            url="https://vendor.example/advisory/12345",
            cve_ids=["CVE-2026-12345"],
        )
    )
    merged = dedup.items[0]
    links = [merged.url] + [link.url for link in merged.alternate_sources]
    assert len(links) == 2
    assert len(set(links)) == 2


def test_alternate_source_link_carries_metadata():
    link = SourceLink(source="CISA", title="Advisory", url="https://cisa.gov/x")
    assert link.source == "CISA"
    assert link.url == "https://cisa.gov/x"
