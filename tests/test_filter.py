"""关键词召回筛选相关测试。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any

from signalintel.models import IntelItem
from signalintel.processors.filter import KeywordFilter, KeywordConfig

CST = timezone(timedelta(hours=8))


def _item(**kwargs: Any) -> IntelItem:
    base: dict[str, Any] = dict(
        source="arXiv",
        source_type="paper",
        title="A Study of Something",
        url="https://arxiv.org/abs/2601.00001",
        abstract="",
        published_at=datetime(2026, 10, 20, 8, 0, tzinfo=CST),
    )
    base.update(kwargs)
    return IntelItem(**base)


def _config() -> KeywordConfig:
    return KeywordConfig(
        protocols=["SS7", "GTP-C", "PFCP", "SIP", "IMS", "5G Core", "NAS", "NGAP"],
        network_elements=["MME", "HSS", "PCRF", "AMF", "SMF", "UPF", "AUSF", "UDM", "UDR", "PCF", "NRF"],
        attack_types=[
            "signaling attack",
            "protocol fuzzing",
            "authentication bypass",
            "location tracking",
            "IMSI catcher",
        ],
        topics=[
            "signaling security",
            "telecom security",
            "core network security",
            "roaming security",
            "interconnect security",
        ],
        chinese_keywords=["信令安全", "核心网", "漫游攻击", "协议漏洞"],
        exclusions=["ransomware", "phishing attack", "ransom ware"],
        ambiguous=["Diameter", "MAP"],
        context_keywords=["5G Core", "telecom", "mobile core", "subscriber"],
        min_matches=1,
    )


def test_keyword_filter_matches_protocol_in_title():
    flt = KeywordFilter(_config())
    item = _item(title="SS7 Attacks Against Mobile Core Networks")
    result = flt.evaluate(item)
    assert result.matched
    assert "SS7" in result.matched_keywords


def test_keyword_filter_matches_protocol_in_abstract_not_title():
    flt = KeywordFilter(_config())
    item = _item(
        title="A Study of Legacy Telecom Protocols",
        abstract="We fuzz GTP-C messages in the AMF and detect memory corruption.",
    )
    result = flt.evaluate(item)
    assert result.matched
    assert "GTP-C" in result.matched_keywords


def test_keyword_filter_matches_chinese_keyword():
    flt = KeywordFilter(_config())
    item = _item(title="5G核心网信令安全防护技术综述", abstract="")
    result = flt.evaluate(item)
    assert result.matched
    assert "信令安全" in result.matched_keywords


def test_keyword_filter_is_case_insensitive():
    """长关键词大小写不敏感。"""
    flt = KeywordFilter(_config())
    item = _item(title="SIGNALING ATTACK deployment analysis")
    assert flt.evaluate(item).matched


def test_protocol_acronyms_require_uppercase():
    """协议缩写必须全大写，避免 map / sip / nas 等普通词误命中。"""
    flt = KeywordFilter(_config())
    lowercase = _item(
        title="memory access protection in the map data structure",
        abstract="A study of the map data structure and sip handling.",
    )
    result = flt.evaluate(lowercase)
    assert not result.matched

    uppercase = _item(
        title="MAP and SIP attacks in the mobile core network",
        abstract="We study MAP operations and SIP routing attacks.",
    )
    assert flt.evaluate(uppercase).matched


def test_keyword_filter_rejects_generic_security_content():
    flt = KeywordFilter(_config())
    item = _item(
        title="Critical Buffer Overflow in Popular Web Browser",
        abstract="A heap overflow in image parsing allows remote code execution.",
    )
    assert not flt.evaluate(item).matched


def test_keyword_filter_rejects_content_matching_exclusion():
    flt = KeywordFilter(_config())
    item = _item(
        title="Phishing attack on Diameter operators",
        abstract="Phishing attack targets carrier staff credentials.",
    )
    result = flt.evaluate(item)
    assert not result.matched
    assert result.excluded_by


def test_keyword_filter_exclusion_takes_precedence_over_signal():
    flt = KeywordFilter(_config())
    item = _item(
        title="SS7 signal and ransomware campaign",
        abstract="Ransomware targeted a carrier.",
    )
    result = flt.evaluate(item)
    assert not result.matched
    assert result.excluded_by


def test_keyword_filter_requires_minimum_matches():
    config = _config()
    config.min_matches = 2
    flt = KeywordFilter(config)
    item = _item(title="SS7 study", abstract="")
    result = flt.evaluate(item)
    assert not result.matched
    assert result.match_count == 1


def test_keyword_filter_counts_distinct_matched_keywords():
    flt = KeywordFilter(_config())
    item = _item(title="SS7 and Diameter attacks on 5G Core", abstract="")
    result = flt.evaluate(item)
    assert result.match_count >= 3


def test_keyword_filter_weights_title_higher_than_abstract():
    flt = KeywordFilter(_config())
    in_title = flt.evaluate(_item(title="SS7 attack", abstract=""))
    in_abstract = flt.evaluate(
        _item(title="Unrelated research", abstract="mentions SS7 once")
    )
    assert in_title.weight > in_abstract.weight


def test_keyword_filter_handles_empty_abstract():
    flt = KeywordFilter(_config())
    result = flt.evaluate(_item(title="", abstract=""))
    assert not result.matched


def test_keyword_filter_handles_none_abstract():
    flt = KeywordFilter(_config())
    item = _item(title="GTP-C tunnel hardening", abstract="")
    item.abstract = ""
    result = flt.evaluate(item)
    assert result.matched


def test_filter_keeps_telecom_cve_items():
    """电信相关漏洞应保留（编号 + 电信语境）。"""
    flt = KeywordFilter(_config())
    item = _item(
        title="CVE-2026-12345: SIP parsing overflow in mobile core network",
        abstract="A stack overflow in the SIP message parser of an MME allows RCE.",
        cve_ids=["CVE-2026-12345"],
    )
    result = flt.evaluate(item)
    assert result.matched
    assert "CVE-2026-12345" in result.matched_keywords


def test_filter_rejects_non_telecom_cve_items():
    """非电信漏洞不应仅凭 CVE 编号放行。

    NVD 检索结果里混有大量 Linux 内核 / 蓝牙 / Web 应用漏洞，
    无条件放行会让报告退化成通用漏洞列表。
    """
    flt = KeywordFilter(_config())
    item = _item(
        title="CVE-2026-98949: Linux kernel drm/imagination reference handling",
        abstract="In the Linux kernel, the following vulnerability has been resolved: "
        "drm/imagination: Fix reference and vm_bo handling in remap().",
        cve_ids=["CVE-2026-98949"],
    )
    result = flt.evaluate(item)
    assert not result.matched


def test_ambiguous_keyword_requires_telecom_context():
    """Diameter 在材料科学语境中含义完全不同，必须有电信上下文才算召回。"""
    flt = KeywordFilter(_config())
    chemistry = _item(
        title="Diameter Control of Core/Shell Nanorods for Tunable Band Gaps",
        abstract="We synthesize nanorods and control their diameter.",
    )
    result = flt.evaluate(chemistry)
    assert not result.matched
    assert "Diameter" not in result.matched_keywords


def test_ambiguous_keyword_matches_in_telecom_context():
    flt = KeywordFilter(_config())
    telecom = _item(
        title="Diameter Routing Attacks in 5G Core",
        abstract="We study Diameter message abuse in the 5G Core.",
    )
    result = flt.evaluate(telecom)
    assert result.matched
    assert "Diameter" in result.matched_keywords


def test_ambiguous_keyword_not_counted_toward_min_matches():
    config = _config()
    config.min_matches = 1
    flt = KeywordFilter(config)
    chemistry = _item(
        title="Diameter Control of Nanorods",
        abstract="Nanorod synthesis study.",
    )
    result = flt.evaluate(chemistry)
    assert result.match_count == 0


def test_keyword_config_loads_from_yaml_mapping():
    config = KeywordConfig.from_mapping(
        {
            "protocols": ["SS7"],
            "network_elements": ["AMF"],
            "attack_types": ["fuzzing"],
            "topics": ["signaling security"],
            "chinese_keywords": ["信令"],
            "exclusions": ["ransomware"],
            "min_matches": 1,
        }
    )
    assert config.protocols == ["SS7"]
    assert config.min_matches == 1


def test_keyword_config_handles_missing_sections():
    config = KeywordConfig.from_mapping({})
    assert config.protocols == []
    assert config.min_matches == 1
