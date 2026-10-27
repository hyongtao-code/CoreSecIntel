"""HTML 报告生成测试。"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone

from signalintel.models import IntelItem, SourceLink
from signalintel.reports.html_report import (
    ReportBuilder,
    ReportData,
    build_subject,
    render_html,
)

CST = timezone(timedelta(hours=8))


def _paper(**kwargs) -> IntelItem:
    base = dict(
        source="arXiv",
        source_type="paper",
        title="SS7 Attack Analysis in Mobile Core Networks",
        title_cn="移动核心网中的 SS7 攻击分析",
        url="https://arxiv.org/abs/2601.00001",
        abstract="We study SS7 attacks against the HLR.",
        authors=["Alice Zhang", "Bob Li"],
        content_type="preprint",
        published_at=datetime(2026, 10, 20, 8, 0, tzinfo=CST),
        doi="10.48550/arXiv.2601.00001",
        is_preprint=True,
        trust_score=0.85,
        priority="P1",
        score=82.5,
        score_reasons=["专业相关性 85/100", "技术新颖性 70/100"],
        relevance_keywords=["SS7", "Diameter"],
        summary_cn="本文系统分析了 SS7 协议在移动核心网中的攻击面……",
        attack_surface="MSC、HLR、VLR",
        technique="协议状态机建模与模糊测试",
        impact="可导致用户位置信息泄露与呼叫劫持",
        significance="对运营商信令防火墙部署有直接参考价值",
        recommendations="部署信令防火墙并对关键字段做合法性校验",
        confidence_note="未提及",
    )
    base.update(kwargs)
    return IntelItem(**base)


def _news(**kwargs) -> IntelItem:
    base = dict(
        source="The Hacker News",
        source_type="news",
        title="Critical flaw found in telecom SIP parsing",
        title_cn="电信 SIP 解析中发现严重漏洞",
        url="https://thehackernews.com/2026/10/sip-flaw.html",
        abstract="A critical flaw affects carrier SIP equipment.",
        authors=[],
        content_type="news",
        published_at=datetime(2026, 10, 22, 8, 0, tzinfo=CST),
        cve_ids=["CVE-2026-12345"],
        trust_score=0.7,
        priority="P1",
        score=76.0,
        score_reasons=["安全影响 90/100"],
        relevance_keywords=["SIP"],
        summary_cn="安全媒体披露了电信 SIP 解析组件中的严重漏洞……",
        attack_surface="SIP 解析组件",
        technique="畸形报文触发内存破坏",
        impact="远程代码执行",
        significance="影响运营商核心网信令面",
        recommendations="核查厂商补丁状态",
        confidence_note="以厂商公告为准",
    )
    base.update(kwargs)
    return IntelItem(**base)


def _report_data(**kwargs) -> ReportData:
    base = dict(
        window_start=datetime(2026, 10, 20, 0, 0, tzinfo=CST),
        window_end=datetime(2026, 10, 27, 0, 0, tzinfo=CST),
        timezone="Asia/Shanghai",
        sources_ok=6,
        sources_failed=1,
        candidates=42,
        after_dedup=30,
        after_filter=18,
        p1_count=4,
        p2_count=7,
        p3_count=7,
        pending_count=2,
        p1_items=[_paper()],
        p2_items=[_news()],
        p3_items=[],
        observations=["Diameter 相关的攻击研究数量上升。"],
        report_date="2026-10-27",
    )
    base.update(kwargs)
    return ReportData(**base)


# ---------------------------------------------------------------------------
# 主题
# ---------------------------------------------------------------------------


def test_build_subject_includes_date_and_counts():
    subject = build_subject("2026-10-27", paper_count=5, intel_count=12)
    assert "2026-10-27" in subject
    assert "5" in subject
    assert "12" in subject
    assert subject.startswith("【核心网信令安全周报】")


# ---------------------------------------------------------------------------
# HTML 渲染
# ---------------------------------------------------------------------------


def test_render_html_contains_chinese_title():
    html = render_html(_report_data())
    assert "核心网信令安全" in html


def test_render_html_contains_overview_stats():
    html = render_html(_report_data())
    assert "2026-10-20" in html
    assert "2026-10-27" in html
    assert "18" in html  # 去重后有效内容数


def test_render_html_contains_item_titles_and_links():
    html = render_html(_report_data())
    assert "移动核心网中的 SS7 攻击分析" in html
    assert "SS7 Attack Analysis in Mobile Core Networks" in html
    assert "https://arxiv.org/abs/2601.00001" in html


def test_render_html_contains_cve_id():
    html = render_html(_report_data())
    assert "CVE-2026-12345" in html


def test_render_html_contains_doi():
    html = render_html(_report_data())
    assert "10.48550/arXiv.2601.00001" in html


def test_render_html_contains_all_required_sections():
    html = render_html(_report_data())
    for section in (
        "本期概览",
        "高优先级情报",
        "学术论文精选",
        "安全新闻与漏洞公告",
        "本期技术观察",
        "来源索引",
    ):
        assert section in html, f"缺少章节: {section}"


def test_render_html_contains_observations():
    html = render_html(_report_data())
    assert "Diameter 相关的攻击研究数量上升" in html


def test_render_html_contains_disclaimer_for_observations():
    html = render_html(_report_data())
    assert "基于本期样本" in html


def test_render_html_is_valid_minimal_structure():
    html = render_html(_report_data())
    assert html.strip().startswith("<!DOCTYPE html>")
    assert "</html>" in html
    assert "<meta charset=\"utf-8\"" in html or "<meta charset='utf-8'" in html


def test_render_html_uses_inline_styles_for_email_compat():
    """邮件客户端普遍不支持 <style> 块与外部 CSS。"""
    html = render_html(_report_data())
    assert "style=" in html


def test_render_html_uses_table_layout():
    """表格布局在 Outlook / Gmail 中兼容性最好。"""
    html = render_html(_report_data())
    assert "<table" in html


def test_render_html_handles_empty_report():
    data = _report_data(
        p1_items=[], p2_items=[], p3_items=[], observations=[], after_filter=0
    )
    html = render_html(data)
    assert "本期无高优先级更新" in html


def test_render_html_handles_missing_summary_fields():
    item = _paper(summary_cn="", attack_surface="", technique="")
    html = render_html(_report_data(p1_items=[item]))
    assert "未提及" in html


def test_render_html_escapes_html_in_content():
    """外部内容必须转义，防止 HTML 注入。"""
    item = _paper(
        title="<script>alert('xss')</script>",
        title_cn="<script>alert('xss')</script>",
        summary_cn="<img src=x onerror=alert(1)>",
    )
    html = render_html(_report_data(p1_items=[item]))
    assert "<script>alert" not in html
    assert "&lt;script&gt;" in html
    assert "<img src=x onerror" not in html


def test_render_html_escapes_href_javascript_scheme():
    item = _paper(url="javascript:alert(1)")
    html = render_html(_report_data(p1_items=[item]))
    assert "javascript:" not in html


def test_render_html_shows_alternate_sources():
    item = _paper(
        alternate_sources=[
            SourceLink(
                source="BleepingComputer",
                title="Related coverage",
                url="https://bleepingcomputer.com/x",
            )
        ]
    )
    html = render_html(_report_data(p1_items=[item]))
    assert "BleepingComputer" in html
    assert "https://bleepingcomputer.com/x" in html


def test_render_html_shows_preprint_marker():
    html = render_html(_report_data(p1_items=[_paper(is_preprint=True)]))
    assert "预印本" in html


def test_render_html_shows_pending_date_note():
    data = _report_data(pending_count=3)
    html = render_html(data)
    assert "发布时间待核实" in html


def test_render_html_source_index_lists_all_items():
    html = render_html(_report_data())
    index_section = html.split("来源索引")[-1]
    assert "arXiv" in index_section
    assert "The Hacker News" in index_section


def test_render_html_has_no_unrendered_jinja_markers():
    html = render_html(_report_data())
    assert "{{" not in html
    assert "{%" not in html


def test_report_builder_writes_file(tmp_path):
    builder = ReportBuilder(output_dir=tmp_path)
    path = builder.build(_report_data())
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "核心网信令安全" in content


def test_report_builder_filename_contains_date(tmp_path):
    builder = ReportBuilder(output_dir=tmp_path)
    path = builder.build(_report_data())
    assert "2026-10-27" in path.name


def test_report_builder_overwrites_same_day_report(tmp_path):
    builder = ReportBuilder(output_dir=tmp_path)
    first = builder.build(_report_data())
    second = builder.build(_report_data())
    assert first == second


def test_priority_order_is_p1_p2_p3():
    data = _report_data()
    assert data.p1_items
    assert data.p2_items
    assert data.p3_items == []
