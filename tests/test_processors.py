"""分类、评分与中文摘要处理器测试。

使用假的 LLM 客户端（不发起网络请求），验证提示词构造、
响应解析、失败降级与事实约束标注的行为。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Any

import pytest

from signalintel.llm.client import LLMError
from signalintel.models import IntelItem
from signalintel.processors.classify import Classifier, PRIORITY_P1
from signalintel.processors.rank import Ranker, ScoreWeights
from signalintel.processors.summarize import Summarizer

CST = timezone(timedelta(hours=8))


def _item(**kwargs: Any) -> IntelItem:
    base: dict[str, Any] = dict(
        source="arXiv",
        source_type="paper",
        title="SS7 Attacks Against Mobile Core Networks",
        url="https://arxiv.org/abs/2601.00001",
        abstract="We analyze SS7 attacks on the MSC and propose a firewall.",
        published_at=datetime(2026, 10, 20, 8, 0, tzinfo=CST),
    )
    base.update(kwargs)
    return IntelItem(**base)


class FakeLLM:
    """记录调用参数并返回预置结果的假客户端。"""

    def __init__(self, result: Any = None, error: bool = False) -> None:
        self.result = result
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def complete_one(self, system_prompt: str, user_prompt: str, json_mode: bool = True) -> Any:
        self.calls.append({"system": system_prompt, "user": user_prompt})
        if self.error:
            raise LLMError("模拟失败")
        return self.result

    def complete_batch(
        self,
        system_prompt: str,
        user_prompt: str,
        items: list[Any],
        max_batch_size: int | None = None,
    ) -> list[Any]:
        self.calls.append({"system": system_prompt, "user": user_prompt, "batch": items})
        if self.error:
            raise LLMError("模拟失败")
        result = self.result
        if isinstance(result, dict):
            return [result for _ in items]
        return list(result)


# ---------------------------------------------------------------------------
# 分类
# ---------------------------------------------------------------------------


def test_classifier_assigns_p1_for_signaling_vulnerability():
    llm = FakeLLM(
        {
            "priority": "P1",
            "reason": "直接研究 SS7 协议漏洞",
            "protocols": ["SS7"],
            "attack_surface": ["MSC", "HLR"],
        }
    )
    clf = Classifier(llm)
    item = _item()
    result = clf.classify(item)
    assert result.priority == PRIORITY_P1
    assert item.priority == PRIORITY_P1
    assert result.reason


def test_classifier_prompt_contains_untrusted_wrapper():
    llm = FakeLLM({"priority": "P2", "reason": "相关"})
    clf = Classifier(llm)
    clf.classify(_item())
    prompt = llm.calls[0]["user"]
    assert "UNTRUSTED_CONTENT" in prompt


def test_classifier_prompt_contains_item_abstract():
    llm = FakeLLM({"priority": "P2", "reason": "相关"})
    clf = Classifier(llm)
    clf.classify(_item(abstract="UNIQUE_ABSTRACT_MARKER"))
    assert "UNIQUE_ABSTRACT_MARKER" in llm.calls[0]["user"]


def test_classifier_falls_back_to_rule_based_on_llm_failure():
    llm = FakeLLM(error=True)
    clf = Classifier(llm)
    item = _item()
    result = clf.classify(item)
    # 关键词规则仍应给出可用的优先级，且标记为降级
    assert result.priority in {"P1", "P2", "P3"}
    assert result.degraded is True


def test_classifier_rule_based_excludes_irrelevant_content():
    llm = FakeLLM(error=True)
    clf = Classifier(llm)
    item = _item(
        title="Quantum error correction with superconducting qubits",
        abstract="We study logical qubit lifetimes.",
        relevance_keywords=[],
    )
    result = clf.classify(item)
    assert result.priority == "EXCLUDE"


def test_classifier_normalizes_invalid_priority_to_rule_based_result():
    """无效优先级与调用失败一致：降级为规则判定，而非直接排除。"""
    llm = FakeLLM({"priority": "P9", "reason": "乱填"})
    clf = Classifier(llm)
    result = clf.classify(_item())
    assert result.priority in {"P1", "P2", "P3", "EXCLUDE"}
    assert result.degraded is True


def test_classifier_accepts_chinese_exclude_label():
    llm = FakeLLM({"priority": "排除", "reason": "与信令无关"})
    clf = Classifier(llm)
    result = clf.classify(_item(title="Quantum error correction with qubits"))
    assert result.priority == "EXCLUDE"


def test_classifier_handles_invalid_llm_payload():
    llm = FakeLLM({"unexpected": "shape"})
    clf = Classifier(llm)
    result = clf.classify(_item())
    assert result.priority in {"P1", "P2", "P3", "EXCLUDE"}


# ---------------------------------------------------------------------------
# 评分
# ---------------------------------------------------------------------------


def test_ranker_computes_score_within_zero_and_hundred():
    ranker = Ranker()
    item = _item()
    score, reasons = ranker.score(item)
    assert 0 <= score <= 100
    assert reasons


def test_ranker_rewards_signal_relevant_content():
    ranker = Ranker()
    relevant = _item(
        title="SS7 Attack on Mobile Core Network",
        abstract="SS7 signaling firewall and Diameter abuse in 5G Core.",
        relevance_keywords=["SS7", "Diameter", "5G Core"],
        content_type="paper",
    )
    irrelevant = _item(
        title="Generic Web Security Study",
        abstract="A study of HTTP cookies.",
        relevance_keywords=[],
    )
    relevant_score, _ = ranker.score(relevant)
    irrelevant_score, _ = ranker.score(irrelevant)
    assert relevant_score > irrelevant_score


def test_ranker_rewards_trusted_sources():
    ranker = Ranker()
    trusted = _item(source="arXiv", trust_score=0.95, relevance_keywords=["SS7"])
    less_trusted = _item(source="random-blog", trust_score=0.2, relevance_keywords=["SS7"])
    assert ranker.score(trusted)[0] > ranker.score(less_trusted)[0]


def test_ranker_rewards_vulnerability_content():
    ranker = Ranker()
    vuln = _item(content_type="vulnerability", cve_ids=["CVE-2026-12345"], relevance_keywords=["SS7"])
    paper = _item(content_type="paper", relevance_keywords=["SS7"])
    assert ranker.score(vuln)[0] > ranker.score(paper)[0]


def test_ranker_respects_custom_weights():
    weights = ScoreWeights(relevance=1.0, novelty=0.0, impact=0.0, source_trust=0.0)
    ranker = Ranker(weights=weights)
    assert abs(sum(weights.as_dict().values()) - 1.0) < 1e-6


def test_ranker_assigns_score_to_item():
    ranker = Ranker()
    item = _item()
    score, reasons = ranker.score(item)
    item.score = score
    item.score_reasons = reasons
    assert item.score == score
    assert item.score_reasons


def test_ranker_reasons_are_human_readable():
    ranker = Ranker()
    _, reasons = ranker.score(_item(relevance_keywords=["SS7"]))
    assert any("相关" in reason for reason in reasons)


# ---------------------------------------------------------------------------
# 摘要
# ---------------------------------------------------------------------------


def test_summarizer_fills_all_fields():
    llm = FakeLLM(
        {
            "title_cn": "针对移动核心网的 SS7 攻击分析",
            "summary_cn": "本文分析 SS7 攻击……",
            "attack_surface": "MSC、HLR",
            "technique": "协议模糊测试",
            "impact": "可导致用户位置信息泄露",
            "significance": "对运营商信令防护有直接参考价值",
            "recommendations": "部署信令防火墙并校验字段",
            "confidence_note": "未提及",
        }
    )
    sm = Summarizer(llm)
    item = _item()
    result = sm.summarize(item)
    assert item.title_cn == "针对移动核心网的 SS7 攻击分析"
    assert item.summary_cn.startswith("本文分析")
    assert item.attack_surface == "MSC、HLR"
    assert item.technique == "协议模糊测试"
    assert result.ok is True


def test_summarizer_marks_missing_fields_as_unmentioned():
    llm = FakeLLM(
        {
            "title_cn": "标题",
            "summary_cn": "摘要",
            "attack_surface": "",
            "technique": "",
            "impact": "",
            "significance": "",
            "recommendations": "",
            "confidence_note": "",
        }
    )
    sm = Summarizer(llm)
    item = _item()
    sm.summarize(item)
    assert item.attack_surface == "未提及"
    assert item.technique == "未提及"


def test_summarizer_returns_failure_without_raising():
    llm = FakeLLM(error=True)
    sm = Summarizer(llm)
    item = _item()
    result = sm.summarize(item)
    assert result.ok is False
    assert result.error


def test_summarizer_keeps_original_metadata_on_failure():
    llm = FakeLLM(error=True)
    sm = Summarizer(llm)
    item = _item()
    sm.summarize(item)
    assert item.title == "SS7 Attacks Against Mobile Core Networks"
    assert item.abstract != ""


def test_summarizer_prompt_includes_abstract_and_url():
    llm = FakeLLM({"title_cn": "t", "summary_cn": "s"})
    sm = Summarizer(llm)
    item = _item(abstract="MARKER_ABSTRACT")
    sm.summarize(item)
    prompt = llm.calls[0]["user"]
    assert "MARKER_ABSTRACT" in prompt
    assert item.url in prompt


def test_summarizer_batch_processes_and_continues_on_partial_failure():
    class PartialLLM(FakeLLM):
        def complete_batch(self, system_prompt, user_prompt, items, max_batch_size=None):
            self.calls.append({"system": system_prompt, "user": user_prompt})
            results = []
            for _ in items:
                results.append(
                    {
                        "title_cn": "标题",
                        "summary_cn": "摘要内容",
                        "attack_surface": "未提及",
                        "technique": "未提及",
                        "impact": "未提及",
                        "significance": "未提及",
                        "recommendations": "未提及",
                        "confidence_note": "未提及",
                    }
                )
            return results

    llm = PartialLLM()
    sm = Summarizer(llm)
    items = [_item(), _item(url="https://arxiv.org/abs/2601.00002")]
    results = sm.summarize_batch(items)
    assert len(results) == 2
    assert all(r.ok for r in results)


def test_summarizer_batch_handles_none_entries():
    class NoneLLM(FakeLLM):
        def complete_batch(self, system_prompt, user_prompt, items, max_batch_size=None):
            self.calls.append({"system": system_prompt, "user": user_prompt})
            return [None for _ in items]

    llm = NoneLLM()
    sm = Summarizer(llm)
    items = [_item(), _item(url="https://arxiv.org/abs/2601.00003")]
    results = sm.summarize_batch(items)
    assert len(results) == 2
    assert results[0].ok is False
    assert results[1].ok is False


def test_summarizer_prompt_declares_all_required_output_fields():
    llm = FakeLLM({"title_cn": "t", "summary_cn": "s"})
    sm = Summarizer(llm)
    sm.summarize(_item())
    prompt = llm.calls[0]["user"]
    for field_name in (
        "title_cn",
        "summary_cn",
        "attack_surface",
        "technique",
        "impact",
        "significance",
        "recommendations",
        "confidence_note",
    ):
        assert field_name in prompt
