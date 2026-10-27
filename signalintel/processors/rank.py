"""综合评分（0-100）。

四个维度，权重可配置：

- 专业相关性：40%
- 技术新颖性：25%
- 安全影响和威胁程度：20%
- 来源可信度：15%

分数仅用于排序与筛选，**不代表客观、绝对的风险等级**。
每次评分都会输出可读的评分理由。
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Optional

from signalintel.models import IntelItem
from signalintel.utils.patterns import NETWORK_ELEMENT_RE, PROTOCOL_RE

__all__ = ["Ranker", "ScoreWeights", "score_item"]


@dataclass
class ScoreWeights:
    """评分权重（总和应为 1.0）。"""

    relevance: float = 0.40
    novelty: float = 0.25
    impact: float = 0.20
    source_trust: float = 0.15

    def as_dict(self) -> dict[str, float]:
        return {
            "relevance": self.relevance,
            "novelty": self.novelty,
            "impact": self.impact,
            "source_trust": self.source_trust,
        }

    @classmethod
    def from_mapping(cls, data: Optional[dict[str, Any]]) -> "ScoreWeights":
        data = data or {}
        return cls(
            relevance=float(data.get("relevance", 0.40)),
            novelty=float(data.get("novelty", 0.25)),
            impact=float(data.get("impact", 0.20)),
            source_trust=float(data.get("source_trust", 0.15)),
        )


#: 新颖性信号词（方法或工具层面的新意）
_NOVELTY_SIGNALS = re.compile(
    r"\b(new|novel|first|uncover|reveal|demonstrate|propose|new attack|"
    r"zero-?[Dd]ay|in-?[Tt]he-?[Ww]ild|out-of-?[Bb]and|proof-of-concept|"
    r"end-to-end|systematic study|survey of)\b",
    re.IGNORECASE,
)

#: 影响面信号词
_IMPACT_SIGNALS = re.compile(
    r"\b(critical|high severity|remote code execution|rce|arbitrary code|"
    r"denial of service|dos |data leak|privacy leak|location leak|imsi|"
    r"subscriber data|intercept|drop call|deny service|massive|全国|大规模|"
    r"critical vulnerability|widely exploited|active exploitation)\b",
    re.IGNORECASE,
)

#: 漏洞类型的内容类型（威胁程度通常更高）
_VULN_TYPES = {"vulnerability", "advisory", "cve", "security_alert"}


class Ranker:
    """综合评分器。"""

    def __init__(self, weights: Optional[ScoreWeights] = None) -> None:
        self.weights = weights or ScoreWeights()

    # ------------------------------------------------------------------

    def score(self, item: IntelItem) -> tuple[float, list[str]]:
        """返回 ``(总分, 评分理由列表)``。"""
        relevance, rel_reason = self._relevance(item)
        novelty, nov_reason = self._novelty(item)
        impact, imp_reason = self._impact(item)
        trust, trust_reason = self._trust(item)

        weights = self.weights.as_dict()
        total = (
            relevance * weights["relevance"]
            + novelty * weights["novelty"]
            + impact * weights["impact"]
            + trust * weights["source_trust"]
        )
        score = round(max(0.0, min(100.0, total)), 1)

        reasons = [
            f"专业相关性 {relevance:.0f}/100（权重 {weights['relevance']:.0%}）：{rel_reason}",
            f"技术新颖性 {novelty:.0f}/100（权重 {weights['novelty']:.0%}）：{nov_reason}",
            f"安全影响 {impact:.0f}/100（权重 {weights['impact']:.0%}）：{imp_reason}",
            f"来源可信度 {trust:.0f}/100（权重 {weights['source_trust']:.0%}）：{trust_reason}",
        ]
        return score, reasons

    def score_item(self, item: IntelItem) -> IntelItem:
        """就地评分并返回条目。"""
        value, reasons = self.score(item)
        item.score = value
        item.score_reasons = reasons
        return item

    # ------------------------------------------------------------------
    # 各维度打分（均返回 0-100）
    # ------------------------------------------------------------------

    def _relevance(self, item: IntelItem) -> tuple[float, str]:
        keywords = item.relevance_keywords or []
        text = f"{item.title} {item.abstract}"

        base = 0.0
        if keywords:
            # 命中数量饱和式加分：1 个 35 分，之后每个递减
            base += min(35.0, 35.0 + (len(keywords) - 1) * 8.0)
        if item.priority == "P1":
            base += 40.0
        elif item.priority == "P2":
            base += 25.0
        elif item.priority == "P3":
            base += 12.0

        # 协议/网元出现在标题中说明高度聚焦
        if PROTOCOL_RE.search(item.title or "") or NETWORK_ELEMENT_RE.search(
            item.title or ""
        ):
            base += 15.0

        if re.search(r"\b(phishing|ransomware|web application|antivirus)\b", text, re.IGNORECASE):
            base *= 0.3

        value = max(0.0, min(100.0, base))
        reason = (
            f"命中 {len(keywords)} 个信令相关关键词"
            if keywords
            else "未命中信令关键词"
        )
        if item.priority:
            reason += f"，优先级 {item.priority}"
        return value, reason

    def _novelty(self, item: IntelItem) -> tuple[float, str]:
        text = f"{item.title} {item.abstract}"
        value = 40.0
        reason = "常规研究内容"

        if _NOVELTY_SIGNALS.search(text):
            value += 35.0
            reason = "标题/摘要含新方法、新发现或首次披露类表述"
        if item.content_type == "paper" and re.search(
            r"\b(fuzz|formal verification|automated|ai|llm|machine learning|"
            r"deep learning|neural network|gnn)\b",
            text,
            re.IGNORECASE,
        ):
            value += 20.0
            reason += "；采用较新的研究方法（模糊测试 / 形式化验证 / AI 辅助）"
        if item.is_preprint:
            value += 5.0
            reason += "；为预印本，尚需同行评议确认"
        if item.content_type == "news":
            value -= 10.0
            reason += "；新闻类内容时效性强但技术新颖度有限"

        value = max(0.0, min(100.0, value))
        return value, reason

    def _impact(self, item: IntelItem) -> tuple[float, str]:
        text = f"{item.title} {item.abstract}"
        value = 30.0
        reason = "未描述具体安全影响"

        if _IMPACT_SIGNALS.search(text):
            value += 45.0
            reason = "提及高危影响（远程代码执行 / 拒绝服务 / 隐私泄露等）"
        if item.cve_ids:
            value += 20.0
            reason += f"；涉及 {len(item.cve_ids)} 个 CVE 编号"
        if item.content_type in _VULN_TYPES:
            value += 15.0
            reason += "；属于漏洞或官方公告类内容"
        if re.search(
            r"\b(core network|5g core|mobile core|roaming|subscriber|ims)\b",
            text,
            re.IGNORECASE,
        ):
            value += 10.0
            reason += "；影响面涉及核心网 / 漫游 / 用户数据"

        value = max(0.0, min(100.0, value))
        return value, reason

    def _trust(self, item: IntelItem) -> tuple[float, str]:
        value = max(0.0, min(100.0, item.trust_score * 100.0))
        reason = f"来源 {item.source} 可信度 {item.trust_score:.2f}"
        if item.doi:
            value = min(100.0, value + 10.0)
            reason += "；有 DOI 可追溯"
        if item.cve_ids:
            value = min(100.0, value + 5.0)
            reason += "；有 CVE 编号可追溯"
        if item.source_type == "official":
            value = min(100.0, value + 10.0)
            reason += "；官方来源"
        return value, reason


def score_item(item: IntelItem, weights: Optional[ScoreWeights] = None) -> IntelItem:
    """便捷函数：就地评分。"""
    return Ranker(weights).score_item(item)
