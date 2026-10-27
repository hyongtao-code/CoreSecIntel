"""相关性分类（P1/P2/P3/排除）。

采用「大模型分类 + 规则校验」的组合：

- 大模型负责语义判断（是否真的涉及核心网信令攻防）；
- 规则层负责兜底与校验，防止模型给出越界或不可信的结论。
- 大模型不可用时自动降级为纯规则判定，任务不中断。
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Optional

from signalintel.llm.client import LLMError, build_safety_preamble
from signalintel.llm.protocol import LLMBackend
from signalintel.models import IntelItem
from signalintel.utils.patterns import ATTACK_STEM, PROTOCOL_RE

logger = logging.getLogger(__name__)

__all__ = [
    "ClassificationResult",
    "Classifier",
    "PRIORITY_P1",
    "PRIORITY_P2",
    "PRIORITY_P3",
    "PRIORITY_EXCLUDE",
]

PRIORITY_P1 = "P1"
PRIORITY_P2 = "P2"
PRIORITY_P3 = "P3"
PRIORITY_EXCLUDE = "EXCLUDE"

_VALID_PRIORITIES = {PRIORITY_P1, PRIORITY_P2, PRIORITY_P3, PRIORITY_EXCLUDE}

#: 攻击类词干（允许复数与派生形式：attacks / vulnerabilities / bypassing ...）
_ATTACK_STEM = ATTACK_STEM

#: 协议名模式（大小写敏感，短缩写要求全大写）
_PROTOCOL = PROTOCOL_RE.pattern

#: P1 信号词：直接命中协议漏洞 / 信令攻击
_P1_SIGNALS = re.compile(
    rf"(?:{_PROTOCOL})[^.]{{0,80}}?\b(?:{_ATTACK_STEM})\w*",
    re.IGNORECASE,
)

#: P1 信号词（顺序反过来：先攻击后协议）
_P1_SIGNALS_REVERSED = re.compile(
    rf"\b(?:{_ATTACK_STEM})\w*[^.]{{0,80}}?(?:{_PROTOCOL})",
    re.IGNORECASE,
)

#: P2 信号词：核心网 / 运营商基础设施 / 漫游 / 身份认证
_P2_SIGNALS = re.compile(
    r"\b(core network|5g core|4g core|mobile core|network function|vnf|"
    r"roaming|interconnect|operator|mobile network|authentication|identity|"
    r"subscriber|ue security|slice|orchestration)\b",
    re.IGNORECASE,
)

#: P3 信号词：检测方法 / 工具 / 研究方法
_P3_SIGNALS = re.compile(
    r"\b(detection|anomaly|machine learning|deep learning|neural network|gNN|"
    r"classification|framework|toolkit|formal verification|fuzzing|"
    r"traffic analysis|behavior analysis|rule-based|intrusion detection)\b",
    re.IGNORECASE,
)

#: 明确无关的内容（普通 Web / 云 / 终端安全）
_IRRELEVANT_SIGNALS = re.compile(
    r"\b(phishing|ransomware|malware|ransomware-as-a-service|web application|"
    r"browser exploit|oauth|endpoint protection|antivirus)\b",
    re.IGNORECASE,
)


@dataclass
class ClassificationResult:
    """分类结果。"""

    priority: str = PRIORITY_EXCLUDE
    reason: str = ""
    protocols: list[str] = field(default_factory=list)
    attack_surface: list[str] = field(default_factory=list)
    degraded: bool = False


class Classifier:
    """相关性分类器。"""

    def __init__(self, llm: Optional[LLMBackend] = None) -> None:
        self.llm = llm

    # ------------------------------------------------------------------

    def classify(self, item: IntelItem) -> ClassificationResult:
        """对单条内容分类，失败时降级为规则判定。"""
        if self.llm is None:
            return self._rule_based(item)

        prompt = self._build_prompt(item)
        try:
            payload = self.llm.complete_one(
                build_safety_preamble()
                + "\n\n请判断下面这条内容与「电信核心网信令安全」的关联等级。",
                prompt,
            )
        except LLMError as exc:
            logger.warning("分类调用失败，降级为规则判定 (%s): %s", item.title[:60], exc)
            return self._rule_based(item)

        if not isinstance(payload, dict):
            logger.warning("分类返回结构异常，降级为规则判定: %s", item.title[:60])
            return self._rule_based(item)

        priority = str(payload.get("priority", "")).strip().upper()
        # 提示词允许模型输出中文「排除」，此处统一归一化
        if priority in {"排除", "EXCLUDED", "EXCLUDE", "无", "无关"}:
            priority = PRIORITY_EXCLUDE
        if priority not in _VALID_PRIORITIES:
            logger.warning("分类返回无效优先级 %r，降级为规则判定", priority)
            return self._rule_based(item)

        reason = str(payload.get("reason", "")).strip()
        protocols = payload.get("protocols") or []
        attack_surface = payload.get("attack_surface") or []
        if isinstance(protocols, str):
            protocols = [protocols]
        if isinstance(attack_surface, str):
            attack_surface = [attack_surface]

        # 规则校验：模型判定为 P1/P2/P3 时，必须有相关的信号支撑，
        # 否则降级为排除，防止模型过度宽松。
        if priority in {PRIORITY_P1, PRIORITY_P2, PRIORITY_P3}:
            if not self._has_supporting_signal(item, priority):
                logger.info(
                    "模型判定 %s 但缺少信号支撑，降级为排除: %s",
                    priority,
                    item.title[:60],
                )
                priority = PRIORITY_EXCLUDE
                reason = f"{reason}（规则校验：缺少相关信号支撑）".strip()

        result = ClassificationResult(
            priority=priority,
            reason=reason,
            protocols=[str(p) for p in protocols],
            attack_surface=[str(a) for a in attack_surface],
            degraded=False,
        )
        item.priority = result.priority
        return result

    # ------------------------------------------------------------------

    def _has_supporting_signal(self, item: IntelItem, priority: str) -> bool:
        """检查内容是否具备支撑该优先级的信号。"""
        text = f"{item.title}\n{item.abstract}"
        if _IRRELEVANT_SIGNALS.search(text) and not (
            _P1_SIGNALS.search(text) or _P1_SIGNALS_REVERSED.search(text)
        ):
            return False
        if priority == PRIORITY_P1:
            return bool(
                _P1_SIGNALS.search(text)
                or _P1_SIGNALS_REVERSED.search(text)
                or item.cve_ids
            )
        if priority == PRIORITY_P2:
            return bool(_P2_SIGNALS.search(text) or item.relevance_keywords)
        return bool(_P3_SIGNALS.search(text) or item.relevance_keywords)

    def _rule_based(self, item: IntelItem) -> ClassificationResult:
        """纯规则判定（大模型不可用时的降级路径）。"""
        text = f"{item.title}\n{item.abstract}"

        if _IRRELEVANT_SIGNALS.search(text) and not (
            _P1_SIGNALS.search(text) or _P1_SIGNALS_REVERSED.search(text)
        ):
            result = ClassificationResult(
                priority=PRIORITY_EXCLUDE, reason="命中无关安全主题", degraded=True
            )
            item.priority = result.priority
            return result

        if item.cve_ids and item.relevance_keywords:
            result = ClassificationResult(
                priority=PRIORITY_P1,
                reason="漏洞公告且与信令相关关键词匹配",
                degraded=True,
            )
        elif _P1_SIGNALS.search(text) or _P1_SIGNALS_REVERSED.search(text):
            result = ClassificationResult(
                priority=PRIORITY_P1, reason="直接涉及信令协议攻击或漏洞", degraded=True
            )
        elif _P2_SIGNALS.search(text) and item.relevance_keywords:
            result = ClassificationResult(
                priority=PRIORITY_P2, reason="涉及核心网 / 运营商基础设施安全", degraded=True
            )
        elif _P3_SIGNALS.search(text) and item.relevance_keywords:
            result = ClassificationResult(
                priority=PRIORITY_P3, reason="涉及相关检测方法或研究工具", degraded=True
            )
        elif item.relevance_keywords:
            result = ClassificationResult(
                priority=PRIORITY_P3, reason="仅关键词匹配，无明确攻防指向", degraded=True
            )
        else:
            result = ClassificationResult(
                priority=PRIORITY_EXCLUDE, reason="未匹配到相关信号", degraded=True
            )

        item.priority = result.priority
        return result

    # ------------------------------------------------------------------

    def _build_prompt(self, item: IntelItem) -> str:
        """构造分类提示词（外部内容以不可信标记包裹）。"""
        lines = [
            "请判断下面这条内容与「电信核心网信令安全」的关联等级。",
            "",
            "分级标准：",
            "- P1：直接涉及核心网信令攻防、协议漏洞或已确认的信令安全事件。",
            "- P2：涉及电信核心网、运营商基础设施、漫游安全或身份认证安全。",
            "- P3：与信令安全相关的前沿研究方法、检测技术和安全工具。",
            "- 排除：与电信信令安全缺乏明确关联的普通网络安全内容。",
            "",
            "请输出 JSON，字段：",
            '{"priority": "P1|P2|P3|排除", "reason": "判定理由（一句话）",',
            ' "protocols": ["涉及的协议"], "attack_surface": ["涉及的攻击面或网元"]}',
            "",
            "待判定内容：",
            "<<<UNTRUSTED_CONTENT>>>",
            f"标题：{item.title}",
            f"来源：{item.source}",
            f"类型：{item.content_type}",
            f"摘要：{item.abstract}",
            f"链接：{item.url}",
            "<<<END_UNTRUSTED_CONTENT>>>",
        ]
        return "\n".join(lines)
