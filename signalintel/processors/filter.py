"""关键词召回筛选。

采用「中英文关键词 + 协议别名 + 网元名 + 攻击类型 + 主题词」的可配置词库，
对标题与摘要进行召回。标题命中权重高于摘要命中。

排除词优先级最高：命中排除词的内容直接判定为不相关，
以避免普通 Web 安全 / 终端恶意软件类内容混入主报告。
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping, Optional

from signalintel.models import IntelItem

__all__ = [
    "KeywordConfig",
    "KeywordFilter",
    "FilterResult",
]


@dataclass
class KeywordConfig:
    """关键词库配置。"""

    protocols: list[str] = field(default_factory=list)
    network_elements: list[str] = field(default_factory=list)
    attack_types: list[str] = field(default_factory=list)
    topics: list[str] = field(default_factory=list)
    chinese_keywords: list[str] = field(default_factory=list)
    exclusions: list[str] = field(default_factory=list)
    #: 有歧义的关键词：本身是常见英文词（如 Diameter 可指直径 / 纳米棒直径），
    #: 必须同时命中上下文关键词才算有效召回。
    ambiguous: list[str] = field(default_factory=list)
    #: 上下文关键词：用于判定歧义关键词是否处于电信语境
    context_keywords: list[str] = field(default_factory=list)
    min_matches: int = 1

    #: 标题命中权重（高于摘要）
    title_weight: float = 3.0
    #: 摘要命中权重
    abstract_weight: float = 1.0

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "KeywordConfig":
        """从 YAML 映射构造配置，容忍缺失字段。"""

        def _list(key: str) -> list[str]:
            raw = (data or {}).get(key) or []
            if isinstance(raw, str):
                raw = [raw]
            return [str(item).strip() for item in raw if str(item).strip()]

        raw = data or {}
        return cls(
            protocols=_list("protocols"),
            network_elements=_list("network_elements"),
            attack_types=_list("attack_types"),
            topics=_list("topics"),
            chinese_keywords=_list("chinese_keywords"),
            exclusions=_list("exclusions"),
            ambiguous=_list("ambiguous"),
            context_keywords=_list("context_keywords"),
            min_matches=int(raw.get("min_matches", 1) or 1),
            title_weight=float(raw.get("title_weight", 3.0)),
            abstract_weight=float(raw.get("abstract_weight", 1.0)),
        )


@dataclass
class FilterResult:
    """筛选评估结果。"""

    matched: bool
    match_count: int = 0
    weight: float = 0.0
    matched_keywords: list[str] = field(default_factory=list)
    excluded_by: Optional[str] = None
    reason: str = ""


#: 歧义关键词附近的电信语境词（局部上下文判定）
_LOCAL_CONTEXT_RE = re.compile(
    r"\b(routing|route|attack|protocol|message|signaling|signalling|network|"
    r"telecom|mobile|cellular|operator|carrier|subscriber|base station|"
    r"authentication|authorization|session|interface|node|element|"
    r"5g\s*core|lte|ran|ims|nas|ngap|sip|gtp|pfcp|ss7|roaming|"
    r"interconnect|hss|mme|amf|smf|upf|vran|open\s*ran)\b",
    re.IGNORECASE,
)


#: 歧义缩写：仅全大写时才算协议名，避免误命中普通英文单词。
#:
#:   MAP  → Memory Access Protection / 内存映射 / map 动词
#:   IMS  → 车载信息娱乐系统
#:   NAS  → 网络附加存储
#:   DEA  → 数据加密算法
#:   SIP  → sip 动词 / 饮料
#:   IDS / IPS → 通用安全术语，与电信无强绑定
#:   SCP / UPF / PCF / RAN → 常见缩写词
#:
#: 这些缩写本身区分度低，小写形式在通用语料中极常见，
#: 因此统一要求全大写。
#:
#: 其它协议缩写（SS7 / TCAP / PFCP / GTP-C / NGAP / MME / HSS / AMF ...）
#: 没有对应的常见英文单词，大小写不敏感匹配即可 —— 例如 Linux 内核
#: 提交信息里的 "pfcp:" 也是有效命中。
_UPPERCASE_ONLY_KEYWORDS = frozenset(
    {"MAP", "IMS", "NAS", "SIP", "DEA", "DRA", "IDS", "IPS", "SCP", "UPF",
     "PCF", "RAN", "SCEF"}
)


def _compile_keyword(keyword: str) -> re.Pattern[str]:
    """把关键词编译为正则，支持空白分隔的多词短语。

    协议缩写（SS7 / MAP / SIP / IMS / NAS 等）要求**全大写**才匹配，
    避免 "map"（映射、内存映射）、"ims"、"nas" 等普通词误命中。
    """
    text = keyword.strip()
    escaped = re.escape(text)
    # 允许 "signaling firewall" 这类短语中间出现空白/连字符
    escaped = escaped.replace(r"\ ", r"[\s\-_]+")

    if text.upper() in _UPPERCASE_ONLY_KEYWORDS and text.isupper():
        # 大小写敏感匹配（无 IGNORECASE 标志）
        return re.compile(rf"\b{escaped}\b")

    # 词边界：拉丁词加 \b，中文不加（中文无空格边界）
    if re.match(r"^[\x00-\x7F]+$", text):
        return re.compile(rf"\b{escaped}\b", re.IGNORECASE)
    return re.compile(escaped, re.IGNORECASE)


class KeywordFilter:
    """基于关键词库的召回筛选器。"""

    def __init__(self, config: KeywordConfig) -> None:
        self.config = config
        self._positive: list[tuple[str, re.Pattern[str]]] = []
        self._exclusions: list[tuple[str, re.Pattern[str]]] = []

        for group in (
            config.protocols,
            config.network_elements,
            config.attack_types,
            config.topics,
            config.chinese_keywords,
        ):
            for keyword in group:
                self._positive.append((keyword, _compile_keyword(keyword)))

            for keyword in config.exclusions:
                self._exclusions.append((keyword, _compile_keyword(keyword)))

            # 歧义关键词单独编译
            self._ambiguous = [
                (keyword, _compile_keyword(keyword)) for keyword in config.ambiguous
            ]
            self._context = [
                (keyword, _compile_keyword(keyword)) for keyword in config.context_keywords
            ]

    # ------------------------------------------------------------------

    def evaluate(self, item: IntelItem) -> FilterResult:
        """评估单条内容是否与核心网信令安全相关。"""
        title = item.title or ""
        abstract = item.abstract or ""
        combined = f"{title}\n{abstract}"

        # 1) 排除词优先
        for keyword, pattern in self._exclusions:
            if pattern.search(combined):
                return FilterResult(
                    matched=False,
                    excluded_by=keyword,
                    reason=f"命中排除词「{keyword}」",
                )

        # 2) 漏洞编号是强信号，但**不能无条件放行**。
        # NVD 的检索结果里混有大量与电信无关的 CVE（Linux 内核、蓝牙、
        # Web 应用等），仅凭「有 CVE 编号」放行会让报告退化成通用漏洞列表。
        # 因此要求漏洞的标题 / 描述中明确出现电信领域实体。
        if item.cve_ids:
            telecom_hit = any(
                pattern.search(combined) for _, pattern in self._context
            )
            if telecom_hit:
                return FilterResult(
                    matched=True,
                    match_count=max(1, len(item.cve_ids)),
                    weight=self.config.title_weight,
                    matched_keywords=list(item.cve_ids),
                    reason="包含 CVE 编号且描述涉及电信领域",
                )

        # 3) 关键词召回
        matched_keywords: list[str] = []
        weight = 0.0
        seen: set[str] = set()

        # 上下文信号（用于判定歧义关键词是否处于电信语境）
        context_hit = any(
            pattern.search(combined) for _, pattern in self._context
        ) or self._has_local_context(combined)

        for keyword, pattern in self._positive:
            in_title = bool(pattern.search(title))
            in_abstract = bool(pattern.search(abstract))
            if not in_title and not in_abstract:
                continue
            if keyword.lower() in seen:
                continue
            seen.add(keyword.lower())
            matched_keywords.append(keyword)
            if in_title:
                weight += self.config.title_weight
            if in_abstract:
                weight += self.config.abstract_weight

        # 歧义关键词：仅在命中电信上下文时才计为有效召回
        for keyword, pattern in self._ambiguous:
            if keyword.lower() in seen:
                continue
            if not (pattern.search(title) or pattern.search(abstract)):
                continue
            if not context_hit:
                continue
            seen.add(keyword.lower())
            matched_keywords.append(keyword)
            weight += self.config.abstract_weight

        count = len(matched_keywords)
        if count < max(1, self.config.min_matches):
            return FilterResult(
                matched=False,
                match_count=count,
                weight=weight,
                matched_keywords=matched_keywords,
                reason="关键词命中数不足",
            )

        return FilterResult(
            matched=True,
            match_count=count,
            weight=weight,
            matched_keywords=matched_keywords,
            reason="关键词命中",
        )

    def _has_local_context(self, text: str) -> bool:
        """判断歧义关键词附近是否存在电信语境词。

        例如 "Diameter routing attack" —— 歧义词本身与 "routing / attack /
        protocol" 等电信语境词直接相邻，属于有效召回；而
        "Diameter Control of Nanorods" 则不是。
        """
        local_context = _LOCAL_CONTEXT_RE
        for _, pattern in self._ambiguous:
            for match in pattern.finditer(text):
                window = text[max(0, match.start() - 60) : match.end() + 60]
                if local_context.search(window):
                    return True
        return False

    def filter(self, items: Iterable[IntelItem]) -> tuple[list[IntelItem], list[IntelItem]]:
        """批量筛选，返回 ``(保留项, 丢弃项)``。"""
        kept: list[IntelItem] = []
        dropped: list[IntelItem] = []
        for item in items:
            result = self.evaluate(item)
            if result.matched:
                item.relevance_keywords = result.matched_keywords
                kept.append(item)
            else:
                dropped.append(item)
        return kept, dropped
