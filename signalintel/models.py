"""核心数据模型。

所有采集器输出 :class:`IntelItem`，所有处理器消费 :class:`IntelItem`，
这是整个系统唯一的数据契约。
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

__all__ = [
    "ContentType",
    "IntelItem",
    "Priority",
    "SourceLink",
    "SourceTrust",
]

# 内容类型
ContentType = str

#: 优先级分级
Priority = str

#: 来源可信度评分（0-1），用于综合评分中的「来源可信度」维度
SourceTrust = float


@dataclass
class SourceLink:
    """同一事件的附加来源链接（用于多来源合并后保留可追溯性）。"""

    source: str
    title: str = ""
    url: str = ""
    published_at: Optional[datetime] = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "title": self.title,
            "url": self.url,
            "published_at": self.published_at.isoformat() if self.published_at else None,
        }


@dataclass
class IntelItem:
    """一条统一的情报条目（论文 / 新闻 / 漏洞公告 / 技术报告）。

    时间字段刻意分开，避免把「网页更新时间」误当成「首次公开时间」：

    - ``first_published_at``: 首次公开时间（预印本首次提交 / 漏洞首次披露）
    - ``published_at``: 对外公布或正式发表时间（报告默认使用）
    - ``updated_at``: 来源页面的更新时间（**不参与**时间窗口判定）
    - ``collected_at``: 本系统采集时间
    """

    source: str
    source_type: str
    title: str
    url: str
    abstract: str = ""
    authors: list[str] = field(default_factory=list)
    content_type: str = "unknown"

    # 时间字段
    published_at: Optional[datetime] = None
    first_published_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
    collected_at: Optional[datetime] = None

    # 标识符
    doi: Optional[str] = None
    cve_ids: list[str] = field(default_factory=list)

    # 分类与评分（由处理器填充）
    priority: Optional[str] = None
    score: Optional[float] = None
    score_reasons: list[str] = field(default_factory=list)
    relevance_keywords: list[str] = field(default_factory=list)

    # 大模型生成的摘要字段
    summary_cn: str = ""
    title_cn: str = ""
    attack_surface: str = ""
    technique: str = ""
    impact: str = ""
    significance: str = ""
    recommendations: str = ""
    confidence_note: str = ""

    # 展示控制
    is_preprint: bool = False
    trust_score: float = 0.5
    alternate_sources: list[SourceLink] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)

    # ------------------------------------------------------------------
    # 派生属性
    # ------------------------------------------------------------------

    @property
    def effective_published_at(self) -> Optional[datetime]:
        """用于时间窗口判定的发布时间。

        优先使用正式发表 / 发布时间，其次回退到首次公开时间。
        """
        return self.published_at or self.first_published_at

    @property
    def has_verified_date(self) -> bool:
        """是否存在可用于时间窗口判定的可靠发布时间。"""
        return self.effective_published_at is not None

    @property
    def content_fingerprint(self) -> str:
        """内容指纹，用于历史去重与增量判断。"""
        basis = "|".join(
            [
                self.doi or "",
                ",".join(sorted(self.cve_ids)),
                self.title.strip().lower(),
            ]
        )
        return hashlib.sha256(basis.encode("utf-8")).hexdigest()[:32]

    @property
    def all_source_links(self) -> list[str]:
        """主链接 + 合并进来的其它来源链接。"""
        links = [self.url] if self.url else []
        links.extend(link.url for link in self.alternate_sources if link.url)
        return links

    def to_dict(self) -> dict[str, Any]:
        """转换为可 JSON 序列化的字典。"""
        return {
            "source": self.source,
            "source_type": self.source_type,
            "title": self.title,
            "title_cn": self.title_cn,
            "url": self.url,
            "abstract": self.abstract,
            "authors": list(self.authors),
            "content_type": self.content_type,
            "published_at": self.published_at.isoformat() if self.published_at else None,
            "first_published_at": (
                self.first_published_at.isoformat() if self.first_published_at else None
            ),
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "collected_at": self.collected_at.isoformat() if self.collected_at else None,
            "doi": self.doi,
            "cve_ids": list(self.cve_ids),
            "priority": self.priority,
            "score": self.score,
            "score_reasons": list(self.score_reasons),
            "relevance_keywords": list(self.relevance_keywords),
            "summary_cn": self.summary_cn,
            "attack_surface": self.attack_surface,
            "technique": self.technique,
            "impact": self.impact,
            "significance": self.significance,
            "recommendations": self.recommendations,
            "confidence_note": self.confidence_note,
            "is_preprint": self.is_preprint,
            "trust_score": self.trust_score,
            "alternate_sources": [link.to_dict() for link in self.alternate_sources],
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "IntelItem":
        """从字典恢复对象（数据库读回时使用）。"""
        from signalintel.utils.dates import parse_date_string

        def _dt(key: str) -> Optional[datetime]:
            return parse_date_string(data.get(key))

        item = cls(
            source=data.get("source", ""),
            source_type=data.get("source_type", ""),
            title=data.get("title", ""),
            url=data.get("url", ""),
            abstract=data.get("abstract", ""),
            authors=list(data.get("authors") or []),
            content_type=data.get("content_type", "unknown"),
            published_at=_dt("published_at"),
            first_published_at=_dt("first_published_at"),
            updated_at=_dt("updated_at"),
            collected_at=_dt("collected_at"),
            doi=data.get("doi"),
            cve_ids=list(data.get("cve_ids") or []),
            priority=data.get("priority"),
            score=data.get("score"),
            score_reasons=list(data.get("score_reasons") or []),
            relevance_keywords=list(data.get("relevance_keywords") or []),
            summary_cn=data.get("summary_cn", ""),
            title_cn=data.get("title_cn", ""),
            attack_surface=data.get("attack_surface", ""),
            technique=data.get("technique", ""),
            impact=data.get("impact", ""),
            significance=data.get("significance", ""),
            recommendations=data.get("recommendations", ""),
            confidence_note=data.get("confidence_note", ""),
            is_preprint=bool(data.get("is_preprint", False)),
            trust_score=float(data.get("trust_score", 0.5) or 0.5),
        )
        for link in data.get("alternate_sources") or []:
            item.alternate_sources.append(
                SourceLink(
                    source=link.get("source", ""),
                    title=link.get("title", ""),
                    url=link.get("url", ""),
                    published_at=parse_date_string(link.get("published_at")),
                )
            )
        return item
