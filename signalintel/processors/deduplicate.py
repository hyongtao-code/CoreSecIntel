"""去重与事件合并。

去重依据（按强度从高到低）：

1. DOI 完全一致
2. CVE 编号存在交集
3. 规范化 URL 一致
4. 标题相似度达到阈值（且内容类型兼容）

同一事件被多个媒体报道时合并为一条主记录，附加来源保留在
``alternate_sources`` 中，邮件中合并展示，避免重复占用篇幅。
"""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Iterable, Optional
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from signalintel.models import IntelItem, SourceLink

__all__ = [
    "Deduplicator",
    "extract_cve_ids",
    "normalize_doi",
    "normalize_title",
    "normalize_url",
    "title_similarity",
]

#: 追踪型查询参数，规范化时剔除
_TRACKING_PARAMS = frozenset(
    {
        "utm_source",
        "utm_medium",
        "utm_campaign",
        "utm_term",
        "utm_content",
        "utm_id",
        "utm_name",
        "utm_reader",
        "utm_social",
        "utm_brand",
        "gclid",
        "fbclid",
        "msclkid",
        "mc_cid",
        "mc_eid",
        "ref",
        "ref_src",
        "ref_url",
        "spm",
        "share_id",
        "from",
        "source",
        "yclid",
        "_hsenc",
        "_hsmi",
        "mkt_tok",
    }
)

#: CVE 正则：CVE-YYYY-NNNN+
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

#: DOI 归一化前缀
_DOI_PREFIX_RE = re.compile(r"^(?:https?://(?:dx\.)?doi\.org/|doi:\s*)", re.IGNORECASE)

#: 标题中的标点与多余空白
_TITLE_PUNCT_RE = re.compile(r"[^\w\s一-鿿]+", re.UNICODE)
_TITLE_SPACE_RE = re.compile(r"\s+")


def normalize_url(url: Optional[str]) -> str:
    """规范化 URL：统一小写域名、去追踪参数、去 fragment、去默认端口。"""
    if not url:
        return ""
    text = str(url).strip()
    if not text:
        return ""
    if "://" not in text:
        text = "https://" + text

    try:
        parts = urlsplit(text)
    except ValueError:
        return text.lower()

    scheme = (parts.scheme or "https").lower()
    if scheme == "http":
        scheme = "https"

    netloc = (parts.netloc or "").lower()
    if netloc.startswith("www."):
        netloc = netloc[4:]
    if netloc.endswith(":443"):
        netloc = netloc[:-4]
    elif netloc.endswith(":80"):
        netloc = netloc[:-3]

    path = parts.path or "/"
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]

    query_pairs = [
        (key, value)
        for key, value in parse_qsl(parts.query, keep_blank_values=True)
        if key.lower() not in _TRACKING_PARAMS
    ]
    query = urlencode(sorted(query_pairs))

    return urlunsplit((scheme, netloc, path, query, ""))


def normalize_doi(doi: Optional[str]) -> Optional[str]:
    """提取并归一化 DOI（统一小写，去除 URL / doi: 前缀）。"""
    if not doi:
        return None
    text = str(doi).strip()
    if not text:
        return None
    text = _DOI_PREFIX_RE.sub("", text)
    text = text.strip().rstrip(".")
    if not text.startswith("10."):
        return None
    return text.lower()


def extract_cve_ids(text: Optional[str]) -> list[str]:
    """从任意文本中提取 CVE 编号列表（大写规范形式，去重保序）。"""
    if not text:
        return []
    found: list[str] = []
    seen: set[str] = set()
    for match in _CVE_RE.findall(str(text)):
        normalized = match.upper()
        if normalized not in seen:
            seen.add(normalized)
            found.append(normalized)
    return found


def normalize_title(title: Optional[str]) -> str:
    """标题归一化：小写、去标点、压缩空白、去除常见前缀噪声。"""
    if not title:
        return ""
    text = str(title)
    # 去掉常见的来源前缀噪声，例如 "[论文]"、"【转载】"、"Paper - "
    text = re.sub(r"^\s*[\[\【][^\]\】]{0,20}[\]\】]\s*", "", text)
    text = _TITLE_PUNCT_RE.sub(" ", text.lower())
    text = _TITLE_SPACE_RE.sub(" ", text).strip()
    return text


def title_similarity(a: Optional[str], b: Optional[str]) -> float:
    """标题相似度（0.0 - 1.0）。"""
    na, nb = normalize_title(a), normalize_title(b)
    if not na or not nb:
        return 0.0
    if na == nb:
        return 1.0
    # 词集合 Jaccard 与序列相似度取较大值，对语序变化更宽容
    set_a, set_b = set(na.split()), set(nb.split())
    union = set_a | set_b
    jaccard = len(set_a & set_b) / len(union) if union else 0.0
    sequence = SequenceMatcher(None, na, nb).ratio()
    return max(jaccard, sequence)


def _content_richness(item: IntelItem) -> int:
    """内容丰富度评分，用于决定合并后的主记录。"""
    score = 0
    score += min(len(item.abstract or ""), 2000) // 100
    score += 5 if item.doi else 0
    score += 5 if item.cve_ids else 0
    score += len(item.authors)
    score += 2 if item.summary_cn else 0
    return score


class Deduplicator:
    """流式去重器。

    ``add(item)`` 返回 ``True`` 表示该条目是新的主记录；
    返回 ``False`` 表示与已有记录重复（信息已合并进主记录）。
    """

    def __init__(self, title_threshold: float = 0.82) -> None:
        self.title_threshold = title_threshold
        self.items: list[IntelItem] = []
        self._by_doi: dict[str, IntelItem] = {}
        self._by_cve: dict[str, IntelItem] = {}
        self._by_url: dict[str, IntelItem] = {}
        self._by_title: list[tuple[str, IntelItem]] = []

    # ------------------------------------------------------------------

    def add(self, item: IntelItem) -> bool:
        """加入条目，返回是否为新的主记录。"""
        existing = self._find_match(item)
        if existing is None:
            self._register(item)
            self.items.append(item)
            return True

        self._merge(existing, item)
        # 主记录可能被替换，需重新登记索引
        if existing is not self.items[self.items.index(existing)]:
            pass
        if _content_richness(item) > _content_richness(existing):
            self._replace_primary(existing, item)
        return False

    def extend(self, items: Iterable[IntelItem]) -> list[IntelItem]:
        """批量加入并返回新的主记录列表。"""
        new_items: list[IntelItem] = []
        for item in items:
            if self.add(item):
                new_items.append(item)
        return new_items

    # ------------------------------------------------------------------

    def _find_match(self, item: IntelItem) -> Optional[IntelItem]:
        doi = normalize_doi(item.doi)
        if doi and doi in self._by_doi:
            return self._by_doi[doi]

        item_cves = {c.upper() for c in item.cve_ids}
        if not item_cves:
            item_cves = set(extract_cve_ids(item.title))
        if item_cves:
            for cve in item_cves:
                if cve in self._by_cve:
                    return self._by_cve[cve]

        url = normalize_url(item.url)
        if url and url in self._by_url:
            return self._by_url[url]

        for norm_title, candidate in self._by_title:
            if title_similarity(norm_title, item.title) >= self.title_threshold:
                return candidate
        return None

    def _register(self, item: IntelItem) -> None:
        doi = normalize_doi(item.doi)
        if doi:
            self._by_doi[doi] = item
        for cve in {c.upper() for c in item.cve_ids} or set(extract_cve_ids(item.title)):
            self._by_cve[cve] = item
        url = normalize_url(item.url)
        if url:
            self._by_url[url] = item
        self._by_title.append((normalize_title(item.title), item))

    def _unregister(self, item: IntelItem) -> None:
        doi = normalize_doi(item.doi)
        if doi and self._by_doi.get(doi) is item:
            del self._by_doi[doi]
        for cve, owner in list(self._by_cve.items()):
            if owner is item:
                del self._by_cve[cve]
        for url, owner in list(self._by_url.items()):
            if owner is item:
                del self._by_url[url]
        self._by_title = [(t, i) for t, i in self._by_title if i is not item]

    def _replace_primary(self, old: IntelItem, new: IntelItem) -> None:
        """内容更丰富的条目替换主记录，保留旧记录作为附加来源。"""
        index = self.items.index(old)
        self._unregister(old)
        link = SourceLink(
            source=old.source,
            title=old.title,
            url=old.url,
            published_at=old.effective_published_at,
        )
        if link.url and link.url != new.url:
            new.alternate_sources.append(link)
        self.items[index] = new
        self._register(new)

    def _merge(self, primary: IntelItem, other: IntelItem) -> None:
        """把重复条目的补充信息合并进主记录。"""
        if other.url and other.url != primary.url:
            exists = {link.url for link in primary.alternate_sources}
            if other.url not in exists:
                primary.alternate_sources.append(
                    SourceLink(
                        source=other.source,
                        title=other.title,
                        url=other.url,
                        published_at=other.effective_published_at,
                    )
                )
        if not primary.doi and other.doi:
            primary.doi = other.doi
        known_cves = {c.upper() for c in primary.cve_ids}
        for cve in other.cve_ids or extract_cve_ids(other.title):
            if cve.upper() not in known_cves:
                primary.cve_ids.append(cve.upper())
                known_cves.add(cve.upper())
        if len(other.abstract or "") > len(primary.abstract or ""):
            primary.abstract = other.abstract
        if not primary.first_published_at and other.first_published_at:
            primary.first_published_at = other.first_published_at
        if primary.effective_published_at is None and other.effective_published_at:
            primary.published_at = other.published_at
            primary.first_published_at = other.first_published_at
        for author in other.authors:
            if author not in primary.authors:
                primary.authors.append(author)
        primary.trust_score = max(primary.trust_score, other.trust_score)
