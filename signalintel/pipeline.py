"""任务流水线。

流程（``full`` 模式）::

    采集 → 时间窗口过滤 → 去重 → 关键词召回 → 大模型分类 → 综合评分
         → 中文摘要 → 报告渲染 → （可选）邮件发送 → 写入历史

各阶段互相解耦，可单独运行（见 app.py 的调试模式）。
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from signalintel.collectors.base import CollectorResult
from signalintel.config import AppConfig
from signalintel.llm.client import LLMClient, LLMError
from signalintel.llm.protocol import LLMBackend
from signalintel.models import IntelItem
from signalintel.processors.classify import (
    PRIORITY_EXCLUDE,
    PRIORITY_P1,
    PRIORITY_P2,
    PRIORITY_P3,
    Classifier,
)
from signalintel.processors.deduplicate import Deduplicator
from signalintel.processors.filter import KeywordConfig, KeywordFilter
from signalintel.processors.rank import Ranker, ScoreWeights
from signalintel.processors.summarize import Summarizer
from signalintel.processors.telecom_gate import TelecomGate
from signalintel.reports.html_report import ReportData, build_subject
from signalintel.storage.repository import Repository
from signalintel.utils.dates import ensure_aware, now_in_tz, time_window

logger = logging.getLogger(__name__)

__all__ = ["Pipeline", "PipelineResult"]


@dataclass
class PipelineResult:
    """一次完整流水线的执行结果。"""

    run_id: Optional[int] = None
    report_date: str = ""
    window_start: Optional[datetime] = None
    window_end: Optional[datetime] = None

    collector_results: list[CollectorResult] = field(default_factory=list)
    items: list[IntelItem] = field(default_factory=list)
    p1_items: list[IntelItem] = field(default_factory=list)
    p2_items: list[IntelItem] = field(default_factory=list)
    p3_items: list[IntelItem] = field(default_factory=list)
    pending_items: list[IntelItem] = field(default_factory=list)

    candidates: int = 0
    after_dedup: int = 0
    after_filter: int = 0

    observations: list[str] = field(default_factory=list)
    report_path: Optional[str] = None
    subject: str = ""
    email_sent: bool = False
    email_error: Optional[str] = None

    sources_ok: int = 0
    sources_failed: int = 0

    @property
    def total_selected(self) -> int:
        return len(self.p1_items) + len(self.p2_items) + len(self.p3_items)

    @property
    def pending_count(self) -> int:
        """缺少可靠发布时间的条目数量。"""
        return len(self.pending_items)


class Pipeline:
    """端到端流水线。"""

    def __init__(
        self,
        config: AppConfig,
        repository: Repository,
        llm: Optional[LLMBackend] = None,
    ) -> None:
        self.config = config
        self.repository = repository
        self.llm = llm

    # ------------------------------------------------------------------

    @property
    def keyword_filter(self) -> KeywordFilter:
        keywords = KeywordConfig.from_mapping(self.config.keywords)
        return KeywordFilter(keywords)

    @property
    def ranker(self) -> Ranker:
        return Ranker(ScoreWeights.from_mapping(self.config.score_weights))

    def _llm_or_none(self) -> Optional[LLMBackend]:
        if self.llm is not None:
            return self.llm
        if not self.config.llm.is_configured:
            logger.warning("未配置 LLM_API_KEY，跳过大模型阶段")
            return None
        return LLMClient(self.config.llm)

    # ------------------------------------------------------------------

    def run(
        self,
        collector_results: list[CollectorResult],
        start: datetime,
        end: datetime,
        mode: str = "full",
        report_date: Optional[str] = None,
    ) -> PipelineResult:
        """执行流水线后处理（去重 → 筛选 → 分类 → 评分 → 摘要 → 报告）。"""
        result = PipelineResult(
            window_start=start,
            window_end=end,
            report_date=report_date or end.strftime("%Y-%m-%d"),
            collector_results=collector_results,
        )

        result.sources_ok = sum(
            1 for r in collector_results if not r.errors and not r.skipped
        )
        result.sources_failed = sum(
            1 for r in collector_results if r.errors or r.skipped
        )

        # 1) 汇总候选（窗口内 + 待核实）
        candidates: list[IntelItem] = []
        for collector_result in collector_results:
            candidates.extend(collector_result.items)
            result.pending_items.extend(collector_result.pending_items)
        result.candidates = len(candidates)
        logger.info("采集完成：候选 %s 条", result.candidates)

        # 2) 去重
        dedup = Deduplicator()
        dedup.extend(candidates)
        deduplicated = dedup.items
        result.after_dedup = len(deduplicated)
        logger.info("去重完成：%s → %s 条", result.candidates, result.after_dedup)

        # 3) 关键词召回
        keyword_filter = self.keyword_filter
        kept, dropped = keyword_filter.filter(deduplicated)
        logger.info(
            "关键词召回完成：保留 %s 条，过滤 %s 条", len(kept), len(dropped)
        )

        # 3.5) 电信领域闸门：剔除通用互联网安全内容（Linux 内核、蓝牙、
        #      Web 应用等），只保留真正属于核心网信令安全的内容。
        gate = TelecomGate()
        telecom_kept, telecom_dropped = gate.filter(kept)
        dropped.extend(telecom_dropped)
        kept = telecom_kept
        result.after_filter = len(kept)
        logger.info(
            "电信相关性闸门完成：保留 %s 条，剔除 %s 条通用安全内容",
            len(kept),
            len(telecom_dropped),
        )

        # 4) 大模型分类
        llm = self._llm_or_none()
        classifier = Classifier(llm)
        classified: list[IntelItem] = []
        for item in kept:
            classification = classifier.classify(item)
            if classification.priority == PRIORITY_EXCLUDE:
                continue
            classified.append(item)
        logger.info("分类完成：入选 %s 条", len(classified))

        # 5) 综合评分
        ranker = self.ranker
        for item in classified:
            ranker.score_item(item)

        # 6) 阈值过滤 + 排序
        min_score = self.config.min_score_for_report
        selected = [item for item in classified if (item.score or 0) >= min_score]
        selected.sort(key=lambda x: (x.score or 0), reverse=True)
        selected = selected[: self.config.max_items_in_report]
        result.items = selected

        for item in selected:
            if item.priority == PRIORITY_P1:
                result.p1_items.append(item)
            elif item.priority == PRIORITY_P2:
                result.p2_items.append(item)
            elif item.priority == PRIORITY_P3:
                result.p3_items.append(item)

        logger.info(
            "评分完成：P1 %s 条，P2 %s 条，P3 %s 条",
            len(result.p1_items),
            len(result.p2_items),
            len(result.p3_items),
        )

        # 7) 中文摘要（只对入选条目调用，控制成本）
        if llm is not None and selected:
            summarizer = Summarizer(llm)
            limit = self.config.llm.max_items
            to_summarize = selected[:limit]
            if len(selected) > limit:
                logger.warning(
                    "入选 %s 条超出 LLM_MAX_ITEMS=%s，仅摘要前 %s 条",
                    len(selected),
                    limit,
                    limit,
                )
            summary_results = summarizer.summarize_batch(to_summarize)
            failed = sum(1 for r in summary_results if not r.ok)
            if failed:
                logger.warning("%s 条摘要生成失败，保留原始元数据", failed)
        elif selected:
            logger.warning("未配置大模型，报告中将使用原始元数据")

        # 8) 技术观察
        result.observations = self._generate_observations(selected, llm)

        # 9) 渲染报告
        report_data = self._build_report_data(result)
        result.subject = build_subject(
            report_data.report_date,
            report_data.paper_count,
            report_data.intel_count,
            prefix=self.config.smtp.subject_prefix,
        )

        from signalintel.reports.html_report import ReportBuilder

        builder = ReportBuilder(output_dir=self.config.data_dir / "reports")
        report_path = builder.build(report_data)
        result.report_path = str(report_path)
        logger.info("报告已生成: %s", report_path)

        # 10) 落库
        self._persist(result)

        return result

    # ------------------------------------------------------------------

    def _build_report_data(self, result: PipelineResult) -> ReportData:
        """构造报告数据。"""
        assert result.window_start is not None and result.window_end is not None
        return ReportData(
            window_start=result.window_start,
            window_end=result.window_end,
            timezone=self.config.timezone,
            sources_ok=result.sources_ok,
            sources_failed=result.sources_failed,
            candidates=result.candidates,
            after_dedup=result.after_dedup,
            after_filter=result.after_filter,
            p1_count=len(result.p1_items),
            p2_count=len(result.p2_items),
            p3_count=len(result.p3_items),
            pending_count=len(result.pending_items),
            p1_items=list(result.p1_items),
            p2_items=list(result.p2_items),
            p3_items=list(result.p3_items),
            observations=result.observations,
            report_date=result.report_date,
        )

    def _generate_observations(
        self, items: list[IntelItem], llm: Optional[LLMBackend]
    ) -> list[str]:
        """基于本期实际内容归纳技术观察。"""
        if not items:
            return []
        if llm is None:
            return self._rule_based_observations(items)

        try:
            payload = llm.complete_one(
                "你是电信核心网安全领域的研究人员。基于给定的情报条目，"
                "归纳 2-4 个技术趋势。必须严格基于给定条目，"
                "不得引入条目之外的信息，不得把少量报道夸大成行业共识。",
                self._observations_prompt(items),
            )
        except LLMError as exc:
            logger.warning("技术观察生成失败，改用规则归纳: %s", exc)
            return self._rule_based_observations(items)

        if isinstance(payload, dict):
            observations = payload.get("observations") or []
        elif isinstance(payload, list):
            observations = payload
        else:
            observations = []

        cleaned = [
            str(item).strip()
            for item in observations
            if str(item).strip()
        ]
        return cleaned[:4] if cleaned else self._rule_based_observations(items)

    def _observations_prompt(self, items: list[IntelItem]) -> str:
        """构造技术观察提示词。"""
        lines = [
            "请基于以下本期采集到的情报条目，归纳 2-4 个技术趋势。",
            "",
            '输出 JSON：{"observations": ["趋势1", "趋势2"]}',
            "",
            "本期条目：",
            "<<<UNTRUSTED_CONTENT>>>",
        ]
        for item in items[:40]:
            lines.append(
                f"- [{item.priority}] {item.title} | 来源: {item.source} | "
                f"类型: {item.content_type} | 关键词: {', '.join(item.relevance_keywords[:6])}"
            )
        lines.append("<<<END_UNTRUSTED_CONTENT>>>")
        return "\n".join(lines)

    @staticmethod
    def _rule_based_observations(items: list[IntelItem]) -> list[str]:
        """规则归纳技术观察（大模型不可用时的降级）。"""
        from collections import Counter

        keyword_counter: Counter[str] = Counter()
        for item in items:
            for keyword in item.relevance_keywords:
                keyword_counter[keyword] += 1

        observations: list[str] = []
        for keyword, count in keyword_counter.most_common(3):
            if count >= 2:
                observations.append(
                    f"本期有 {count} 条内容涉及「{keyword}」，该方向在本期样本中出现频率较高。"
                )

        vuln_count = sum(1 for item in items if item.cve_ids)
        if vuln_count:
            observations.append(
                f"本期包含 {vuln_count} 条带 CVE 编号的漏洞信息，建议对照厂商公告确认修复状态。"
            )

        paper_count = sum(1 for item in items if item.source_type == "paper")
        if paper_count:
            observations.append(
                f"本期收录论文 {paper_count} 篇，学术研究仍是本期信令安全情报的主要来源。"
            )

        return observations[:4]

    def _persist(self, result: PipelineResult) -> None:
        """把结果写入数据库。"""
        try:
            if result.run_id is None:
                assert result.window_start is not None and result.window_end is not None
                result.run_id = self.repository.start_run(
                    result.window_start,
                    result.window_end,
                    self.config.timezone,
                )

            self.repository.save_items(result.items, run_id=result.run_id)
            self.repository.update_run(
                result.run_id,
                status="completed",
                sources_ok=result.sources_ok,
                sources_failed=result.sources_failed,
                candidates=result.candidates,
                after_dedup=result.after_dedup,
                after_filter=result.after_filter,
                p1_count=len(result.p1_items),
                p2_count=len(result.p2_items),
                p3_count=len(result.p3_items),
                pending_count=len(result.pending_items),
                report_path=result.report_path,
            )
        except Exception as exc:  # noqa: BLE001 - 落库失败不应丢失报告
            logger.error("写入数据库失败: %s", exc)
