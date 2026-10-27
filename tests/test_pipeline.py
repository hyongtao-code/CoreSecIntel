"""端到端流水线测试（使用假 LLM 与假采集器，不联网）。

验证：采集结果 → 去重 → 筛选 → 分类 → 评分 → 摘要 → 报告 的完整链路，
以及数据库落库与状态记录。
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

from signalintel.collectors.base import CollectorResult
from signalintel.config import AppConfig
from signalintel.models import IntelItem
from signalintel.pipeline import Pipeline
from signalintel.storage.database import Database
from signalintel.storage.repository import Repository

CST = timezone(timedelta(hours=8))

START = datetime(2026, 10, 20, 0, 0, tzinfo=CST)
END = datetime(2026, 10, 27, 0, 0, tzinfo=CST)


class FakeLLM:
    """假大模型：分类返回 P1/P2，摘要返回固定内容。"""

    def __init__(self) -> None:
        self.calls = 0

    def complete_one(self, system_prompt: str, user_prompt: str, json_mode: bool = True) -> Any:
        self.calls += 1
        if "判定下面这条内容" in user_prompt or "关联等级" in user_prompt:
            return {
                "priority": "P1",
                "reason": "直接涉及核心网信令攻击",
                "protocols": ["SS7"],
                "attack_surface": ["MSC"],
            }
        if "归纳" in user_prompt and "技术趋势" in user_prompt:
            return {"observations": ["SS7 相关攻击研究在本期样本中出现频率较高。"]}
        return {
            "title_cn": "移动核心网 SS7 攻击分析",
            "summary_cn": "本文分析了 SS7 在核心网中的攻击面与防护方法，"
            "包括状态机建模、协议模糊测试与信令防火墙部署建议。",
            "attack_surface": "MSC、HLR",
            "technique": "协议模糊测试",
            "impact": "可能导致用户位置泄露",
            "significance": "对运营商信令防护有参考价值",
            "recommendations": "部署信令防火墙",
            "confidence_note": "未提及",
        }

    def complete_batch(
        self,
        system_prompt: str,
        user_prompt: str,
        items: list[Any],
        max_batch_size: Optional[int] = None,
    ) -> list[Any]:
        self.calls += 1
        return [self.complete_one(system_prompt, user_prompt) for _ in items]


def _item(**kwargs: Any) -> IntelItem:
    base: dict[str, Any] = dict(
        source="arXiv",
        source_type="paper",
        title="SS7 Attack Analysis in Mobile Core Networks",
        url="https://arxiv.org/abs/2601.00001",
        abstract="We study SS7 attacks on the HLR and propose a signaling firewall.",
        content_type="preprint",
        published_at=datetime(2026, 10, 22, 8, 0, tzinfo=CST),
        is_preprint=True,
        trust_score=0.85,
    )
    base.update(kwargs)
    return IntelItem(**base)


def _config(tmp_path: Path) -> AppConfig:
    cfg = AppConfig(
        timezone="Asia/Shanghai",
        window_days=7,
        data_dir=tmp_path / "data",
        log_dir=tmp_path / "logs",
        db_path=tmp_path / "data" / "test.db",
    )
    cfg.score_weights = {"relevance": 0.40, "novelty": 0.25, "impact": 0.20, "source_trust": 0.15}
    cfg.min_score_for_report = 0.0
    cfg.keywords_raw = {
        "keywords": {
            "protocols": ["SS7", "Diameter", "GTP-C", "SIP"],
            "network_elements": ["MSC", "HLR", "AMF"],
            "attack_types": ["attack", "vulnerability", "fuzzing"],
            "topics": ["signaling security", "telecom security"],
            "chinese_keywords": ["信令安全"],
            "exclusions": ["ransomware", "phishing"],
            "min_matches": 1,
        },
        "scoring": {
            "weights": {
                "relevance": 0.40,
                "novelty": 0.25,
                "impact": 0.20,
                "source_trust": 0.15,
            },
            "min_score": 0,
            "max_items": 30,
        },
    }
    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    return cfg


def test_pipeline_end_to_end(tmp_path):
    cfg = _config(tmp_path)
    db = Database(cfg.db_path)
    db.migrate()
    repo = Repository(db)

    collector_result = CollectorResult(source_name="arXiv")
    collector_result.items = [
        _item(),
        _item(
            source="IEEE Xplore",
            source_type="news",
            title="Diameter Routing Attack Disclosed in 5G Core",
            url="https://ieeexplore.ieee.org/document/1",
            content_type="news",
            cve_ids=["CVE-2026-12345"],
            published_at=datetime(2026, 10, 23, 8, 0, tzinfo=CST),
        ),
        # 无关内容，应被关键词过滤掉
        _item(
            title="Generic Web Buffer Overflow Study",
            url="https://arxiv.org/abs/2601.99999",
            abstract="A heap overflow in an image parser.",
            relevance_keywords=[],
        ),
    ]

    pipeline = Pipeline(cfg, repo, llm=FakeLLM())
    result = pipeline.run([collector_result], START, END, report_date="2026-10-27")

    # 统计
    assert result.candidates == 3
    assert result.after_dedup == 3
    assert result.after_filter == 2
    assert len(result.p1_items) == 2

    # 摘要已写入
    assert result.p1_items[0].summary_cn != ""
    assert result.p1_items[0].title_cn == "移动核心网 SS7 攻击分析"

    # 报告已生成
    assert result.report_path
    report = Path(result.report_path).read_text(encoding="utf-8")
    assert "核心网信令安全" in report
    assert "移动核心网 SS7 攻击分析" in report

    # 主题
    assert "2026-10-27" in result.subject

    # 技术观察
    assert result.observations

    # 数据库已落库
    assert repo.count("items") == 2
    last_run = repo.get_last_run()
    assert last_run is not None
    assert last_run.status == "completed"
    assert last_run.after_filter == 2

    db.close()


def test_pipeline_persists_and_allows_reload(tmp_path):
    cfg = _config(tmp_path)
    db = Database(cfg.db_path)
    db.migrate()
    repo = Repository(db)

    collector_result = CollectorResult(source_name="arXiv")
    collector_result.items = [_item()]

    pipeline = Pipeline(cfg, repo, llm=FakeLLM())
    pipeline.run([collector_result], START, END, report_date="2026-10-27")

    items = repo.get_items_in_window(START, END)
    assert len(items) == 1
    assert items[0].priority == "P1"
    assert items[0].score is not None

    db.close()


def test_pipeline_marks_items_without_date_as_pending(tmp_path):
    cfg = _config(tmp_path)
    db = Database(cfg.db_path)
    db.migrate()
    repo = Repository(db)

    collector_result = CollectorResult(source_name="web")
    collector_result.pending_items = [_item(published_at=None)]

    pipeline = Pipeline(cfg, repo, llm=FakeLLM())
    result = pipeline.run([collector_result], START, END, report_date="2026-10-27")

    assert result.pending_count == 1
    assert result.total_selected == 0

    db.close()


def test_pipeline_without_llm_still_produces_report(tmp_path):
    """未配置大模型时降级为规则判定，流程不中断。"""
    cfg = _config(tmp_path)
    db = Database(cfg.db_path)
    db.migrate()
    repo = Repository(db)

    collector_result = CollectorResult(source_name="arXiv")
    collector_result.items = [_item()]

    pipeline = Pipeline(cfg, repo, llm=None)
    result = pipeline.run([collector_result], START, END, report_date="2026-10-27")

    assert result.report_path
    assert Path(result.report_path).exists()
    assert len(result.p1_items) == 1

    db.close()


def test_pipeline_reports_observation_disclaimer(tmp_path):
    cfg = _config(tmp_path)
    db = Database(cfg.db_path)
    db.migrate()
    repo = Repository(db)

    collector_result = CollectorResult(source_name="arXiv")
    collector_result.items = [_item()]

    pipeline = Pipeline(cfg, repo, llm=FakeLLM())
    result = pipeline.run([collector_result], START, END, report_date="2026-10-27")

    report = Path(result.report_path).read_text(encoding="utf-8")
    assert "基于本期样本" in report

    db.close()
