#!/usr/bin/env python3
"""端到端冒烟脚本（ad-hoc, not suite green）。

用真实网络采集 + 假 LLM（不消耗 API 额度）跑完整流水线，
产出真实 HTML 报告并检查内容。用法：

    python3 scripts/smoke_e2e.py [--days 7]
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timedelta
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from signalintel.collectors.registry import build_collectors, run_collectors  # noqa: E402
from signalintel.config import load_config  # noqa: E402
from signalintel.pipeline import Pipeline  # noqa: E402
from signalintel.storage.database import Database  # noqa: E402
from signalintel.storage.repository import Repository  # noqa: E402
from signalintel.utils.dates import now_in_tz  # noqa: E402
from signalintel.utils.http import HttpClient  # noqa: E402


class FakeLLM:
    """假大模型，用于无 API Key 时验证流水线。"""

    def complete_one(self, system_prompt: str, user_prompt: str, json_mode: bool = True):
        if "关联等级" in user_prompt or "判定下面" in user_prompt:
            return {
                "priority": "P1",
                "reason": "直接涉及核心网信令攻防",
                "protocols": ["SS7"],
                "attack_surface": ["MSC"],
            }
        if "技术趋势" in user_prompt:
            return {"observations": ["本期样本中与 SS7 / Diameter 相关的攻击研究较为集中。"]}
        return {
            "title_cn": "（假 LLM）中文标题占位",
            "summary_cn": "这是冒烟测试用的假摘要，用于验证报告渲染链路是否正常，"
            "不代表真实内容。",
            "attack_surface": "MSC、HLR",
            "technique": "协议模糊测试",
            "impact": "可能导致用户位置信息泄露",
            "significance": "对运营商核心网信令防护有参考价值",
            "recommendations": "部署信令防火墙并校验关键字段",
            "confidence_note": "未提及",
        }

    def complete_batch(self, system_prompt, user_prompt, items, max_batch_size=None):
        return [self.complete_one(system_prompt, user_prompt) for _ in items]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--days", type=int, default=7)
    parser.add_argument("--out", default="/tmp/signalintel-smoke")
    args = parser.parse_args()

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    config = load_config()
    config.data_dir = out_dir
    config.db_path = out_dir / "smoke.db"

    db = Database(config.db_path)
    db.migrate()
    repo = Repository(db)

    end = now_in_tz(config.timezone)
    start = end - timedelta(days=args.days)

    http_client = HttpClient(timeout=25, max_retries=2, min_interval=1.2)
    collectors = build_collectors(config.sources, http_client=http_client)
    print(f"启用来源 {len(collectors)} 个，窗口 {start} ~ {end}")

    results = run_collectors(collectors, start, end)
    for result in results:
        print(
            f"  {result.source_name:24s} items={len(result.items):3d} "
            f"pending={len(result.pending_items):3d} errors={len(result.errors)}"
        )

    pipeline = Pipeline(config, repo, llm=FakeLLM())
    result = pipeline.run(results, start, end, report_date=end.strftime("%Y-%m-%d"))

    print("\n=== 流水线结果 ===")
    print(f"候选        : {result.candidates}")
    print(f"去重后      : {result.after_dedup}")
    print(f"关键词筛选后: {result.after_filter}")
    print(f"P1/P2/P3    : {len(result.p1_items)}/{len(result.p2_items)}/{len(result.p3_items)}")
    print(f"待核实      : {result.pending_count}")
    print(f"报告        : {result.report_path}")
    print(f"主题        : {result.subject}")

    report = Path(result.report_path).read_text(encoding="utf-8")
    checks = {
        "概览": "本期概览",
        "P1 章节": "高优先级情报",
        "论文章节": "学术论文精选",
        "新闻章节": "安全新闻与漏洞公告",
        "技术观察": "本期技术观察",
        "来源索引": "来源索引",
        "观察免责声明": "基于本期样本",
        "无脚本注入": "<script>alert",
    }
    print("\n=== 报告内容检查 ===")
    ok = True
    for name, needle in checks.items():
        present = needle in report
        expected = name != "无脚本注入"
        status = "OK" if present == expected else "FAIL"
        if present != expected:
            ok = False
        print(f"  [{status}] {name}: {'包含' if present else '未包含'} {needle!r}")

    print(f"\n报告大小: {len(report)} 字符")
    db.close()
    http_client.close()
    print("SMOKE RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
