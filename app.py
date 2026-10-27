#!/usr/bin/env python3
"""核心网信令安全情报自动订阅系统 —— 命令行入口。

常用命令::

    # 完整流程（采集 → 分析 → 报告 → 发邮件）
    python app.py run

    # 只采集，不调用大模型
    python app.py run --mode collect

    # 只生成报告，不发送邮件
    python app.py run --dry-run

    # 补采指定日期范围
    python app.py run --start 2026-10-01 --end 2026-10-20

    # 只对历史候选内容生成摘要
    python app.py summarize --limit 20

    # 查看最近一次任务状态
    python app.py status
"""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional

# 允许以 `python signalintel/app.py` 或 `python app.py` 两种方式启动
if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from signalintel.config import AppConfig, load_config  # noqa: E402
from signalintel.llm.client import LLMClient  # noqa: E402
from signalintel.notifications.email_sender import EmailSender  # noqa: E402
from signalintel.pipeline import Pipeline  # noqa: E402
from signalintel.storage.database import Database  # noqa: E402
from signalintel.storage.repository import Repository  # noqa: E402
from signalintel.utils.dates import ensure_aware, now_in_tz, parse_date_string  # noqa: E402
from signalintel.utils.http import HttpClient  # noqa: E402

logger = logging.getLogger("signalintel")

__all__ = ["main", "setup_logging"]


# ---------------------------------------------------------------------------
# 日志
# ---------------------------------------------------------------------------


def setup_logging(log_dir: Path, verbose: bool = False) -> None:
    """配置日志（文件 + 控制台）。"""
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "signalintel.log"

    level = logging.DEBUG if verbose else logging.INFO
    formatter = logging.Formatter(
        "%(asctime)s %(levelname)-8s [%(name)s] %(message)s", "%Y-%m-%d %H:%M:%S"
    )

    root = logging.getLogger()
    root.setLevel(level)
    for handler in list(root.handlers):
        root.removeHandler(handler)

    file_handler = logging.FileHandler(log_file, encoding="utf-8")
    file_handler.setFormatter(formatter)
    file_handler.setLevel(level)
    root.addHandler(file_handler)

    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(formatter)
    console.setLevel(level)
    root.addHandler(console)

    # 降低第三方库噪音
    logging.getLogger("urllib3").setLevel(logging.WARNING)


# ---------------------------------------------------------------------------
# 时间窗口
# ---------------------------------------------------------------------------


def resolve_window(
    config: AppConfig, start_arg: Optional[str], end_arg: Optional[str]
) -> tuple[datetime, datetime]:
    """解析时间窗口。"""
    tz = config.timezone
    end = parse_date_string(end_arg, tz) if end_arg else now_in_tz(tz)
    if end is None:
        end = now_in_tz(tz)
    if start_arg:
        start = parse_date_string(start_arg, tz)
        if start is None:
            raise SystemExit(f"无法解析起始日期: {start_arg}")
    else:
        start = end - timedelta(days=config.window_days)
    return ensure_aware(start, tz), ensure_aware(end, tz)


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------


def cmd_run(args: argparse.Namespace, config: AppConfig) -> int:
    """执行采集与分析流程。"""
    from signalintel.collectors.registry import build_collectors, run_collectors

    start, end = resolve_window(config, args.start, args.end)
    logger.info("时间窗口：%s ~ %s (%s)", start, end, config.timezone)

    db = Database(config.db_path)
    db.migrate()
    repository = Repository(db)

    run_id = repository.start_run(start, end, config.timezone, mode=args.mode)
    logger.info("任务开始，run_id=%s", run_id)

    http_client = HttpClient(
        timeout=float(args.http_timeout),
        max_retries=int(args.http_retries),
        min_interval=float(args.min_interval),
    )

    collectors = build_collectors(config.sources, http_client=http_client)
    logger.info("已启用 %s 个数据源", len(collectors))

    if args.mode == "collect":
        collector_results = run_collectors(collectors, start, end)
        total = 0
        for collector_result in collector_results:
            logger.info(
                "  %s: %s 条（错误 %s）",
                collector_result.source_name,
                len(collector_result.items),
                len(collector_result.errors),
            )
            total += len(collector_result.items)
        repository.update_run(
            run_id,
            status="completed",
            candidates=total,
            sources_ok=sum(
                1 for r in collector_results if not r.errors and not r.skipped
            ),
            sources_failed=sum(
                1 for r in collector_results if r.errors or r.skipped
            ),
        )
        logger.info("仅采集模式完成，共 %s 条候选内容", total)
        http_client.close()
        db.close()
        return 0

    collector_results = run_collectors(collectors, start, end)

    llm: Optional[LLMClient] = None
    if args.mode != "collect" and config.llm.is_configured:
        llm = LLMClient(config.llm)
    elif args.mode != "collect":
        logger.warning("未配置 LLM_API_KEY，将跳过分类与摘要阶段")

    pipeline = Pipeline(config, repository, llm=llm)
    result = pipeline.run(
        collector_results,
        start,
        end,
        mode=args.mode,
        report_date=end.strftime("%Y-%m-%d"),
    )
    result.run_id = run_id

    logger.info(
        "报告已生成：%s（入选 %s 条）", result.report_path, result.total_selected
    )

    # 发送邮件
    if args.dry_run:
        logger.info("dry-run 模式：跳过邮件发送")
    elif not config.smtp.is_configured:
        logger.warning("SMTP 配置不完整，跳过邮件发送")
    else:
        html = Path(result.report_path).read_text(encoding="utf-8")
        sender = EmailSender(config.smtp)
        send_result = sender.send(result.subject, html)
        if send_result.success:
            result.email_sent = True
            logger.info("邮件发送成功：%s", ", ".join(send_result.recipients))
        else:
            result.email_error = send_result.error
            logger.error("邮件发送失败: %s", send_result.error)

        repository.record_sent_report(
            run_id=run_id,
            report_date=result.report_date,
            subject=result.subject,
            recipients=send_result.recipients,
            item_count=result.total_selected,
            status="sent" if send_result.success else "failed",
            error=send_result.error,
        )

    repository.update_run(
        run_id,
        status="completed",
        email_sent=1 if result.email_sent else 0,
        error=result.email_error,
    )

    if llm is not None:
        llm.close()
    http_client.close()
    db.close()
    return 0


def cmd_summarize(args: argparse.Namespace, config: AppConfig) -> int:
    """只对历史候选内容生成中文摘要。"""
    if not config.llm.is_configured:
        logger.error("未配置 LLM_API_KEY，无法生成摘要")
        return 2

    db = Database(config.db_path)
    db.migrate()
    repository = Repository(db)

    items = repository.get_unsummarized(limit=args.limit)
    if not items:
        logger.info("没有需要生成摘要的历史条目")
        db.close()
        return 0

    logger.info("待处理条目 %s 条", len(items))
    llm = LLMClient(config.llm)
    from signalintel.processors.summarize import Summarizer

    summarizer = Summarizer(llm)
    results = summarizer.summarize_batch(items)

    ok = 0
    for result in results:
        if result.ok and result.item is not None:
            repository.save_item(result.item)
            ok += 1
        elif result.error:
            logger.warning("摘要失败: %s", result.error)

    logger.info("完成：成功 %s 条，失败 %s 条", ok, len(items) - ok)
    llm.close()
    db.close()
    return 0


def cmd_report(args: argparse.Namespace, config: AppConfig) -> int:
    """只生成 HTML 报告（不采集、不发邮件）。"""
    from signalintel.reports.html_report import ReportBuilder, ReportData

    start, end = resolve_window(config, args.start, args.end)
    db = Database(config.db_path)
    db.migrate()
    repository = Repository(db)

    items = repository.get_items_in_window(start, end, limit=args.limit)
    logger.info("从数据库读取 %s 条条目", len(items))

    p1 = [i for i in items if i.priority == "P1"]
    p2 = [i for i in items if i.priority == "P2"]
    p3 = [i for i in items if i.priority == "P3"]

    data = ReportData(
        window_start=start,
        window_end=end,
        timezone=config.timezone,
        sources_ok=0,
        sources_failed=0,
        candidates=len(items),
        after_dedup=len(items),
        after_filter=len(items),
        p1_count=len(p1),
        p2_count=len(p2),
        p3_count=len(p3),
        p1_items=p1,
        p2_items=p2,
        p3_items=p3,
        report_date=end.strftime("%Y-%m-%d"),
    )

    builder = ReportBuilder(output_dir=config.data_dir / "reports")
    path = builder.build(data)
    logger.info("报告已生成: %s", path)
    db.close()
    return 0


def cmd_status(args: argparse.Namespace, config: AppConfig) -> int:
    """查看最近一次任务状态与日志。"""
    db = Database(config.db_path)
    db.migrate()
    repository = Repository(db)

    last = repository.get_last_run()
    if last is None:
        print("尚无任务记录")
        db.close()
        return 0

    print("最近一次任务：")
    for key, value in last.to_dict().items():
        print(f"  {key}: {value}")

    print("\n最近发送记录：")
    for record in repository.get_sent_reports(limit=5):
        print(
            f"  [{record['status']}] {record['report_date']} "
            f"{record['subject']} → {record['recipients']}"
        )

    log_file = config.log_dir / "signalintel.log"
    if log_file.exists():
        print(f"\n日志文件：{log_file}")
        lines = log_file.read_text(encoding="utf-8", errors="replace").splitlines()
        print("--- 最近 20 行 ---")
        for line in lines[-20:]:
            print(line)

    db.close()
    return 0


def cmd_init(args: argparse.Namespace, config: AppConfig) -> int:
    """初始化数据库。"""
    db = Database(config.db_path)
    version = db.migrate()
    print(f"数据库已初始化：{config.db_path}（schema v{version}）")
    db.close()
    return 0


# ---------------------------------------------------------------------------
# 参数解析
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="signalintel",
        description="核心网信令安全情报自动订阅系统",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="输出调试日志")
    parser.add_argument("--config-dir", help="配置文件目录（默认 ./config）")

    sub = parser.add_subparsers(dest="command")

    run_parser = sub.add_parser("run", help="执行采集与分析流程")
    run_parser.add_argument(
        "--mode",
        choices=["full", "collect"],
        default="full",
        help="full=完整流程（默认），collect=只采集不调用大模型",
    )
    run_parser.add_argument("--start", help="起始日期（YYYY-MM-DD），默认今天往前 7 天")
    run_parser.add_argument("--end", help="结束日期（YYYY-MM-DD），默认当前时间")
    run_parser.add_argument(
        "--dry-run", action="store_true", help="生成报告但不发送邮件"
    )
    run_parser.add_argument("--http-timeout", type=float, default=30.0)
    run_parser.add_argument("--http-retries", type=int, default=3)
    run_parser.add_argument(
        "--min-interval", type=float, default=1.0, help="同一来源两次请求的最小间隔（秒）"
    )
    run_parser.set_defaults(func=cmd_run)

    summarize_parser = sub.add_parser("summarize", help="只对历史候选内容生成摘要")
    summarize_parser.add_argument("--limit", type=int, default=20)
    summarize_parser.set_defaults(func=cmd_summarize)

    report_parser = sub.add_parser("report", help="只生成 HTML 报告")
    report_parser.add_argument("--start")
    report_parser.add_argument("--end")
    report_parser.add_argument("--limit", type=int, default=100)
    report_parser.set_defaults(func=cmd_report)

    status_parser = sub.add_parser("status", help="查看最近一次任务状态")
    status_parser.set_defaults(func=cmd_status)

    init_parser = sub.add_parser("init", help="初始化数据库")
    init_parser.set_defaults(func=cmd_init)

    return parser


def main(argv: Optional[list[str]] = None) -> int:
    """命令行入口。"""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not getattr(args, "command", None):
        parser.print_help()
        return 1

    config_dir = Path(args.config_dir) if args.config_dir else None
    config = load_config(config_dir)
    setup_logging(config.log_dir, verbose=args.verbose)

    logger.info("=" * 60)
    logger.info("核心网信令安全情报自动订阅系统")
    logger.info("=" * 60)

    try:
        return int(args.func(args, config))
    except KeyboardInterrupt:
        logger.warning("已被用户中断")
        return 130
    except Exception as exc:  # noqa: BLE001
        logger.exception("执行失败: %s", exc)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
