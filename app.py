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
import time
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
from signalintel.utils.dates import (  # noqa: E402
    ensure_aware,
    get_tz,
    now_in_tz,
    parse_date_string,
)
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


def cmd_serve(args: argparse.Namespace, config: AppConfig) -> int:
    """启动周期调度 + HTTP 服务（一条命令搞定）。"""
    import signal

    from signalintel.archive import ReportArchive
    from signalintel.scheduler import ScheduleConfig, Scheduler
    from signalintel.webserver import WebServer

    schedule_raw = dict(config.schedule_raw.get("schedule", {}) or {})
    web_raw = dict(config.web_raw or {})

    # 命令行覆盖 YAML
    if getattr(args, "no_schedule", False):
        schedule_raw["enabled"] = False
    if getattr(args, "no_web", False):
        web_raw["enabled"] = False
    if getattr(args, "host", None):
        web_raw["host"] = args.host
    if getattr(args, "port", None):
        web_raw["port"] = args.port

    try:
        schedule = ScheduleConfig.from_mapping(schedule_raw)
    except ValueError as exc:
        logger.error("调度配置有误: %s", exc)
        return 2

    archive = ReportArchive(config.data_dir / "archive")

    logger.info("=" * 60)
    logger.info("核心网信令安全情报自动订阅系统 —— 常驻服务")
    logger.info("=" * 60)
    logger.info(
        "调度频率: %s %s%s",
        schedule.frequency,
        schedule.run_at,
        f"（{schedule.weekday}）" if schedule.frequency == "weekly" else "",
    )
    logger.info("归档目录: %s", archive.root)
    existing = archive.list()
    logger.info("已有归档: %s 期", len(existing))
    if existing:
        logger.info("最近一期: %s", existing[0].report_date)

    # ---- HTTP 服务 ----
    web_server: Optional[WebServer] = None
    if web_raw.get("enabled", True):
        host = str(web_raw.get("host", "127.0.0.1"))
        port = int(web_raw.get("port", 8765))
        web_server = WebServer(archive, host=host, port=port)
        web_server.start_background()
        logger.info("HTTP 服务: %s", web_server.url)
        logger.info("  列表页 : %s", web_server.url)
        logger.info("  最新一期: %s/r/%s", web_server.url, existing[0].report_date if existing else "<待生成>")
    else:
        logger.info("HTTP 服务已禁用")

    # ---- 调度器 ----
    scheduler: Optional[Scheduler] = None
    if schedule.enabled and schedule_raw.get("enabled", True):
        scheduler = Scheduler(
            job=lambda when: _run_scheduled_task(config, when),
            config=schedule,
        )
        scheduler.start()
        logger.info("下次运行: %s", scheduler.next_run().strftime("%Y-%m-%d %H:%M"))
    else:
        logger.info("周期调度已禁用")

    if web_server is None and scheduler is None:
        logger.error("调度与 HTTP 服务都未启用，无事可做。退出。")
        return 2

    # --run-now：立即执行一次完整任务（采集 → 报告 → 发信）
    if getattr(args, "run_now", False):
        logger.info("立即执行一次任务…")
        try:
            _run_scheduled_task(config, now_in_tz(config.timezone))
        except Exception as exc:  # noqa: BLE001
            logger.exception("立即执行失败: %s", exc)

    # ---- 等待退出 ----
    logger.info("服务运行中，按 Ctrl+C 退出")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("收到中断信号，正在退出…")

    if scheduler is not None:
        scheduler.stop()
    if web_server is not None:
        web_server.shutdown()
    logger.info("已退出")
    return 0


def _run_scheduled_task(config: AppConfig, when: datetime) -> None:
    """调度任务：采集 → 分析 → 报告 → 归档 → 发邮件。

    复用 ``cmd_run`` 的完整流程，保证行为与手动运行完全一致。
    """
    from signalintel.collectors.registry import build_collectors, run_collectors
    from signalintel.llm.client import LLMClient
    from signalintel.pipeline import Pipeline
    from signalintel.storage.database import Database
    from signalintel.storage.repository import Repository
    from signalintel.utils.http import HttpClient

    tz = config.timezone
    end = when.astimezone(get_tz(tz))
    start = end - timedelta(days=config.window_days)

    logger.info("=== 调度任务开始（窗口 %s ~ %s）===", start, end)

    db = Database(config.db_path)
    db.migrate()
    repository = Repository(db)
    run_id = repository.start_run(start, end, tz, mode="scheduled")

    http_client = HttpClient(timeout=30.0, max_retries=3, min_interval=1.0)
    collectors = build_collectors(config.sources, http_client=http_client)
    collector_results = run_collectors(collectors, start, end)

    llm = LLMClient(config.llm) if config.llm.is_configured else None
    pipeline = Pipeline(config, repository, llm=llm)
    result = pipeline.run(
        collector_results,
        start,
        end,
        mode="scheduled",
        report_date=end.strftime("%Y-%m-%d"),
    )
    result.run_id = run_id

    if config.smtp.is_configured:
        html = Path(result.report_path).read_text(encoding="utf-8")
        send_result = EmailSender(config.smtp).send(result.subject, html)
        if send_result.success:
            result.email_sent = True
            logger.info("邮件已发送: %s", ", ".join(send_result.recipients))
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
    else:
        logger.warning("SMTP 配置不完整，跳过邮件发送")

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
    logger.info("=== 调度任务结束（入选 %s 条）===", result.total_selected)


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

    serve_parser = sub.add_parser(
        "serve",
        help="启动周期调度 + HTTP 归档页面（常驻服务）",
    )
    serve_parser.add_argument(
        "--host", help="HTTP 监听地址，覆盖 config/schedule.yaml"
    )
    serve_parser.add_argument(
        "--port", type=int, help="HTTP 监听端口，覆盖 config/schedule.yaml"
    )
    serve_parser.add_argument(
        "--no-web", action="store_true", help="不启动 HTTP 服务，只跑调度"
    )
    serve_parser.add_argument(
        "--no-schedule", action="store_true", help="不启动调度，只提供 HTTP 服务"
    )
    serve_parser.add_argument(
        "--run-now",
        action="store_true",
        help="立即执行一次采集+发信，然后进入常驻等待",
    )
    serve_parser.set_defaults(func=cmd_serve)

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
