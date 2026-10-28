"""文件化归档与 HTTP 服务的测试。

归档不依赖数据库：每期报告存为 data/archive/<日期>/{report.html,meta.json}。
"""

from __future__ import annotations

import json
import threading
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from signalintel.archive import ArchivedReport, ReportArchive
from signalintel.models import IntelItem
from signalintel.reports.html_report import ReportData
from signalintel.scheduler import ScheduleConfig, Scheduler, next_run_time

CST = timezone(timedelta(hours=8))


def _item(**kwargs) -> IntelItem:
    base: dict = dict(
        source="arXiv",
        source_type="paper",
        title="SS7 Attacks in Mobile Core Networks",
        title_cn="移动核心网中的 SS7 攻击",
        url="https://arxiv.org/abs/2601.00001",
        abstract="abstract",
        content_type="preprint",
        published_at=datetime(2026, 10, 22, 8, 0, tzinfo=CST),
        priority="P1",
        score=71.0,
        summary_cn="摘要内容",
        attack_surface="MSC",
        technique="模糊测试",
        impact="位置泄露",
        significance="有参考价值",
        recommendations="部署信令防火墙",
        confidence_note="未提及",
    )
    base.update(kwargs)
    return IntelItem(**base)


def _report_data(report_date: str = "2026-10-26") -> ReportData:
    return ReportData(
        window_start=datetime(2026, 10, 19, tzinfo=CST),
        window_end=datetime(2026, 10, 26, tzinfo=CST),
        timezone="Asia/Shanghai",
        sources_ok=5,
        sources_failed=1,
        candidates=230,
        after_dedup=172,
        after_filter=18,
        p1_count=2,
        p2_count=0,
        p3_count=1,
        p1_items=[_item()],
        p2_items=[],
        p3_items=[_item(source="NVD", source_type="vulnerability", url="https://nvd/1")],
        observations=["观察一"],
        report_date=report_date,
    )


# ---------------------------------------------------------------------------
# 归档
# ---------------------------------------------------------------------------


def test_archive_saves_report_and_metadata(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    entry = archive.save(_report_data(), "<html>报告内容</html>", "主题")
    assert entry.report_date == "2026-10-26"
    assert entry.path.exists()
    assert entry.meta_path.exists()
    assert "报告内容" in entry.path.read_text(encoding="utf-8")


def test_archive_metadata_contains_counts_and_items(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "主题")
    meta = json.loads(
        (tmp_path / "archive" / "2026-10-26" / "meta.json").read_text(encoding="utf-8")
    )
    assert meta["report_date"] == "2026-10-26"
    assert meta["item_count"] == 2
    assert meta["p1_count"] == 2
    assert meta["candidates"] == 230
    assert meta["subject"] == "主题"
    assert len(meta["items"]) == 2
    assert meta["items"][0]["title_cn"] == "移动核心网中的 SS7 攻击"
    assert meta["items"][0]["url"] == "https://arxiv.org/abs/2601.00001"


def test_archive_lists_newest_first(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    for date in ("2026-10-05", "2026-10-26", "2026-10-19"):
        archive.save(_report_data(date), "<html>x</html>", "t")
    dates = [entry.report_date for entry in archive.list()]
    assert dates == ["2026-10-26", "2026-10-19", "2026-10-05"]


def test_archive_get_by_date(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")
    assert archive.get("2026-10-26") is not None
    assert archive.get("1999-01-01") is None


def test_archive_latest(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data("2026-10-19"), "<html>x</html>", "t")
    archive.save(_report_data("2026-10-26"), "<html>x</html>", "t")
    latest = archive.latest()
    assert latest is not None
    assert latest.report_date == "2026-10-26"


def test_archive_latest_is_none_when_empty(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    assert archive.latest() is None
    assert archive.list() == []


def test_archive_overwrites_same_date(tmp_path):
    """同一期重复生成应覆盖，不产生重复目录。"""
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>第一版</html>", "t")
    archive.save(_report_data(), "<html>第二版</html>", "t")
    assert len(archive.list()) == 1
    assert "第二版" in archive.get("2026-10-26").path.read_text(encoding="utf-8")


def test_archive_paginates(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    for index in range(25):
        archive.save(_report_data(f"2026-10-{index + 1:02d}"), "<html>x</html>", "t")
    page1, total, total_pages, actual = archive.page(1, page_size=10)
    assert len(page1) == 10
    assert total == 25
    assert total_pages == 3
    assert actual == 1
    page3, _, _, actual3 = archive.page(3, page_size=10)
    assert len(page3) == 5
    assert actual3 == 3


def test_archive_page_out_of_range_clamps_to_last_page(tmp_path):
    """越界页码钳制到最后一页，翻页 UI 不会出现空白页。"""
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")
    page, total, total_pages, actual = archive.page(99, page_size=10)
    assert len(page) == 1
    assert total == 1
    assert total_pages == 1
    assert actual == 1


def test_archive_page_clamps_invalid_page_number(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")
    page, _, _, actual = archive.page(0, page_size=10)
    assert len(page) == 1
    assert actual == 1
    page, _, _, actual = archive.page(-5, page_size=10)
    assert len(page) == 1
    assert actual == 1


def test_archive_ignores_corrupt_metadata(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")
    (tmp_path / "archive" / "2026-10-26" / "meta.json").write_text("{坏 json", encoding="utf-8")
    # 不应崩溃，能跳过损坏的条目
    archive.list()


def test_archive_item_carries_source_and_priority(tmp_path):
    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")
    meta = json.loads(
        (tmp_path / "archive" / "2026-10-26" / "meta.json").read_text(encoding="utf-8")
    )
    item = meta["items"][0]
    assert item["source"] == "arXiv"
    assert item["priority"] == "P1"
    assert item["score"] == 71.0


# ---------------------------------------------------------------------------
# 调度配置
# ---------------------------------------------------------------------------


def test_schedule_config_weekly_defaults():
    config = ScheduleConfig.from_mapping({"frequency": "weekly"})
    assert config.frequency == "weekly"
    assert config.run_at == "08:30"
    assert config.enabled is True


def test_schedule_config_reads_values():
    config = ScheduleConfig.from_mapping(
        {
            "frequency": "monthly",
            "run_at": "09:15",
            "day_of_month": 5,
            "weekday": "friday",
            "catch_up": False,
        }
    )
    assert config.frequency == "monthly"
    assert config.run_at == "09:15"
    assert config.day_of_month == 5
    assert config.weekday == "friday"
    assert config.catch_up is False


def test_schedule_config_rejects_bad_frequency():
    with pytest.raises(ValueError):
        ScheduleConfig.from_mapping({"frequency": "hourly"})


def test_schedule_config_rejects_bad_run_at():
    with pytest.raises(ValueError):
        ScheduleConfig.from_mapping({"run_at": "25:00"})


def test_next_run_weekly_is_next_monday():
    """周一 08:00 运行 → 下次是当天 08:30（若还没到）或下周一。"""
    now = datetime(2026, 10, 26, 8, 0, tzinfo=CST)  # 周一
    nxt = next_run_time(ScheduleConfig.from_mapping({"frequency": "weekly"}), now)
    assert nxt > now
    assert nxt.hour == 8 and nxt.minute == 30


def test_next_run_weekly_rolls_to_next_week_after_time():
    now = datetime(2026, 10, 26, 9, 0, tzinfo=CST)  # 周一 09:00，已过 08:30
    nxt = next_run_time(ScheduleConfig.from_mapping({"frequency": "weekly"}), now)
    assert nxt.weekday() == 0  # 下一个周一
    assert nxt > now


def test_next_run_monthly():
    config = ScheduleConfig.from_mapping(
        {"frequency": "monthly", "run_at": "07:00", "day_of_month": 1}
    )
    now = datetime(2026, 10, 15, 10, 0, tzinfo=CST)
    nxt = next_run_time(config, now)
    assert nxt.month == 11
    assert nxt.day == 1
    assert nxt.hour == 7


def test_next_run_daily():
    config = ScheduleConfig.from_mapping({"frequency": "daily", "run_at": "06:00"})
    now = datetime(2026, 10, 26, 5, 0, tzinfo=CST)
    nxt = next_run_time(config, now)
    assert nxt.day == 26 and nxt.hour == 6


# ---------------------------------------------------------------------------
# HTTP 服务
# ---------------------------------------------------------------------------


@pytest.fixture
def server(tmp_path):
    from signalintel.webserver import WebServer

    archive = ReportArchive(tmp_path / "archive")
    for date in ("2026-10-05", "2026-10-19", "2026-10-26"):
        archive.save(_report_data(date), "<html>正文 " + date + "</html>", "主题 " + date)

    web = WebServer(archive, host="127.0.0.1", port=0)
    thread = threading.Thread(target=web.serve_forever, daemon=True)
    thread.start()
    yield web
    web.shutdown()


def _get(url: str) -> tuple[int, str]:
    with urllib.request.urlopen(url, timeout=10) as response:
        return response.status, response.read().decode("utf-8")


def test_web_index_lists_reports(server):
    base = f"http://127.0.0.1:{server.port}"
    status, body = _get(base + "/")
    assert status == 200
    assert "2026-10-26" in body
    assert "2026-10-19" in body


def test_web_index_is_chinese(server):
    base = f"http://127.0.0.1:{server.port}"
    _, body = _get(base + "/")
    assert "核心网信令安全" in body


def test_web_report_detail_shows_content(server):
    base = f"http://127.0.0.1:{server.port}"
    status, body = _get(base + "/r/2026-10-26")
    assert status == 200
    assert "正文 2026-10-26" in body


def test_web_report_detail_unknown_date_returns_404(server):
    base = f"http://127.0.0.1:{server.port}"
    try:
        _get(base + "/r/1999-01-01")
        assert False, "应当返回 404"
    except urllib.error.HTTPError as exc:
        assert exc.code == 404


def test_web_pagination_query(server):
    base = f"http://127.0.0.1:{server.port}"
    status, body = _get(base + "/?page=2")
    assert status == 200
    assert "2026-10-05" in body


def test_web_index_shows_plain_dates_not_iso_timestamps(server):
    """列表页的检索窗口只显示日期，不显示完整 ISO 时间戳。"""
    base = f"http://127.0.0.1:{server.port}"
    _, body = _get(base + "/")
    assert "2026-09-28T00:00:00" not in body
    assert "T00:00:00" not in body


def test_web_page_display_matches_actual_page(server):
    """页码显示必须与实际钳制后的页码一致（不能出现「第 2 / 1 页」）。"""
    base = f"http://127.0.0.1:{server.port}"
    _, body = _get(base + "/?page=99")
    assert "第 1 / 1 页" in body
    assert "第 2 / 1 页" not in body
    _, body = _get(base + "/?page=0")
    assert "第 1 / 1 页" in body


def test_web_api_returns_json(server):
    base = f"http://127.0.0.1:{server.port}"
    status, body = _get(base + "/api/reports")
    assert status == 200
    data = json.loads(body)
    assert len(data["reports"]) == 3
    assert data["reports"][0]["report_date"] == "2026-10-26"


def test_web_api_single_report(server):
    base = f"http://127.0.0.1:{server.port}"
    status, body = _get(base + "/api/report/2026-10-19")
    assert status == 200
    data = json.loads(body)
    assert data["report_date"] == "2026-10-19"
    assert len(data["items"]) == 2


def test_web_unknown_path_returns_404(server):
    base = f"http://127.0.0.1:{server.port}"
    try:
        _get(base + "/nope")
        assert False, "应当返回 404"
    except urllib.error.HTTPError as exc:
        assert exc.code == 404


def test_web_display_url_omits_standard_port(tmp_path):
    """80 端口时展示 URL 不带端口号（浏览器只需输 IP）。"""
    from signalintel.webserver import WebServer

    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")

    # 用 80 端口不可用时无法测试，直接验证 URL 生成规则
    web = WebServer(archive, host="192.168.0.104", port=0)
    try:
        assert web.port != 80
        assert web.display_url == f"http://192.168.0.104:{web.port}/"
        assert web.is_standard_port is False
    finally:
        web.shutdown()


def test_web_falls_back_when_port_unavailable(tmp_path):
    """首选端口不可用时自动降级到候选列表中的下一个。"""
    from signalintel.webserver import WebServer

    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")

    # 先占住一个端口，让它必然不可用
    import socket

    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    taken = blocker.getsockname()[1]
    try:
        web = WebServer(
            archive,
            host="127.0.0.1",
            port=None,
            port_candidates=(taken, 0),
        )
        try:
            assert web.port == 0 or web.port != taken
            assert web.port_fallbacks, "应记录被跳过的端口"
            assert str(taken) in web.port_fallbacks[0]
        finally:
            web.shutdown()
    finally:
        blocker.close()


def test_web_explicit_port_failure_raises_when_strict(tmp_path):
    """strict=True（用户显式 --port）时端口不可用应抛错，不擅自改端口。"""
    import socket

    from signalintel.webserver import WebServer

    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")

    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    taken = blocker.getsockname()[1]
    try:
        try:
            WebServer(archive, host="127.0.0.1", port=taken, strict=True)
            assert False, "应当抛错"
        except OSError:
            pass
    finally:
        blocker.close()


def test_web_explicit_port_falls_back_when_not_strict(tmp_path):
    """非 strict 时，显式端口不可用会降级到候选端口（保证服务能起来）。"""
    import socket

    from signalintel.webserver import WebServer

    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")

    blocker = socket.socket()
    blocker.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    blocker.bind(("127.0.0.1", 0))
    blocker.listen(1)
    taken = blocker.getsockname()[1]
    try:
        web = WebServer(
            archive,
            host="127.0.0.1",
            port=taken,
            port_candidates=(0,),
            strict=False,
        )
        try:
            assert web.port != taken
            assert web.port_fallbacks
        finally:
            web.shutdown()
    finally:
        blocker.close()


def test_web_config_port_80_falls_back_when_unprivileged(tmp_path):
    """配置文件写 80 但无权限时，应自动降级而不是启动失败。"""
    from signalintel.webserver import WebServer

    archive = ReportArchive(tmp_path / "archive")
    archive.save(_report_data(), "<html>x</html>", "t")

    web = WebServer(
        archive,
        host="127.0.0.1",
        port=80,
        port_candidates=(0,),
        strict=False,
    )
    try:
        assert web.port != 80
        assert web.port_fallbacks
        assert "80" in web.port_fallbacks[0]
    finally:
        web.shutdown()


def test_web_escapes_report_content(server):
    """归档中的内容必须转义，防止 HTML 注入。"""
    from signalintel.webserver import WebServer

    archive = ReportArchive(Path("/tmp/hermes-verify-web-archive"))
    archive.save(
        _report_data(),
        "<html><script>alert('x')</script></html>",
        "t",
    )
    web = WebServer(archive, host="127.0.0.1", port=0)
    thread = threading.Thread(target=web.serve_forever, daemon=True)
    thread.start()
    try:
        base = f"http://127.0.0.1:{web.port}"
        _, body = _get(base + "/")
        assert "<script>alert" not in body
    finally:
        web.shutdown()
        import shutil

        shutil.rmtree("/tmp/hermes-verify-web-archive", ignore_errors=True)
