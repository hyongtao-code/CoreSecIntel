"""时间窗口与日期解析相关测试。"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from signalintel.utils.dates import (
    DateParseError,
    ensure_aware,
    iso_to_datetime,
    now_in_tz,
    parse_date_string,
    time_window,
    within_window,
    CST,
)


def test_now_in_tz_returns_aware_datetime():
    now = now_in_tz("Asia/Shanghai")
    assert now.tzinfo is not None
    assert now.utcoffset() == timedelta(hours=8)


def test_time_window_default_is_seven_days():
    end = now_in_tz("Asia/Shanghai")
    start, end = time_window(end, days=7)
    assert (end - start) == timedelta(days=7)


def test_time_window_end_is_exclusive_boundary_semantics():
    end = datetime(2026, 10, 27, 12, 0, 0, tzinfo=CST)
    start, window_end = time_window(end, days=7)
    assert window_end == end
    assert start == datetime(2026, 10, 20, 12, 0, 0, tzinfo=CST)


def test_within_window_inclusive_on_start_exclusive_on_end():
    end = datetime(2026, 10, 27, 12, 0, 0, tzinfo=CST)
    start, window_end = time_window(end, days=7)
    assert within_window(start, start, window_end)
    assert within_window(window_end - timedelta(seconds=1), start, window_end)
    assert not within_window(window_end, start, window_end)
    assert not within_window(start - timedelta(seconds=1), start, window_end)


def test_within_window_handles_naive_datetime_by_assuming_configured_tz():
    end = datetime(2026, 10, 27, 12, 0, 0, tzinfo=CST)
    start, window_end = time_window(end, days=7)
    naive = (start + timedelta(days=1)).replace(tzinfo=None)
    assert within_window(naive, start, window_end)


def test_within_window_none_publish_date_is_false():
    end = datetime(2026, 10, 27, 12, 0, 0, tzinfo=CST)
    start, window_end = time_window(end, days=7)
    assert not within_window(None, start, window_end)


@pytest.mark.parametrize(
    "raw,expected_year",
    [
        ("2026-10-27", 2026),
        ("2026-10-27T10:30:00", 2026),
        ("2026-10-27T10:30:00Z", 2026),
        ("2026-10-27T10:30:00+08:00", 2026),
    ],
)
def test_parse_date_string_supported_formats(raw, expected_year):
    dt = parse_date_string(raw)
    assert dt is not None
    assert dt.year == expected_year
    assert dt.tzinfo is not None


def test_parse_date_string_returns_none_for_garbage():
    assert parse_date_string("not a date") is None
    assert parse_date_string("") is None
    assert parse_date_string(None) is None


def test_parse_date_string_does_not_raise_on_none():
    assert parse_date_string(None) is None


def test_iso_to_datetime_handles_z_suffix():
    dt = iso_to_datetime("2026-10-27T10:30:00Z")
    assert dt is not None
    assert dt.tzinfo == timezone.utc


def test_iso_to_datetime_raises_on_invalid():
    with pytest.raises(DateParseError):
        iso_to_datetime("garbage")


def test_ensure_aware_converts_to_target_tz():
    dt = datetime(2026, 10, 27, 2, 30, 0, tzinfo=timezone.utc)
    converted = ensure_aware(dt, "Asia/Shanghai")
    assert converted.hour == 10
    assert converted.utcoffset() == timedelta(hours=8)


def test_ensure_aware_assumes_local_tz_for_naive():
    dt = datetime(2026, 10, 27, 10, 30, 0)
    converted = ensure_aware(dt, "Asia/Shanghai")
    assert converted.utcoffset() == timedelta(hours=8)


def test_ensure_aware_none_returns_none():
    assert ensure_aware(None, "Asia/Shanghai") is None
