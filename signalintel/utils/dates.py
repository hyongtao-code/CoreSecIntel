"""时间解析与时间窗口计算工具。

统一处理「首次公开时间 / 正式发表时间 / 新闻发布时间 / 采集时间」的区分，
所有对外暴露的 datetime 都是带时区的 aware 对象。
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Optional
from zoneinfo import ZoneInfo

__all__ = [
    "CST",
    "DateParseError",
    "ensure_aware",
    "get_tz",
    "iso_to_datetime",
    "now_in_tz",
    "parse_date_string",
    "time_window",
    "to_iso",
    "within_window",
]


class DateParseError(ValueError):
    """当要求严格解析的日期字符串无法被识别时抛出。"""


def get_tz(name: str) -> ZoneInfo:
    """获取时区对象，无法识别时回退到 UTC。"""
    try:
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001 - 时区名非法不应导致任务中断
        return ZoneInfo("UTC")


#: 默认时区：Asia/Shanghai
CST = get_tz("Asia/Shanghai")

#: 常见的 ISO-8601 变体（覆盖各数据源返回格式）
_ISO_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d",
    "%Y/%m/%d",
    "%Y%m%d",
)

#: 常见的 RFC-822 / RFC-1123 格式（RSS 常用）
_RFC_FORMATS: tuple[str, ...] = (
    "%a, %d %b %Y %H:%M:%S %z",
    "%a, %d %b %Y %H:%M:%S %Z",
    "%a, %d %b %Y %H:%M %z",
    "%a, %d %b %Y %H:%M:%S",
    "%d %b %Y %H:%M:%S %z",
    "%d %b %Y %H:%M:%S",
)


def now_in_tz(tz_name: str = "Asia/Shanghai") -> datetime:
    """返回指定时区的当前时间（aware）。"""
    return datetime.now(get_tz(tz_name))


def _from_timestamp(value: float, tz_name: str) -> datetime:
    return datetime.fromtimestamp(value, tz=get_tz(tz_name))


def ensure_aware(
    value: Optional[datetime], tz_name: str = "Asia/Shanghai"
) -> Optional[datetime]:
    """把 naive datetime 视为目标时区本地时间；aware datetime 转换到目标时区。"""
    if value is None:
        return None
    tz = get_tz(tz_name)
    if value.tzinfo is None:
        return value.replace(tzinfo=tz)
    return value.astimezone(tz)


def parse_date_string(
    raw: Optional[str], tz_name: str = "Asia/Shanghai"
) -> Optional[datetime]:
    """宽松解析多种日期字符串；无法识别时返回 ``None`` 而不抛异常。

    支持 ISO-8601、RFC-822/1123、``YYYY-MM-DD``、``YYYYMMDD`` 以及 Unix 时间戳字符串。
    """
    if raw is None:
        return None
    if isinstance(raw, datetime):
        return ensure_aware(raw, tz_name)

    text = str(raw).strip()
    if not text:
        return None

    # 纯数字且长度合理时按 Unix 时间戳处理
    if text.isdigit():
        length = len(text)
        try:
            if length == 10:  # 秒
                return _from_timestamp(int(text), tz_name)
            if length == 13:  # 毫秒
                return _from_timestamp(int(text) / 1000.0, tz_name)
        except (OverflowError, OSError, ValueError):
            return None

    # ISO-8601（标准库可处理的变体）
    normalized = text.replace("Z", "+00:00")
    try:
        return ensure_aware(datetime.fromisoformat(normalized), tz_name)
    except ValueError:
        pass

    for fmt in _ISO_FORMATS:
        try:
            return ensure_aware(datetime.strptime(text, fmt), tz_name)
        except ValueError:
            continue

    for fmt in _RFC_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
        except ValueError:
            continue
        # %Z 在部分实现下不填充时区，此时按目标时区处理
        return ensure_aware(parsed, tz_name)

    return None


def iso_to_datetime(raw: str) -> datetime:
    """严格解析 ISO-8601 字符串，失败时抛出 :class:`DateParseError`。"""
    if not raw or not str(raw).strip():
        raise DateParseError("空字符串不是合法日期")
    try:
        parsed = datetime.fromisoformat(str(raw).strip().replace("Z", "+00:00"))
    except ValueError as exc:
        raise DateParseError(f"无法解析日期: {raw!r}") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def time_window(
    end: Optional[datetime] = None, days: int = 7
) -> tuple[datetime, datetime]:
    """返回 ``(start, end)`` 时间窗口，区间为左闭右开。

    ``end`` 缺省为当前时间；``days`` 为回溯天数。
    """
    if end is None:
        end = now_in_tz()
    else:
        end = ensure_aware(end) or end
    if days < 0:
        raise ValueError("days 不能为负数")
    return end - timedelta(days=days), end


def within_window(
    value: Optional[datetime],
    start: datetime,
    end: datetime,
    tz_name: str = "Asia/Shanghai",
) -> bool:
    """判断时间点是否落在 ``[start, end)`` 窗口内。

    ``value`` 为 ``None``（发布时间缺失）时返回 ``False``。
    """
    if value is None:
        return False
    aware = ensure_aware(value, tz_name)
    assert aware is not None
    start_aware = ensure_aware(start, tz_name)
    end_aware = ensure_aware(end, tz_name)
    assert start_aware is not None and end_aware is not None
    return start_aware <= aware < end_aware


def to_iso(value: Optional[datetime]) -> Optional[str]:
    """序列化为带时区偏移的 ISO 字符串。"""
    if value is None:
        return None
    return value.isoformat()
