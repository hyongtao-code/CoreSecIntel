"""周期调度。

由 ``config/schedule.yaml`` 配置，支持 daily / weekly / monthly 三种频率。

调度器本身不依赖外部库：后台线程按固定间隔检查「是否到达下次运行时间」，
到点则触发回调。回调执行期间不会重复触发（避免上一轮未跑完就叠加）。
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Callable, Mapping, Optional

from signalintel.utils.dates import get_tz, now_in_tz

logger = logging.getLogger(__name__)

__all__ = [
    "ScheduleConfig",
    "Scheduler",
    "next_run_time",
    "WEEKDAY_MAP",
]

#: 星期名 → Python weekday（周一=0）
WEEKDAY_MAP: dict[str, int] = {
    "monday": 0,
    "tuesday": 1,
    "wednesday": 2,
    "thursday": 3,
    "friday": 4,
    "saturday": 5,
    "sunday": 6,
    "mon": 0,
    "tue": 1,
    "wed": 2,
    "thu": 3,
    "fri": 4,
    "sat": 5,
    "sun": 6,
}

#: 支持的频率
VALID_FREQUENCIES = ("daily", "weekly", "monthly")


@dataclass
class ScheduleConfig:
    """调度配置。"""

    frequency: str = "weekly"
    #: 触发时刻 HH:MM
    run_at: str = "08:30"
    #: weekly：星期几（默认周一）
    weekday: str = "monday"
    #: monthly：每月第几日
    day_of_month: int = 1
    #: 是否启用调度
    enabled: bool = True
    #: 启动时若已错过当期，是否立即补跑一次
    catch_up: bool = False
    #: 任务失败后是否继续等待下一次
    continue_on_error: bool = True
    timezone: str = "Asia/Shanghai"

    @property
    def hour(self) -> int:
        return int(self.run_at.split(":")[0])

    @property
    def minute(self) -> int:
        return int(self.run_at.split(":")[1])

    @property
    def weekday_index(self) -> int:
        return WEEKDAY_MAP.get(self.weekday.lower(), 0)

    @classmethod
    def from_mapping(cls, data: Optional[Mapping[str, Any]]) -> "ScheduleConfig":
        """从 YAML 映射构造，非法值直接报错（避免静默跑错频率）。"""
        data = data or {}
        frequency = str(data.get("frequency", "weekly")).strip().lower()
        if frequency not in VALID_FREQUENCIES:
            raise ValueError(
                f"不支持的频率 {frequency!r}，可用：{', '.join(VALID_FREQUENCIES)}"
            )

        run_at = str(data.get("run_at", "08:30")).strip()
        try:
            hour_text, minute_text = run_at.split(":")
            hour, minute = int(hour_text), int(minute_text)
        except (ValueError, AttributeError) as exc:
            raise ValueError(f"run_at 格式应为 HH:MM，收到 {run_at!r}") from exc
        if not (0 <= hour <= 23 and 0 <= minute <= 59):
            raise ValueError(f"run_at 时间超出范围: {run_at!r}")

        weekday = str(data.get("weekday", "monday")).strip().lower()
        if weekday not in WEEKDAY_MAP:
            raise ValueError(f"未知星期 {weekday!r}")

        try:
            day_of_month = int(data.get("day_of_month", 1))
        except (TypeError, ValueError) as exc:
            raise ValueError("day_of_month 必须是整数") from exc
        if not (1 <= day_of_month <= 31):
            raise ValueError(f"day_of_month 超出范围: {day_of_month}")

        return cls(
            frequency=frequency,
            run_at=f"{hour:02d}:{minute:02d}",
            weekday=weekday,
            day_of_month=day_of_month,
            enabled=bool(data.get("enabled", True)),
            catch_up=bool(data.get("catch_up", False)),
            continue_on_error=bool(data.get("continue_on_error", True)),
            timezone=str(data.get("timezone", "Asia/Shanghai")),
        )


def next_run_time(
    config: ScheduleConfig, now: Optional[datetime] = None
) -> datetime:
    """计算下一次触发时间（严格大于 ``now``）。"""
    now = now or now_in_tz(config.timezone)
    tz = get_tz(config.timezone)

    hour, minute = config.hour, config.minute

    if config.frequency == "daily":
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        if candidate <= now:
            candidate += timedelta(days=1)
        return candidate

    if config.frequency == "weekly":
        candidate = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
        days_ahead = (config.weekday_index - candidate.weekday()) % 7
        candidate += timedelta(days=days_ahead)
        if candidate <= now:
            candidate += timedelta(days=7)
        return candidate

    # monthly
    candidate = _month_candidate(now, config, tz)
    if candidate <= now:
        candidate = _month_candidate(now + timedelta(days=32), config, tz)
    return candidate


def _month_candidate(
    now: datetime, config: ScheduleConfig, tz: Any
) -> datetime:
    """当月的第 day_of_month 日（超出当月天数则取当月最后一天）。"""
    import calendar

    days_in_month = calendar.monthrange(now.year, now.month)[1]
    day = min(config.day_of_month, days_in_month)
    return now.replace(
        day=day, hour=config.hour, minute=config.minute, second=0, microsecond=0
    )


class Scheduler:
    """后台调度器。

    :param job: 到点执行的回调
    :param config: 调度配置
    """

    def __init__(
        self,
        job: Callable[[datetime], None],
        config: Optional[ScheduleConfig] = None,
    ) -> None:
        self.job = job
        self.config = config or ScheduleConfig()
        self._thread: Optional[threading.Thread] = None
        self._stop = threading.Event()
        self._running = False
        self.last_run: Optional[datetime] = None
        self.last_error: Optional[str] = None
        self.run_count = 0

    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        return self._running

    def next_run(self, now: Optional[datetime] = None) -> datetime:
        """下一次触发时间。"""
        return next_run_time(self.config, now)

    def start(self) -> None:
        """启动调度线程。"""
        if self._thread is not None:
            return
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="signalintel-scheduler", daemon=True
        )
        self._thread.start()
        logger.info(
            "调度器已启动：%s %s，下次运行 %s",
            self.config.frequency,
            self.config.run_at,
            self.next_run().strftime("%Y-%m-%d %H:%M"),
        )

    def stop(self, timeout: float = 5.0) -> None:
        """停止调度线程。"""
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=timeout)
            self._thread = None

    # ------------------------------------------------------------------

    def _loop(self) -> None:
        """调度主循环：每 30 秒检查一次是否到点。"""
        pending = self.next_run()
        if self.config.catch_up:
            # 启动即跑一次（不改变周期，只补跑当期）
            self._trigger(pending, reason="启动补跑")

        while not self._stop.is_set():
            now = now_in_tz(self.config.timezone)
            if now >= pending:
                self._trigger(pending, reason="到达计划时间")
                pending = self.next_run(now)
                logger.info("下次运行: %s", pending.strftime("%Y-%m-%d %H:%M"))
            # 睡到下一个检查点，或被唤醒
            self._stop.wait(min(30.0, max(1.0, (pending - now).total_seconds())))
            if self._stop.is_set():
                break
            # 时间可能因配置变更而改变，重算
            pending = self.next_run(now)

    def _trigger(self, when: datetime, reason: str) -> None:
        """执行任务。"""
        logger.info("触发调度任务（%s）", reason)
        self.last_run = when
        try:
            self.job(when)
            self.run_count += 1
            self.last_error = None
        except Exception as exc:  # noqa: BLE001 - 单次失败不应终止调度
            self.last_error = f"{type(exc).__name__}: {exc}"
            logger.exception("调度任务执行失败: %s", exc)
            if not self.config.continue_on_error:
                logger.error("continue_on_error=false，停止调度")
                self._stop.set()
