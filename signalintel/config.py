"""配置加载。

配置来源优先级：

1. 环境变量（``.env`` 文件 + 真实环境变量）
2. YAML 配置文件（``config/sources.yaml``、``config/keywords.yaml``）

所有密钥只从环境变量读取，绝不写入代码或日志。
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping, Optional

try:
    import yaml
except ImportError:  # pragma: no cover - requirements 中已声明
    yaml = None  # type: ignore[assignment]

logger = logging.getLogger(__name__)

__all__ = [
    "LLMConfig",
    "SMTPConfig",
    "AppConfig",
    "load_config",
    "load_yaml",
    "parse_bool",
    "parse_list",
]

#: 项目根目录（signalintel/ 的上一级）
PROJECT_ROOT = Path(__file__).resolve().parent.parent

#: 配置文件默认搜索目录
DEFAULT_CONFIG_DIR = PROJECT_ROOT / "config"

#: 数据目录
DEFAULT_DATA_DIR = PROJECT_ROOT / "data"

#: 日志目录
DEFAULT_LOG_DIR = PROJECT_ROOT / "logs"


# ---------------------------------------------------------------------------
# 基础解析工具
# ---------------------------------------------------------------------------


def parse_bool(value: Any, default: bool = False) -> bool:
    """把多种形态的值解析为布尔值。"""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off"}:
        return False
    return default


def parse_list(value: Any) -> list[str]:
    """把逗号/分号分隔的字符串或列表解析为字符串列表。"""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(item).strip() for item in value if str(item).strip()]
    text = str(value).strip()
    if not text:
        return []
    parts = text.replace(";", ",").split(",")
    return [part.strip() for part in parts if part.strip()]


def load_yaml(path: Path) -> dict[str, Any]:
    """读取 YAML 文件，不存在或解析失败时返回空字典。"""
    if yaml is None:
        logger.error("未安装 PyYAML，无法读取 %s", path)
        return {}
    if not path.exists():
        logger.warning("配置文件不存在: %s", path)
        return {}
    try:
        with path.open("r", encoding="utf-8") as handle:
            data = yaml.safe_load(handle)
    except Exception as exc:  # noqa: BLE001
        logger.error("读取 YAML 失败 %s: %s", path, exc)
        return {}
    return data if isinstance(data, dict) else {}


def load_dotenv(path: Optional[Path] = None) -> None:
    """加载 ``.env`` 文件到 ``os.environ``（已存在的环境变量优先）。"""
    env_path = path or (PROJECT_ROOT / ".env")
    if not env_path.exists():
        return
    try:
        lines = env_path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        logger.warning("读取 .env 失败 %s: %s", env_path, exc)
        return

    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        key = key.strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _env(name: str, default: Any = None) -> Any:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(_env(name, default)).strip())
    except (TypeError, ValueError):
        logger.warning("环境变量 %s 不是合法整数，使用默认值 %s", name, default)
        return default


def _env_float(name: str, default: float) -> float:
    try:
        return float(str(_env(name, default)).strip())
    except (TypeError, ValueError):
        logger.warning("环境变量 %s 不是合法浮点数，使用默认值 %s", name, default)
        return default


# ---------------------------------------------------------------------------
# 配置数据类
# ---------------------------------------------------------------------------


@dataclass
class LLMConfig:
    """大模型 API 配置。"""

    api_base: str = "https://api.openai.com/v1"
    api_key: Optional[str] = None
    model: str = "gpt-4o-mini"
    timeout: float = 60.0
    max_retries: int = 3
    temperature: float = 0.2
    max_batch_size: int = 5
    max_concurrency: int = 2
    max_items: int = 60

    @property
    def is_configured(self) -> bool:
        """是否具备调用条件（配置了 API Key）。"""
        return bool(self.api_key)

    @classmethod
    def from_env(cls) -> "LLMConfig":
        return cls(
            api_base=str(_env("LLM_API_BASE", "https://api.openai.com/v1")).rstrip("/"),
            api_key=_env("LLM_API_KEY"),
            model=str(_env("LLM_MODEL", "gpt-4o-mini")),
            timeout=_env_float("LLM_TIMEOUT", 60.0),
            # 默认 5 次：公网 API 经代理时偶发 TLS 握手中断，需要足够重试次数
            max_retries=_env_int("LLM_MAX_RETRIES", 5),
            temperature=_env_float("LLM_TEMPERATURE", 0.2),
            max_batch_size=_env_int("LLM_MAX_BATCH_SIZE", 5),
            max_concurrency=_env_int("LLM_MAX_CONCURRENCY", 2),
            max_items=_env_int("LLM_MAX_ITEMS", 60),
        )


@dataclass
class SMTPConfig:
    """SMTP 邮件发送配置。

    配置来源优先级：环境变量 > ``config/email.yaml``。
    密码永远只从环境变量读取（默认 ``SMTP_PASSWORD``），
    配置文件里只写变量名，不写明文。
    """

    host: Optional[str] = None
    port: int = 465
    user: Optional[str] = None
    password: Optional[str] = None
    use_tls: bool = True
    use_ssl: bool = False
    sender: Optional[str] = None
    recipients: list[str] = field(default_factory=list)
    timeout: float = 30.0
    max_retries: int = 3
    enabled: bool = True
    subject_prefix: str = "【核心网信令安全周报】"
    sender_name: str = "核心网信令安全周报"

    @property
    def is_configured(self) -> bool:
        return bool(self.host and self.recipients and (self.sender or self.user))

    @classmethod
    def from_env(cls, file_config: Optional[dict[str, Any]] = None) -> "SMTPConfig":
        """构造 SMTP 配置。

        :param file_config: ``config/email.yaml`` 中 ``email:`` 节点的映射。
        """
        file_config = file_config or {}
        smtp_file = file_config.get("smtp", {}) or {}

        host = _env("SMTP_HOST") or smtp_file.get("host")
        port = _env_int("SMTP_PORT", int(smtp_file.get("port", 465) or 465))
        use_tls = parse_bool(
            _env("SMTP_USE_TLS", smtp_file.get("use_tls", True)), True
        )
        use_ssl = parse_bool(
            _env("SMTP_USE_SSL", smtp_file.get("use_ssl", port == 465)),
            port == 465,
        )

        user = _env("SMTP_USER") or smtp_file.get("user")
        password_env = str(smtp_file.get("password_env") or "SMTP_PASSWORD")
        password = _env("SMTP_PASSWORD") or _env(password_env)

        sender = _env("EMAIL_FROM") or file_config.get("from")
        recipients = parse_list(_env("EMAIL_TO")) or parse_list(
            file_config.get("to")
        )

        return cls(
            host=host,
            port=port,
            user=user,
            password=password,
            use_tls=use_tls,
            use_ssl=use_ssl,
            sender=sender,
            recipients=recipients,
            timeout=_env_float("SMTP_TIMEOUT", 30.0),
            max_retries=_env_int("SMTP_MAX_RETRIES", 3),
            enabled=parse_bool(file_config.get("enabled", True), True),
            subject_prefix=str(
                file_config.get("subject_prefix") or "【核心网信令安全周报】"
            ),
            sender_name=str(file_config.get("sender_name") or "核心网信令安全周报"),
        )


@dataclass
class AppConfig:
    """应用全局配置。"""

    timezone: str = "Asia/Shanghai"
    window_days: int = 7
    data_dir: Path = DEFAULT_DATA_DIR
    log_dir: Path = DEFAULT_LOG_DIR
    db_path: Path = DEFAULT_DATA_DIR / "signalintel.db"
    config_dir: Path = DEFAULT_CONFIG_DIR

    sources_raw: dict[str, Any] = field(default_factory=dict)
    keywords_raw: dict[str, Any] = field(default_factory=dict)
    email_raw: dict[str, Any] = field(default_factory=dict)

    llm: LLMConfig = field(default_factory=LLMConfig)
    smtp: SMTPConfig = field(default_factory=SMTPConfig)

    #: 评分权重
    score_weights: dict[str, float] = field(
        default_factory=lambda: {
            "relevance": 0.40,
            "novelty": 0.25,
            "impact": 0.20,
            "source_trust": 0.15,
        }
    )
    #: 优先级阈值
    min_score_for_report: float = 45.0
    #: 最多纳入邮件的条目数
    max_items_in_report: int = 30

    @property
    def sources(self) -> dict[str, Any]:
        return self.sources_raw.get("sources", {}) or {}

    @property
    def keywords(self) -> dict[str, Any]:
        return self.keywords_raw.get("keywords", {}) or {}

    @property
    def scoring(self) -> dict[str, Any]:
        return self.keywords_raw.get("scoring", {}) or {}


def load_config(config_dir: Optional[Path] = None) -> AppConfig:
    """加载完整配置。"""
    load_dotenv()

    config_dir = Path(config_dir) if config_dir else DEFAULT_CONFIG_DIR
    sources_raw = load_yaml(config_dir / "sources.yaml")
    keywords_raw = load_yaml(config_dir / "keywords.yaml")
    email_raw = load_yaml(config_dir / "email.yaml")

    data_dir = Path(str(_env("DATA_DIR", DEFAULT_DATA_DIR))).expanduser()
    log_dir = Path(str(_env("LOG_DIR", DEFAULT_LOG_DIR))).expanduser()

    cfg = AppConfig(
        timezone=str(_env("TIMEZONE", "Asia/Shanghai")),
        window_days=_env_int("WINDOW_DAYS", 7),
        data_dir=data_dir,
        log_dir=log_dir,
        db_path=Path(str(_env("DB_PATH", data_dir / "signalintel.db"))).expanduser(),
        config_dir=config_dir,
        sources_raw=sources_raw,
        keywords_raw=keywords_raw,
        email_raw=email_raw,
        llm=LLMConfig.from_env(),
        smtp=SMTPConfig.from_env(email_raw.get("email")),
    )

    # 评分权重可被 YAML 覆盖
    scoring = cfg.scoring
    if isinstance(scoring.get("weights"), dict):
        for key, value in scoring["weights"].items():
            if key in cfg.score_weights:
                try:
                    cfg.score_weights[key] = float(value)
                except (TypeError, ValueError):
                    logger.warning("评分权重 %s 不是合法数字，忽略", key)
    if "min_score" in scoring:
        try:
            cfg.min_score_for_report = float(scoring["min_score"])
        except (TypeError, ValueError):
            pass
    if "max_items" in scoring:
        try:
            cfg.max_items_in_report = int(scoring["max_items"])
        except (TypeError, ValueError):
            pass

    cfg.data_dir.mkdir(parents=True, exist_ok=True)
    cfg.log_dir.mkdir(parents=True, exist_ok=True)
    cfg.db_path.parent.mkdir(parents=True, exist_ok=True)

    return cfg
