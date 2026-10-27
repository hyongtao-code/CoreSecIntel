"""SMTP 邮件发送器。

要点：

- 支持多收件人、HTML 正文、UTF-8 中文。
- 支持 TLS（STARTTLS）与 SSL 两种模式。
- 发送失败时有限次重试（指数退避）。
- **密码与密钥绝不写入日志**（所有日志只记录是否配置，不记录内容）。
- 只有在 SMTP 服务器确认投递后才返回成功，不做任何「假装发送成功」。
"""

from __future__ import annotations

import logging
import smtplib
import time
from dataclasses import dataclass
from email.message import EmailMessage
from email.utils import formataddr, formatdate, make_msgid
from typing import Optional

from signalintel.config import SMTPConfig

logger = logging.getLogger(__name__)

__all__ = ["EmailSender", "SendResult", "build_message"]


@dataclass
class SendResult:
    """发送结果。"""

    success: bool
    recipients: list[str]
    error: Optional[str] = None
    attempts: int = 0
    message_id: Optional[str] = None

    def __bool__(self) -> bool:
        return self.success


def build_message(
    subject: str,
    html_body: str,
    recipients: list[str],
    sender: str,
    sender_name: str = "核心网信令安全周报",
) -> EmailMessage:
    """构造 UTF-8 HTML 邮件消息。"""
    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = formataddr((sender_name, sender))
    message["To"] = ", ".join(recipients)
    message["Date"] = formatdate(localtime=True)
    message["Message-ID"] = make_msgid(domain="signalintel.local")
    message.set_content("本邮件为 HTML 格式，请使用支持 HTML 的客户端查看。")
    message.add_alternative(html_body, subtype="html")
    return message


class EmailSender:
    """SMTP 发送器。"""

    def __init__(self, config: SMTPConfig) -> None:
        self.config = config

    # ------------------------------------------------------------------

    def _connect(self) -> smtplib.SMTP:
        """建立 SMTP 连接并完成 TLS 握手。"""
        host = self.config.host or ""
        port = self.config.port

        if self.config.use_ssl:
            logger.info("连接 SMTP (SSL) %s:%s", host, port)
            server: smtplib.SMTP = smtplib.SMTP_SSL(host, port, timeout=self.config.timeout)
        else:
            logger.info("连接 SMTP %s:%s", host, port)
            server = smtplib.SMTP(host, port, timeout=self.config.timeout)

        server.ehlo()
        if self.config.use_tls and not self.config.use_ssl:
            logger.debug("启用 STARTTLS")
            server.starttls()
            server.ehlo()

        if self.config.user and self.config.password:
            server.login(self.config.user, self.config.password)
        return server

    # ------------------------------------------------------------------

    def send(
        self,
        subject: str,
        html_body: str,
        recipients: Optional[list[str]] = None,
    ) -> SendResult:
        """发送 HTML 邮件，失败时按指数退避重试。"""
        targets = list(recipients if recipients is not None else self.config.recipients)

        if not self.config.host:
            return SendResult(
                success=False, recipients=targets, error="未配置 SMTP_HOST"
            )
        if not targets:
            return SendResult(
                success=False, recipients=targets, error="未配置收件人（EMAIL_TO）"
            )

        sender = self.config.sender or self.config.user
        if not sender:
            return SendResult(
                success=False, recipients=targets, error="未配置发件人（EMAIL_FROM）"
            )

        message = build_message(
            subject,
            html_body,
            targets,
            sender,
            sender_name=self.config.sender_name,
        )
        attempts = 0
        last_error: Optional[str] = None

        for attempt in range(1, self.config.max_retries + 1):
            attempts = attempt
            try:
                server = self._connect()
            except (smtplib.SMTPException, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "SMTP 连接失败（第 %s/%s 次）: %s",
                    attempt,
                    self.config.max_retries,
                    last_error,
                )
                if attempt < self.config.max_retries:
                    time.sleep(min(30.0, 2.0 ** (attempt - 1)))
                continue

            try:
                server.send_message(message)
            except (smtplib.SMTPException, OSError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "SMTP 发送失败（第 %s/%s 次）: %s",
                    attempt,
                    self.config.max_retries,
                    last_error,
                )
            else:
                logger.info(
                    "邮件发送成功：收件人 %s，主题 %s", len(targets), subject
                )
                return SendResult(
                    success=True,
                    recipients=targets,
                    attempts=attempts,
                    message_id=message["Message-ID"],
                )
            finally:
                try:
                    server.quit()
                except Exception:  # noqa: BLE001
                    try:
                        server.close()
                    except Exception:  # noqa: BLE001
                        pass

            if attempt < self.config.max_retries:
                time.sleep(min(30.0, 2.0 ** (attempt - 1)))

        logger.error("邮件发送最终失败（尝试 %s 次）: %s", attempts, last_error)
        return SendResult(
            success=False,
            recipients=targets,
            error=last_error,
            attempts=attempts,
        )
