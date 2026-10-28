"""内置 HTTP 服务。

只用标准库 ``http.server``，不新增依赖。提供：

- ``/``                报告列表（按周/期倒序，支持翻页）
- ``/r/<日期>``        某期报告全文
- ``/api/reports``     JSON：全部报告摘要
- ``/api/report/<日期>`` JSON：某期报告详情

所有输出内容都经过转义，归档中的 HTML 只在 ``/r/<日期>`` 里原样呈现
（那是自己生成的报告，浏览器以 iframe/独立页方式展示）。
"""

from __future__ import annotations

import html
import json
import logging
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Optional
from urllib.parse import parse_qs, unquote, urlsplit

from signalintel.archive import ArchivedReport, ReportArchive

logger = logging.getLogger(__name__)

__all__ = ["WebServer", "create_server", "DEFAULT_PORTS"]

#: 默认端口候选，按优先级排列，第一个能绑定的即生效。
#:
#: 80 是 HTTP 标准端口 —— 用户在浏览器只输 IP 就能访问，无需记端口号。
#: 但绑定 80 需要 root 或 ``CAP_NET_BIND_SERVICE``，因此无权限时
#: 自动降级到 8080，再不行降到 8765，保证在容器等受限环境也能跑起来。
DEFAULT_PORTS: tuple[int, ...] = (80, 8080, 8765)

#: 列表页每页条数
DEFAULT_PAGE_SIZE = 10


def _esc(value: Any) -> str:
    """HTML 转义。"""
    return html.escape(str(value if value is not None else ""), quote=True)


def _fmt_date(value: Any) -> str:
    """把 ISO 时间串格式化为 YYYY-MM-DD。"""
    if not value:
        return ""
    text = str(value)
    return text.split("T")[0]


class _Handler(BaseHTTPRequestHandler):
    """请求处理器。"""

    server_version = "SignalIntelWeb/1.0"
    #: 由 create_server 注入
    archive: ReportArchive

    # ------------------------------------------------------------------

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        """把访问日志降到 DEBUG，避免刷屏。"""
        logger.debug("%s - %s", self.address_string(), format % args)

    def do_GET(self) -> None:  # noqa: N802
        parts = urlsplit(self.path)
        path = unquote(parts.path)
        query = parse_qs(parts.query)

        try:
            if path == "/":
                self._handle_index(query)
            elif path.startswith("/r/"):
                self._handle_report(path[len("/r/") :])
            elif path == "/api/reports":
                self._handle_api_list()
            elif path.startswith("/api/report/"):
                self._handle_api_report(path[len("/api/report/") :])
            elif path == "/api/status":
                self._handle_api_status()
            elif path == "/healthz":
                self._send(200, "text/plain; charset=utf-8", "ok")
            else:
                self._send(404, "text/html; charset=utf-8", _not_found_page())
        except BrokenPipeError:
            pass
        except Exception:  # noqa: BLE001 - 单个请求失败不应影响服务
            logger.exception("处理请求 %s 失败", self.path)
            try:
                self._send(500, "text/plain; charset=utf-8", "internal error")
            except Exception:  # noqa: BLE001
                pass

    # ------------------------------------------------------------------

    def _handle_index(self, query: dict[str, list[str]]) -> None:
        """报告列表页。"""
        try:
            page = int(query.get("page", ["1"])[0])
        except (TypeError, ValueError):
            page = 1
        try:
            page_size = int(query.get("size", [str(DEFAULT_PAGE_SIZE)])[0])
        except (TypeError, ValueError):
            page_size = DEFAULT_PAGE_SIZE
        page_size = max(1, min(100, page_size))

        entries, total, total_pages, actual_page = self.archive.page(page, page_size)
        self._send(
            200,
            "text/html; charset=utf-8",
            _index_page(entries, total, total_pages, actual_page, page_size),
        )

    def _handle_report(self, report_date: str) -> None:
        """某期报告全文。"""
        entry = self.archive.get(report_date)
        if entry is None:
            self._send(404, "text/html; charset=utf-8", _not_found_page())
            return
        body = entry.html or ""
        # 报告本身是完整 HTML 文档，直接返回以便原样渲染
        self._send(200, "text/html; charset=utf-8", body)

    def _handle_api_list(self) -> None:
        """JSON：报告摘要列表。"""
        entries = self.archive.list()
        payload = {
            "total": len(entries),
            "reports": [_summary(entry) for entry in entries],
        }
        self._send_json(200, payload)

    def _handle_api_report(self, report_date: str) -> None:
        """JSON：某期详情。"""
        entry = self.archive.get(report_date)
        if entry is None:
            self._send_json(404, {"error": "not found", "report_date": report_date})
            return
        payload = dict(entry.meta)
        payload["items"] = entry.items
        self._send_json(200, payload)

    def _handle_api_status(self) -> None:
        """JSON：服务状态。"""
        self._send_json(
            200,
            {
                "status": "ok",
                "total_reports": len(self.archive.list()),
                "archive_root": str(self.archive.root),
            },
        )

    # ------------------------------------------------------------------

    def _send(self, code: int, content_type: str, body: str) -> None:
        data = body.encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(data)

    def _send_json(self, code: int, payload: dict[str, Any]) -> None:
        self._send(
            code,
            "application/json; charset=utf-8",
            json.dumps(payload, ensure_ascii=False, indent=2),
        )


def _summary(entry: ArchivedReport) -> dict[str, Any]:
    """报告摘要（用于列表与 API）。"""
    meta = entry.meta or {}
    return {
        "report_date": entry.report_date,
        "subject": entry.subject,
        "item_count": entry.item_count,
        "p1_count": meta.get("p1_count", 0),
        "p2_count": meta.get("p2_count", 0),
        "p3_count": meta.get("p3_count", 0),
        "candidates": meta.get("candidates", 0),
        "window_start": _fmt_date(meta.get("window_start")),
        "window_end": _fmt_date(meta.get("window_end")),
        "window_start_full": meta.get("window_start"),
        "window_end_full": meta.get("window_end"),
        "url": f"/r/{entry.report_date}",
    }


def _index_page(
    entries: list[ArchivedReport],
    total: int,
    total_pages: int,
    page: int,
    page_size: int,
) -> str:
    """报告列表页 HTML。"""
    rows: list[str] = []
    for entry in entries:
        meta = entry.meta or {}
        rows.append(
            f"""
      <tr>
        <td class="date"><a href="/r/{_esc(entry.report_date)}">{_esc(entry.report_date)}</a></td>
        <td>{_esc(entry.subject or '核心网信令安全周报')}</td>
        <td class="num">{_esc(entry.item_count)}</td>
        <td class="num">{_esc(meta.get('p1_count', 0))}</td>
        <td class="num">{_esc(meta.get('p2_count', 0))}</td>
        <td class="num">{_esc(meta.get('p3_count', 0))}</td>
        <td class="win">{_esc(_fmt_date(meta.get('window_start')))} ~ {_esc(_fmt_date(meta.get('window_end')))}</td>
      </tr>"""
        )

    if not rows:
        rows.append(
            '<tr><td colspan="7" class="empty">暂无归档报告，等待首次调度任务生成。</td></tr>'
        )

    # 翻页条
    nav: list[str] = []
    if page > 1:
        nav.append(f'<a class="pg" href="/?page={page - 1}">‹ 上一页</a>')
    nav.append(f'<span class="pg-info">第 {page} / {total_pages} 页</span>')
    if page < total_pages:
        nav.append(f'<a class="pg" href="/?page={page + 1}">下一页 ›</a>')

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>核心网信令安全情报归档</title>
<style>
  * {{ box-sizing: border-box; }}
  body {{ margin:0; padding:0; background:#f2f4f7; color:#101828;
         font-family:-apple-system,BlinkMacSystemFont,'Segoe UI','PingFang SC','Microsoft YaHei',Arial,sans-serif; }}
  .wrap {{ max-width:960px; margin:0 auto; padding:28px 16px 48px; }}
  header {{ background:#0b3d6b; color:#fff; padding:22px 26px; border-radius:10px 10px 0 0; }}
  header h1 {{ margin:0 0 6px; font-size:21px; }}
  header p {{ margin:0; font-size:13px; color:#b9d4ec; }}
  .panel {{ background:#fff; border-radius:0 0 10px 10px; padding:20px 26px 26px;
            box-shadow:0 1px 3px rgba(16,24,40,.08); }}
  table {{ width:100%; border-collapse:collapse; font-size:14px; }}
  th {{ text-align:left; font-size:12px; color:#667085; font-weight:600;
        border-bottom:1px solid #eaecf0; padding:8px 10px 8px 0; white-space:nowrap; }}
  td {{ padding:9px 10px 9px 0; border-bottom:1px solid #f2f4f7; color:#344054; vertical-align:top; }}
  td.num {{ text-align:right; white-space:nowrap; }}
  td.date {{ white-space:nowrap; font-weight:600; }}
  td.win {{ color:#98a2b3; font-size:12px; white-space:nowrap; }}
  td.empty {{ text-align:center; color:#98a2b3; padding:34px 0; }}
  a {{ color:#0b63ce; text-decoration:none; }}
  a:hover {{ text-decoration:underline; }}
  .pager {{ margin-top:16px; display:flex; gap:12px; align-items:center; justify-content:center; }}
  .pg {{ padding:5px 12px; border:1px solid #d0d5dd; border-radius:6px; font-size:13px; background:#fff; }}
  .pg-info {{ font-size:13px; color:#667085; }}
  .total {{ font-size:12px; color:#98a2b3; text-align:right; margin-bottom:10px; }}
  footer {{ margin-top:18px; font-size:12px; color:#98a2b3; text-align:center; line-height:1.8; }}
  @media (max-width:720px) {{ .win {{ display:none; }} th.hide-sm {{ display:none; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>核心网信令安全情报归档</h1>
    <p>共 {total} 期报告 · 每页 {page_size} 期</p>
  </header>
  <div class="panel">
    <div class="total">按生成时间倒序</div>
    <table>
      <thead>
        <tr>
          <th>期次日期</th><th>主题</th><th class="num">条目</th>
          <th class="num">P1</th><th class="num">P2</th><th class="num">P3</th>
          <th class="hide-sm">检索窗口</th>
        </tr>
      </thead>
      <tbody>{''.join(rows)}
      </tbody>
    </table>
    <div class="pager">{''.join(nav)}</div>
    <footer>
      由「核心网信令安全情报自动订阅系统」自动生成与归档<br>
      报告正文见各期原文链接；评分仅用于排序与筛选，不代表客观风险等级
    </footer>
  </div>
</div>
</body>
</html>"""


def _not_found_page() -> str:
    """404 页面。"""
    return """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8"><title>未找到</title>
<style>body{font-family:'PingFang SC','Microsoft YaHei',Arial,sans-serif;
text-align:center;padding:80px 20px;color:#667085;background:#f2f4f7;margin:0}
h1{color:#101828;font-size:20px}</style></head>
<body><h1>404 · 未找到该报告</h1><p><a href="/">返回归档列表</a></p></body></html>"""


def create_server(
    archive: ReportArchive, host: str = "127.0.0.1", port: int = 8765
) -> ThreadingHTTPServer:
    """创建 HTTP 服务实例（未启动）。"""
    handler = type("_BoundHandler", (_Handler,), {"archive": archive})
    return ThreadingHTTPServer((host, port), handler)


class WebServer:
    """HTTP 服务封装（可在后台线程运行）。

    端口选择：

    - ``port`` 显式指定 → 直接用它（失败则抛出，由调用方决定）
    - ``port=0`` → 端口自动选择（系统分配），用于测试
    - ``port=None`` → 按 :data:`DEFAULT_PORTS` 顺序尝试绑定，
      80（标准端口，免端口号）→ 8080 → 8765
    """

    def __init__(
        self,
        archive: ReportArchive,
        host: str = "127.0.0.1",
        port: Optional[int] = None,
        port_candidates: tuple[int, ...] = DEFAULT_PORTS,
        strict: bool = False,
    ) -> None:
        self.archive = archive
        self.host = host
        self.requested_port = port
        self.port_fallbacks: list[str] = []
        #: strict=True 时端口不可用直接报错（用户显式指定端口的场景）
        self.strict = strict

        self._server = self._bind(port, port_candidates)
        self._thread: Optional[threading.Thread] = None

    def _bind(
        self, port: Optional[int], candidates: tuple[int, ...]
    ) -> ThreadingHTTPServer:
        """绑定监听端口，必要时按候选列表降级。

        - ``port=None``：按 ``candidates`` 顺序尝试
        - ``port=0``：系统随机分配（测试用）
        - ``port>0`` 且 ``strict=False``：先试该端口，失败则降级到候选列表
        - ``port>0`` 且 ``strict=True``：失败直接报错
        """
        if port == 0:
            return create_server(self.archive, self.host, 0)

        if port is not None:
            try:
                return create_server(self.archive, self.host, port)
            except OSError as exc:
                if self.strict:
                    raise
                self.port_fallbacks.append(f"{port}（{exc.strerror or exc}）")
        else:
            port = None

        last_error: Optional[OSError] = None
        for candidate in candidates:
            if candidate == self.requested_port:
                continue
            try:
                return create_server(self.archive, self.host, candidate)
            except OSError as exc:
                self.port_fallbacks.append(f"{candidate}（{exc.strerror or exc}）")
                last_error = exc
                continue

        raise OSError(
            f"无法绑定任何候选端口 {list(candidates)}："
            f"{'；'.join(self.port_fallbacks)}"
        ) from last_error

    @property
    def port(self) -> int:
        """实际监听端口（port=0 时由系统分配）。"""
        return self._server.server_address[1]

    @property
    def url(self) -> str:
        """完整 URL（含端口）。"""
        return f"http://{self.host}:{self.port}/"

    @property
    def display_url(self) -> str:
        """给用户看的 URL —— 80 端口省略端口号。

        监听 0.0.0.0 时显示实际可访问的本机地址，便于用户直接复制。
        """
        host = self.host
        if host in ("0.0.0.0", "::"):
            host = self.lan_ip() or "localhost"
        if self.port == 80:
            return f"http://{host}/"
        return f"http://{host}:{self.port}/"

    @staticmethod
    def lan_ip() -> Optional[str]:
        """探测本机在局域网中的 IP（仅用于展示）。"""
        import socket

        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            # 不实际发包，靠路由表判断出网网卡
            sock.connect(("10.255.255.255", 1))
            return sock.getsockname()[0]
        except OSError:
            return None
        finally:
            sock.close()

    @property
    def is_standard_port(self) -> bool:
        """是否监听在标准 HTTP 端口（浏览器只需输 IP）。"""
        return self.port == 80

    def serve_forever(self) -> None:
        """阻塞式运行（供主线程使用）。"""
        logger.info("HTTP 服务已启动: %s", self.url)
        self._server.serve_forever()

    def start_background(self) -> None:
        """后台线程运行。"""
        self._thread = threading.Thread(
            target=self.serve_forever, name="signalintel-web", daemon=True
        )
        self._thread.start()

    def shutdown(self) -> None:
        """停止服务。

        注意：``BaseServer.shutdown()`` 只有在 ``serve_forever()`` 正在运行时
        才能返回，否则会永久阻塞。因此先判断服务循环是否已启动。
        """
        if self._thread is not None:
            try:
                self._server.shutdown()
            except Exception:  # noqa: BLE001
                pass
            self._thread.join(timeout=5)
            self._thread = None
        try:
            self._server.server_close()
        except Exception:  # noqa: BLE001
            pass
