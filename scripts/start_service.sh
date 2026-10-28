#!/usr/bin/env bash
# ============================================================================
# 一键启动常驻服务：周期调度 + HTTP 归档页面
#
#   ./scripts/start_service.sh              # 按 config/schedule.yaml 启动
#   ./scripts/start_service.sh --port 8080  # 覆盖端口
#   ./scripts/start_service.sh --run-now    # 立即先跑一次，再进入常驻
#   ./scripts/start_service.sh --daemon     # 后台运行（写 PID 文件）
#
# 默认行为：每周一 08:30 自动采集 → 生成报告 → 归档 → 发邮件；
#           HTTP 页面展示最近一期及历史各期，支持翻页。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

# 优先使用项目 venv —— 若对其设置了 CAP_NET_BIND_SERVICE，
# 才能绑定 80 端口（免端口号访问）。没有 venv 时退回系统 python3。
if [[ -z "${PYTHON:-}" ]]; then
    if [[ -x "$PROJECT_DIR/.venv/bin/python3" ]]; then
        PYTHON="$PROJECT_DIR/.venv/bin/python3"
    else
        PYTHON="python3"
    fi
fi
PID_FILE="${PID_FILE:-$PROJECT_DIR/logs/service.pid}"
LOG_DIR="${LOG_DIR:-$PROJECT_DIR/logs}"
mkdir -p "$LOG_DIR"

DAEMON=""
ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --daemon)  DAEMON="1"; shift ;;
        -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
        *)         ARGS+=("$1"); shift ;;
    esac
done

# 已在运行则不重复启动
if [[ -f "$PID_FILE" ]] && kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
    echo "服务已在运行（PID $(cat "$PID_FILE")）"
    echo "  停止: kill \$(cat $PID_FILE)"
    exit 0
fi

# 绑定 80 端口的能力提示（非致命）
if [[ -x "$PROJECT_DIR/.venv/bin/python3" ]] \
   && ! getcap "$PROJECT_DIR/.venv/bin/python3" 2>/dev/null | grep -q net_bind_service; then
    echo "提示: .venv 尚未获得绑定 80 端口的能力，将自动降级到 8080 端口。"
    echo "      如需免端口号访问，执行:"
    echo "        sudo setcap 'cap_net_bind_service=+ep' $PROJECT_DIR/.venv/bin/python3"
    echo ""
fi

if [[ -n "$DAEMON" ]]; then
    nohup "$PYTHON" app.py serve "${ARGS[@]}" >> "$LOG_DIR/service.log" 2>&1 &
    echo $! > "$PID_FILE"
    sleep 2
    if kill -0 "$(cat "$PID_FILE")" 2>/dev/null; then
        echo "已后台启动（PID $(cat "$PID_FILE")）"
        echo "  日志: $LOG_DIR/service.log"
        grep -E "HTTP 服务|下次运行|归档" "$LOG_DIR/service.log" | tail -5
    else
        echo "启动失败，请查看 $LOG_DIR/service.log"
        exit 1
    fi
else
    exec "$PYTHON" app.py serve "${ARGS[@]}"
fi
