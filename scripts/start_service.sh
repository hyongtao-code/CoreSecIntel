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

PYTHON="${PYTHON:-python3}"
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
