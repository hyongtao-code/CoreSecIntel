#!/usr/bin/env bash
# ============================================================================
# 一键发送：采集 → 分析 → 生成报告 → 发邮件
#
#   ./scripts/run_daily.sh              # 正常跑（发邮件）
#   ./scripts/run_daily.sh --dry-run    # 只生成报告不发邮件
#   ./scripts/run_daily.sh --start 2026-10-19 --end 2026-10-26
#
# 供 cron / systemd 定时调用。日志同时写入 logs/run_*.log。
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$PROJECT_DIR"

DRY_RUN=""
START=""
END=""
EXTRA=()

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dry-run) DRY_RUN="--dry-run"; shift ;;
        --start)   START="$2"; shift 2 ;;
        --end)     END="$2"; shift 2 ;;
        -h|--help) sed -n '2,11p' "$0"; exit 0 ;;
        *)         EXTRA+=("$1"); shift ;;
    esac
done

PYTHON="${PYTHON:-python3}"
LOG_DIR="${LOG_DIR:-$PROJECT_DIR/logs}"
mkdir -p "$LOG_DIR"
RUN_LOG="$LOG_DIR/run_$(date +%Y%m%d_%H%M%S).log"

echo "[$(date '+%F %T')] 开始执行" | tee -a "$RUN_LOG"

CMD=("$PYTHON" app.py run)
[[ -n "$DRY_RUN" ]] && CMD+=("--dry-run")
[[ -n "$START" ]]   && CMD+=("--start" "$START")
[[ -n "$END" ]]     && CMD+=("--end" "$END")
[[ ${#EXTRA[@]} -gt 0 ]] && CMD+=("${EXTRA[@]}")

echo "命令: ${CMD[*]}" | tee -a "$RUN_LOG"

set +e
"${CMD[@]}" 2>&1 | tee -a "$RUN_LOG"
STATUS=${PIPESTATUS[0]}
set -e

if [[ $STATUS -eq 0 ]]; then
    echo "[$(date '+%F %T')] 执行成功" | tee -a "$RUN_LOG"
else
    echo "[$(date '+%F %T')] 执行失败，退出码 $STATUS" | tee -a "$RUN_LOG"
fi
exit $STATUS
