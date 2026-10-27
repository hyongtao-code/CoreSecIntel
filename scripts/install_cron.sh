#!/usr/bin/env bash
# ============================================================================
# 安装 cron 定时任务（每天 08:30 执行）
#
#   ./scripts/install_cron.sh          # 安装
#   ./scripts/install_cron.sh --remove # 卸载
#
# 说明：
#   - 任务在项目目录下执行，会自动加载项目根目录的 .env
#   - 环境变量不写入 crontab（密钥只在 .env 中）
#   - cron 的 PATH 很短，脚本内用绝对路径
# ============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RUNNER="$PROJECT_DIR/scripts/run_daily.sh"
TAG="# signalintel-daily"

if [[ "${1:-}" == "--remove" ]]; then
    crontab -l 2>/dev/null | grep -v "$TAG" | grep -v "run_daily.sh" | crontab - || true
    echo "已移除 cron 任务"
    exit 0
fi

CHROME="PATH=/usr/local/bin:/usr/bin:/bin
0 8 * * * $RUNNER >> $PROJECT_DIR/logs/cron.log 2>&1 $TAG"

# 幂等：先移除旧的再写入
( crontab -l 2>/dev/null | grep -v "$TAG" | grep -v "run_daily.sh" ; echo "$CHROME" ) | crontab -

echo "已安装 cron 任务：每天 08:30 执行"
echo "  命令 : $RUNNER"
echo "  日志 : $PROJECT_DIR/logs/cron.log"
echo
echo "查看当前 crontab："
crontab -l | grep -A2 signalintel || true
