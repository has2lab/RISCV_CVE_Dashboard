#!/bin/bash
# RISC-V CVE 增量更新示例脚本
# 用于每日自动更新RISC-V CVE数据库

# 切换到脚本所在目录
cd "$(dirname "$0")"

# 设置日志文件
LOG_FILE="update_$(date +%Y%m%d_%H%M%S).log"

echo "========================================"
echo "RISC-V CVE 增量更新"
echo "开始时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "========================================"

# 执行更新脚本
python update_riscv_cves.py 2>&1 | tee "$LOG_FILE"

EXIT_CODE=${PIPESTATUS[0]}

echo ""
echo "========================================"
echo "结束时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "退出码: $EXIT_CODE"
echo "日志文件: $LOG_FILE"
echo "========================================"

# 如果成功，可以选择清理旧日志（保留最近7天）
if [ $EXIT_CODE -eq 0 ]; then
    find . -name "update_*.log" -mtime +7 -delete
    echo "✓ 已清理7天前的日志文件"
fi

exit $EXIT_CODE
