# RISC-V CVE 数据库 + 可视化系统

[![Python Version](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![Auto Update](https://github.com/YOUR_USERNAME/RISCV_CVE_Dashboard/actions/workflows/update-cves.yml/badge.svg)](https://github.com/YOUR_USERNAME/RISCV_CVE_Dashboard/actions/workflows/update-cves.yml)
[![GitHub Pages](https://github.com/YOUR_USERNAME/RISCV_CVE_Dashboard/actions/workflows/deploy-pages.yml/badge.svg)](https://github.com/YOUR_USERNAME/RISCV_CVE_Dashboard/actions/workflows/deploy-pages.yml)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

一个全自动的RISC-V CVE数据库系统，每日自动更新并部署到GitHub Pages。

## 🌐 在线查看

**访问地址**: https://YOUR_USEE.github.io/RISCV_CVE_Dashboard/

系统每天北京时间上午9:35自动更新CVE数据并重新部署。

## 🎯 项目特色

- 🔄 **全自动更新**: 使用GitHub Actions每日自动下载CVE增量包
- 🤖 **智能分类**: 使用LLM对RISC-V CVE进行智能分类和总结
- 📊 **可视化展示**: 交互式Web界面，支持筛选、搜索和统计
- 🌐 **在线访问**: 部署到GitHub Pages，无需本地环境即可查看
- 📈 **实时统计**: 自动生成年份分布、分类统计等可视化图表

## 📦 项目结构

```
RISCV_CVE_Dashboard/
├── .github/
│   └── workflows/
│       ├── update-cves.yml      # 自动更新CVE的workflow
│       └── deploy-pages.yml     # 部署到GitHub Pages
├── visualization/               # Web可视化系统
│   ├── index.html              # 主页面
│   ├── css/                    # 样式文件
│   ├── js/                     # JavaScript代码
│   ├── update_riscv_cves.py    # 增量更新脚本（整合提取和分类）
│   ├── riscv_cves_classified.json         # 分类数据（完整版）
│   └── riscv_cves_classified_summary.json # 分类数据（摘要版）
├── riscv_cves/                 # 提取的RISC-V CVE
├── extract_riscv_cves.py       # CVE提取脚本（独立使用）
├── classify_riscv_cves.py      # CVE分类脚本（独立使用）
├── llm_config_manager.py       # LLM配置管理器
├── llm_config.json             # LLM配置文件
├── README.md                   # 项目说明文档
└── DEPLOYMENT.md               # GitHub部署指南
```

## 🚀 GitHub Actions 自动化流程

### 1. 自动更新CVE (每日运行)

Workflow文件: `.github/workflows/update-cves.yml`

**运行时间**: 每天北京时间上午9:35 (UTC 01:35)

**工作流程**:
1. 下载前一天的CVE增量包
2. 提取RISC-V相关的CVE
3. 使用LLM进行分类（本地模拟模式）
4. 更新JSON数据文件
5. 提交更改到仓库
6. 自动部署到GitHub Pages

**手动触发**:
```bash
# 在GitHub仓库页面
Actions → Update RISC-V CVEs → Run workflow
```

### 2. 部署到GitHub Pages

Workflow文件: `.github/workflows/deploy-pages.yml`

**触发条件**:
- `master`分支的`visualization/`目录有更新时自动部署
- 可以手动触发

## 📋 部署到您自己的仓库

### 步骤1: Fork或克隆仓库

```bash
# 方法1: Fork这个仓库到你的GitHub账号

# 方法2: 克隆并推送到新仓库
git clone https://github.com/YOUR_USERNAME/RISCV_CVE_Dashboard.git
cd RISCV_CVE_Dashboard
git remote set-url origin https://github.com/YOUR_NEW_USERNAME/YOUR_NEW_REPO.git
git push -u origin master
```

### 步骤2: 启用GitHub Pages

1. 进入仓库的 **Settings** → **Pages**
2. 在 **Source** 下选择 **GitHub Actions**
3. 保存设置

### 步骤3: 配置Secrets (可选)

如果要使用真实的LLM API（OpenAI或Anthropic），需要添加API密钥：

1. 进入仓库的 **Settings** → **Secrets and variables** → **Actions**
2. 点击 **New repository secret**
3. 添加以下secrets（根据需要）:

| Secret名称 | 说明 | 示例 |
|-----------|------|------|
| `OPENAI_API_KEY` | OpenAI API密钥 | `sk-...` |
| `ANTHROPIC_API_KEY` | Anthropic API密钥 | `sk-ant-...` |

**注意**: 如果不添加这些secrets，系统会使用本地模拟模式（基于规则的分类），不会调用API。

### 步骤4: 更新README中的链接

将以下内容中的 `YOUR_USERNAME` 替换为您的GitHub用户名：

```markdown
[![Auto Update](https://github.com/YOUR_USERNAME/RISCV_CVE_Dashboard/actions/workflows/update-cves.yml/badge.svg)]
**访问地址**: https://YOUR_USERNAME.github.io/RISCV_CVE_Dashboard/
```

### 步骤5: 首次运行

```bash
# 方法1: 手动触发workflow
# GitHub仓库页面 → Actions → Update RISC-V CVEs → Run workflow

# 方法2: 推送一个更改触发
git commit --allow-empty -m "Trigger first run"
git push
```

## 🔧 本地开发

### 环境要求

```bash
# Python 3.11+
python --version

# 安装依赖
pip install -r requirements.txt
```

### 本地运行更新脚本

```bash
cd visualization

# 测试模式（不下载增量包）
python update_riscv_cves.py --no-download --provider local

# 下载并更新（下载昨天的增量包）
python update_riscv_cves.py

# 下载特定日期的增量包
python update_riscv_cves.py --date 2025-11-16
```

### 本地预览网页

```bash
cd visualization

# 启动简单的HTTP服务器
python serve.py
# 或
python -m http.server 8000

# 在浏览器中访问
# http://localhost:8000
```

## 📊 数据文件说明

### visualization/riscv_cves_classified.json
完整的分类数据，包含所有CVE的原始数据、分类信息、摘要等。

```json
{
  "metadata": {
    "total_cves": 83,
    "classification_date": "2025-11-17T16:38:22",
    "categories": ["Linux Kernel", "RISC-V CPU/SoC", "Simulator", ...]
  },
  "statistics": {
    "by_category": {
      "Linux Kernel": 64,
      "RISC-V CPU/SoC": 9,
      "Simulator": 3,
      "RISC-V Development Tools": 2,
      ...
    }
  },
  "classified_cves": [...]
}
```

### visualization/riscv_cves_classified_summary.json
简化版本，不包含CVE原始数据，文件更小，适合Web端快速加载。

## 🎨 可视化功能

访问在线页面后，您可以：

- 📋 **浏览CVE列表**: 查看所有RISC-V相关的CVE
- 🔍 **搜索和筛选**: 按CVE ID、分类、严重程度筛选
- 📊 **统计图表**: 查看年份分布、分类分布等统计图表
- 📝 **详细信息**: 点击CVE查看完整的描述和技术细节
- 🏷️ **分类标签**: 根据智能分类快速定位相关CVE

## 🔐 安全性说明

### API密钥管理

- ✅ API密钥存储在GitHub Secrets中，不会暴露在代码或日志中
- ✅ Workflow日志不会显示敏感信息
- ✅ 如果不配置API密钥，系统使用本地模拟模式，无安全风险

### 数据隐私

- ✅ 所有CVE数据来自公开的CVE数据库
- ✅ 不收集任何用户信息
- ✅ 部署到GitHub Pages的都是静态文件

## 🛠️ 自定义配置

### 修改更新时间

编辑 `.github/workflows/update-cves.yml`:

```yaml
on:
  schedule:
    # 修改为您想要的时间 (UTC时区)
    - cron: '35 1 * * *'  # 北京时间上午9:35
```

### 修改LLM配置

编辑 `llm_config.json`:

```json
default:
  provider: local  # 改为 "openai" 或 "anthropic"
  model: gpt-3.5-turbo

classification:
  predefined_categories:
    - Linux Kernel
    - RISC-V CPU/SoC
    - Simulator
    - RISC-V Development Tools
    - Device-Specific Firmware & Applications
    - RISC-V Instruction Set Manual
    - Other
  allow_new_categories: true
```

### 修改更新脚本

如果要使用OpenAI API，修改 `.github/workflows/update-cves.yml`:

```yaml
- name: Download and extract CVE delta package
  run: |
    cd visualization
    # 改为使用 openai provider
    python update_riscv_cves.py --provider openai --model gpt-3.5-turbo
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

## 📈 监控和调试

### 查看Workflow运行状态

1. 进入仓库的 **Actions** 标签页
2. 选择相应的workflow
3. 查看运行历史和日志

### 查看部署状态

1. 进入 **Settings** → **Pages**
2. 查看最新部署状态和URL

### 常见问题

**Q: Workflow运行失败怎么办？**
- 检查Actions日志查看错误信息
- 确认GitHub Pages已启用
- 检查API密钥是否正确配置（如果使用）

**Q: 页面无法访问？**
- 确认GitHub Pages已启用并选择"GitHub Actions"作为源
- 等待几分钟让部署完成
- 检查仓库是否为Public（Private仓库需要GitHub Pro）

**Q: 如何跳过某天的更新？**
- 在Actions页面手动取消运行
- 或临时禁用workflow

## 📚 相关文档

- [GitHub部署指南](DEPLOYMENT.md) - 详细的部署步骤和故障排查
- [GitHub Actions 文档](https://docs.github.com/actions)
- [GitHub Pages 文档](https://docs.github.com/pages)
- [CVE数据源](https://github.com/CVEProject/cvelistV5)

## 🤝 贡献

欢迎提交Issue和Pull Request！

## 📜 许可证

MIT License

## 🙏 致谢

- CVE数据: [CVEProject/cvelistV5](https://github.com/CVEProject/cvelistV5)
- RISC-V社区: [RISC-V International](https://riscv.org/)

---

**最后更新**: 2025-11-17  
**版本**: 2.0.0 (支持GitHub Actions自动化)

Made with ❤️ for RISC-V Security Research
