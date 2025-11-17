# GitHub Actions 部署指南

## 快速部署步骤

### 1. 推送代码到GitHub

```bash
cd /root/mydemo/RISCV_CVE_Dashboard

# 添加所有文件
git add .

# 提交
git commit -m "Setup GitHub Actions and Pages deployment"

# 推送到远程仓库
git push origin master
```

### 2. 启用GitHub Pages

1. 访问您的GitHub仓库
2. 点击 **Settings** (设置)
3. 在左侧菜单找到 **Pages**
4. 在 **Source** 下拉菜单中选择 **GitHub Actions**
5. 保存

### 3. 配置API密钥（可选）

如果要使用OpenAI或Anthropic API：

1. 访问 **Settings** → **Secrets and variables** → **Actions**
2. 点击 **New repository secret**
3. 添加密钥：
   - Name: `OPENAI_API_KEY`
   - Value: 您的OpenAI API密钥（如`sk-...`）
   
   或
   
   - Name: `ANTHROPIC_API_KEY`
   - Value: 您的Anthropic API密钥

**注意**: 如果不添加这些密钥，系统会使用本地模拟模式，功能正常但分类效果较简单。

### 4. 运行工作流

#### 方法1: 手动触发

1. 访问 **Actions** 标签页
2. 选择 **Update RISC-V CVEs** workflow
3. 点击 **Run workflow** 按钮
4. 选择分支（通常是`master`）
5. 点击绿色的 **Run workflow** 按钮

#### 方法2: 等待自动运行

工作流会在每天北京时间上午9:35自动运行。

### 5. 查看结果

- **查看工作流状态**: Actions 标签页
- **查看部署状态**: Settings → Pages
- **访问网站**: `https://YOUR_USERNAME.github.io/RISCV_CVE_Dashboard/`

## 工作流说明

### update-cves.yml

**功能**: 
- 每天自动下载CVE增量包
- 提取RISC-V相关CVE
- 使用LLM分类
- 更新JSON文件
- 部署到GitHub Pages

**运行时间**: 每天UTC 01:35 (北京时间09:35)

**环境变量**:
- `OPENAI_API_KEY`: OpenAI API密钥（可选）
- `ANTHROPIC_API_KEY`: Anthropic API密钥（可选）

### deploy-pages.yml

**功能**: 
- 当`visualization/`目录有更新时自动部署
- 也可以手动触发

**触发条件**:
- Push到`master`分支且修改了`visualization/`目录
- 手动触发

## 自定义配置

### 修改运行时间

编辑 `.github/workflows/update-cves.yml`:

```yaml
on:
  schedule:
    # 修改cron表达式
    - cron: '35 1 * * *'  # UTC时间
```

**Cron表达式格式**: `分 时 日 月 星期`

常用时间转换:
- 北京时间 09:35 = UTC 01:35 → `35 1 * * *`
- 北京时间 10:00 = UTC 02:00 → `0 2 * * *`
- 北京时间 20:00 = UTC 12:00 → `0 12 * * *`

### 使用OpenAI API

1. 在仓库添加 `OPENAI_API_KEY` secret
2. 修改 `.github/workflows/update-cves.yml`:

```yaml
- name: Download and extract CVE delta package
  run: |
    cd visualization
    # 改为使用openai provider
    python update_riscv_cves.py --provider openai --model gpt-3.5-turbo
  env:
    OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
```

### 更改部署目录

如果要更改部署到Pages的目录：

编辑 `.github/workflows/update-cves.yml`:

```yaml
- name: Upload Pages artifact
  uses: actions/upload-pages-artifact@v3
  with:
    path: visualization/  # 修改这里
```

## 故障排除

### Q: Workflow运行失败

**检查清单**:
1. 查看Actions日志获取详细错误信息
2. 确认Python版本和依赖正确安装
3. 检查API密钥配置（如果使用）
4. 确认GitHub Pages已启用

### Q: 页面部署失败

**可能原因**:
1. Pages未启用或配置错误
2. 仓库是私有的（需要GitHub Pro）
3. 部署权限不足

**解决方案**:
- 检查 Settings → Pages 配置
- 确认仓库是Public
- 检查workflow的permissions配置

### Q: CVE数据未更新

**可能原因**:
1. 增量包还未发布（通常在北京时间9:30后）
2. 网络问题导致下载失败
3. 没有新的RISC-V CVE

**解决方案**:
- 查看workflow日志
- 手动运行workflow测试
- 检查CVE数据源是否可访问

### Q: API调用失败

**可能原因**:
1. API密钥无效或过期
2. API限额用尽
3. 网络问题

**解决方案**:
- 检查API密钥是否正确
- 使用本地模拟模式（`--provider local`）
- 查看API使用情况

## 监控建议

### 1. 启用GitHub通知

在仓库设置中启用workflow失败通知：
- Settings → Notifications
- 勾选"Send notifications for failed workflows"

### 2. 定期检查

建议每周检查：
- Actions运行历史
- Pages部署状态
- CVE数据更新情况

### 3. 日志保留

GitHub Actions日志保留90天，重要信息建议定期导出。

## 高级功能

### 添加多个定时任务

在 `.github/workflows/update-cves.yml` 中添加多个cron表达式：

```yaml
on:
  schedule:
    - cron: '35 1 * * *'  # 每天上午9:35
    - cron: '0 12 * * *'  # 每天下午8:00
```

### 使用矩阵策略

如果想在多个Python版本上测试：

```yaml
jobs:
  update-and-deploy:
    strategy:
      matrix:
        python-version: ['3.10', '3.11', '3.12']
    runs-on: ubuntu-latest
    steps:
    - uses: actions/setup-python@v5
      with:
        python-version: ${{ matrix.python-version }}
```

### 添加测试步骤

在部署前运行测试：

```yaml
- name: Run tests
  run: |
    python -m pytest tests/
```

## 资源链接

- [GitHub Actions 文档](https://docs.github.com/actions)
- [GitHub Pages 文档](https://docs.github.com/pages)
- [工作流语法](https://docs.github.com/actions/reference/workflow-syntax-for-github-actions)
- [Cron表达式](https://crontab.guru/)

---

最后更新: 2025-11-17
