// RISC-V CVE Dashboard - CVE详情模块
const CveDetails = {
  // 当前显示的CVE详情
  currentCve: null,
  
  // 模态框元素
  modal: null,
  modalBody: null,
  modalTitle: null,

  /**
   * 初始化CVE详情模块
   */
  init() {
    Utils.log('info', 'CveDetails initializing...');
    
    // 获取DOM元素
    this.modal = document.getElementById('cveModal');
    this.modalBody = document.getElementById('modalBody');
    this.modalTitle = document.getElementById('modalCveId');
    
    // 绑定事件
    this.bindEvents();
  },

  /**
   * 绑定事件处理器
   */
  bindEvents() {
    // 关闭模态框
    const closeBtn = document.getElementById('modalClose');
    if (closeBtn) {
      closeBtn.addEventListener('click', () => this.hideModal());
    }

    // 点击模态框背景关闭
    if (this.modal) {
      this.modal.addEventListener('click', (e) => {
        if (e.target === this.modal) {
          this.hideModal();
        }
      });
    }

    // ESC键关闭模态框
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape' && this.modal && this.modal.classList.contains('active')) {
        this.hideModal();
      }
    });
  },

  /**
   * 显示CVE详情
   */
  async showDetails(cveId) {
    try {
      Utils.log('info', 'Showing CVE details', cveId);
      
      // 显示加载状态
      this.showLoadingModal(cveId);
      
      // 获取详细数据
      const cveData = await this.getCveData(cveId);
      
      if (!cveData) {
        this.showErrorModal(cveId, '未找到CVE详情数据');
        return;
      }

      // 渲染详情内容
      this.renderDetails(cveData);
      
      // 显示模态框
      this.showModal();
      
      this.currentCve = cveData;

    } catch (error) {
      Utils.log('error', 'Failed to show CVE details', error);
      this.showErrorModal(cveId, '加载CVE详情时发生错误');
    }
  },

  /**
   * 获取CVE数据
   */
  async getCveData(cveId) {
    // 首先尝试从详细数据中获取
    let cveData = DataLoader.getCveDetails(cveId);
    
    if (!cveData) {
      // 从摘要数据中获取
      const summaryData = DataLoader.cache.summary;
      if (summaryData && summaryData.classified_cves) {
        cveData = summaryData.classified_cves.find(cve => cve.cve_id === cveId);
      }
    }

    return cveData;
  },

  /**
   * 渲染CVE详情内容
   */
  renderDetails(cveData) {
    if (!this.modalTitle || !this.modalBody) return;

    // 设置标题
    this.modalTitle.textContent = cveData.cve_id;

    // 渲染主体内容
    this.modalBody.innerHTML = this.buildDetailsHTML(cveData);

    // 绑定详情页面事件
    this.bindDetailsEvents(cveData);
  },

  /**
   * 构建详情HTML
   */
  buildDetailsHTML(cve) {
    const severity = Utils.parseSeverity(cve.severity_assessment);
    const severityConfig = CONFIG.SEVERITY_LEVELS[severity];
    const categoryColor = CONFIG.CATEGORIES[cve.category]?.color || '#6B7280';
    
    return `
      <div class="cve-details">
        <!-- 基本信息卡片 -->
        <div class="details-section">
          <div class="section-title">
            <i class="fas fa-info-circle"></i>
            <h3>基本信息</h3>
          </div>
          <div class="info-grid">
            <div class="info-item">
              <label>CVE ID</label>
              <div class="info-value">
                <span class="cve-id-link">${cve.cve_id}</span>
                <button class="copy-btn" data-copy="${cve.cve_id}" title="复制CVE ID">
                  <i class="fas fa-copy"></i>
                </button>
              </div>
            </div>
            
            <div class="info-item">
              <label>分类</label>
              <div class="info-value">
                <span class="category-badge" style="color: ${categoryColor}; border-color: ${categoryColor}; background: ${categoryColor}15;">
                  ${Utils.getCategoryDisplayName(cve.category)}
                </span>
              </div>
            </div>
            
            <div class="info-item">
              <label>严重程度</label>
              <div class="info-value">
                <span class="severity-badge severity-${severity.toLowerCase()}">
                  <i class="fas ${severityConfig?.icon || 'fa-circle'}"></i>
                  ${severityConfig?.label || severity}
                </span>
              </div>
            </div>
            
            <div class="info-item">
              <label>发现年份</label>
              <div class="info-value">
                <i class="fas fa-calendar-alt" style="color: var(--primary-color);"></i>
                ${Utils.extractYearFromCveId(cve.cve_id)}年
              </div>
            </div>
            
            <div class="info-item">
              <label>分类时间</label>
              <div class="info-value">
                <i class="fas fa-clock" style="color: var(--primary-color);"></i>
                ${Utils.formatDate(cve.classification_timestamp, CONFIG.DATE_FORMATS.TOOLTIP)}
              </div>
            </div>
          </div>
        </div>

        <!-- 中文摘要 -->
        <div class="details-section">
          <div class="section-title">
            <i class="fas fa-file-alt"></i>
            <h3>中文摘要</h3>
          </div>
          <div class="summary-content">
            <p>${cve.summary}</p>
          </div>
        </div>

        <!-- 关键点 -->
        <div class="details-section">
          <div class="section-title">
            <i class="fas fa-list-ul"></i>
            <h3>关键点</h3>
          </div>
          <ul class="key-points-list">
            ${cve.key_points.map(point => `<li>${point}</li>`).join('')}
          </ul>
        </div>

        <!-- 技术细节 -->
        <div class="details-section">
          <div class="section-title">
            <i class="fas fa-cogs"></i>
            <h3>技术细节</h3>
            <button class="expand-btn" data-target="technical-details">
              <i class="fas fa-chevron-down"></i>
            </button>
          </div>
          <div class="expandable-content" id="technical-details">
            <div class="technical-details">
              ${this.formatTechnicalDetails(cve.technical_details)}
            </div>
          </div>
        </div>

        ${this.buildOriginalDataSection(cve)}
        ${this.buildRelatedCvesSection(cve.cve_id)}
        
        <!-- 操作按钮 -->
        <div class="details-actions">
          <button class="action-btn primary" data-action="copy-link" data-cve="${cve.cve_id}">
            <i class="fas fa-link"></i>
            复制分享链接
          </button>
          <button class="action-btn secondary" data-action="export" data-cve="${cve.cve_id}">
            <i class="fas fa-download"></i>
            导出JSON
          </button>
          <button class="action-btn secondary" data-action="open-official" data-cve="${cve.cve_id}">
            <i class="fas fa-external-link-alt"></i>
            官方页面
          </button>
        </div>
      </div>
    `;
  },

  /**
   * 构建原始数据部分
   */
  buildOriginalDataSection(cve) {
    if (!cve.original_data) return '';

    const originalData = cve.original_data;
    
    return `
      <div class="details-section">
        <div class="section-title">
          <i class="fas fa-database"></i>
          <h3>原始数据</h3>
          <button class="expand-btn" data-target="original-data">
            <i class="fas fa-chevron-down"></i>
          </button>
        </div>
        <div class="expandable-content collapsed" id="original-data">
          ${this.buildOriginalDataContent(originalData)}
        </div>
      </div>
    `;
  },

  /**
   * 构建原始数据内容
   */
  buildOriginalDataContent(originalData) {
    let content = '';

    // 参考链接（最重要，优先显示）
    if (originalData.references && originalData.references.length > 0) {
      content += `
        <div class="original-data-item">
          <h4><i class="fas fa-link"></i> 参考链接</h4>
          <div class="references">
            ${this.formatReferences(originalData.references)}
          </div>
        </div>
      `;
    }

    // 英文描述
    if (originalData.descriptions && originalData.descriptions.length > 0) {
      content += `
        <div class="original-data-item">
          <h4><i class="fas fa-language"></i> 原始描述</h4>
          <div class="descriptions">
            ${this.formatDescriptions(originalData.descriptions)}
          </div>
        </div>
      `;
    }

    // CVSS评分
    if (originalData.metrics) {
      content += `
        <div class="original-data-item">
          <h4><i class="fas fa-tachometer-alt"></i> CVSS评分</h4>
          <div class="cvss-info">
            ${this.formatCvssInfo(originalData.metrics)}
          </div>
        </div>
      `;
    }

    // 受影响的产品
    if (originalData.configurations) {
      content += `
        <div class="original-data-item">
          <h4><i class="fas fa-server"></i> 受影响的配置</h4>
          <div class="configurations">
            ${this.formatConfigurations(originalData.configurations)}
          </div>
        </div>
      `;
    }

    return content || '<p style="color: var(--text-secondary); text-align: center; padding: 20px;">暂无原始数据</p>';
  },

  /**
   * 构建相关CVE部分
   */
  buildRelatedCvesSection(cveId) {
    const relatedCves = DataLoader.getRelatedCves(cveId, 5);
    
    if (!relatedCves || relatedCves.length === 0) {
      return '';
    }

    return `
      <div class="details-section">
        <div class="section-title">
          <i class="fas fa-link"></i>
          <h3>相关CVE</h3>
        </div>
        <div class="related-cves">
          ${relatedCves.map(cve => this.buildRelatedCveItem(cve)).join('')}
        </div>
      </div>
    `;
  },

  /**
   * 构建相关CVE项目
   */
  buildRelatedCveItem(cve) {
    const categoryColor = CONFIG.CATEGORIES[cve.category]?.color || '#6B7280';
    const severity = Utils.parseSeverity(cve.severity_assessment);
    const severityConfig = CONFIG.SEVERITY_LEVELS[severity];
    
    return `
      <div class="related-cve-item" data-cve="${cve.cve_id}">
        <div class="related-cve-header">
          <span class="related-cve-id">${cve.cve_id}</span>
          <span class="related-cve-category" style="background: ${categoryColor}15; color: ${categoryColor}; border: 1px solid ${categoryColor}40;">
            ${Utils.getCategoryDisplayName(cve.category)}
          </span>
        </div>
        <div class="related-cve-summary">
          ${Utils.truncateText(cve.summary, 100)}
        </div>
        <div class="related-cve-footer" style="margin-top: 8px; display: flex; justify-content: space-between; align-items: center;">
          <span style="font-size: 11px; color: var(--text-secondary);">
            <i class="fas fa-calendar"></i> ${Utils.extractYearFromCveId(cve.cve_id)}
          </span>
          <span style="font-size: 11px; padding: 2px 8px; border-radius: 10px; background: ${severityConfig?.color}15; color: ${severityConfig?.color};">
            ${severityConfig?.label || severity}
          </span>
        </div>
      </div>
    `;
  },

  /**
   * 格式化技术细节
   */
  formatTechnicalDetails(details) {
    if (!details) return '<p style="color: var(--text-secondary); text-align: center; padding: 20px;">暂无技术细节</p>';
    
    // 将换行符转换为HTML段落
    return details.split('\n').map(paragraph => {
      if (paragraph.trim()) {
        return `<p>${paragraph.trim()}</p>`;
      }
      return '';
    }).join('');
  },

  /**
   * 格式化CVSS信息
   */
  formatCvssInfo(metrics) {
    if (!metrics) return '<p style="color: var(--text-secondary);">暂无CVSS信息</p>';
    
    let html = '<div style="display: flex; flex-direction: column; gap: 12px;">';
    
    // CVSS v3
    if (metrics.cvssMetricV31 && metrics.cvssMetricV31.length > 0) {
      const cvss = metrics.cvssMetricV31[0];
      const data = cvss.cvssData;
      const score = data.baseScore;
      const severity = data.baseSeverity;
      const color = this.getCvssColor(score);
      
      html += `
        <div style="padding: 12px; background: ${color}10; border-left: 3px solid ${color}; border-radius: 6px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="color: var(--text-primary);">CVSS v3.1</strong>
            <span style="font-size: 24px; font-weight: 700; color: ${color};">${score}</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary);">
            <div><strong>严重程度:</strong> <span style="color: ${color};">${severity}</span></div>
            <div><strong>向量:</strong> <code style="font-size: 11px; background: var(--bg-tertiary); padding: 2px 6px; border-radius: 3px;">${data.vectorString}</code></div>
          </div>
        </div>
      `;
    }
    
    // CVSS v2
    if (metrics.cvssMetricV2 && metrics.cvssMetricV2.length > 0) {
      const cvss = metrics.cvssMetricV2[0];
      const data = cvss.cvssData;
      const score = data.baseScore;
      const severity = cvss.baseSeverity;
      const color = this.getCvssColor(score);
      
      html += `
        <div style="padding: 12px; background: ${color}10; border-left: 3px solid ${color}; border-radius: 6px;">
          <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
            <strong style="color: var(--text-primary);">CVSS v2.0</strong>
            <span style="font-size: 24px; font-weight: 700; color: ${color};">${score}</span>
          </div>
          <div style="font-size: 13px; color: var(--text-secondary);">
            <div><strong>严重程度:</strong> <span style="color: ${color};">${severity}</span></div>
            <div><strong>向量:</strong> <code style="font-size: 11px; background: var(--bg-tertiary); padding: 2px 6px; border-radius: 3px;">${data.vectorString}</code></div>
          </div>
        </div>
      `;
    }
    
    html += '</div>';
    return html;
  },

  /**
   * 获取CVSS分数对应的颜色
   */
  getCvssColor(score) {
    if (score >= 9.0) return '#DC2626';      // Critical: 红色
    if (score >= 7.0) return '#EA580C';      // High: 橙色
    if (score >= 4.0) return '#EAB308';      // Medium: 黄色
    if (score > 0.0) return '#22C55E';       // Low: 绿色
    return '#6B7280';                        // None: 灰色
  },

  /**
   * 格式化配置信息
   */
  formatConfigurations(configurations) {
    if (!configurations || !configurations.length) {
      return '<p style="color: var(--text-secondary);">暂无配置信息</p>';
    }
    
    // 简化显示：只显示受影响的产品数量和部分示例
    let html = '<div style="font-size: 13px; line-height: 1.8; color: var(--text-secondary);">';
    html += `<p>该漏洞影响了多个配置和产品。详细信息请参考官方CVE页面。</p>`;
    html += '</div>';
    
    return html;
  },

  /**
   * 格式化参考链接
   */
  formatReferences(references) {
    if (!references || !Array.isArray(references) || references.length === 0) {
      return '<p style="color: var(--text-secondary);">暂无参考链接</p>';
    }

    return references.map((ref, index) => {
      const url = ref.url || ref;
      const tags = ref.tags || [];
      const displayUrl = url.length > 80 ? url.substring(0, 77) + '...' : url;
      
      return `
        <div class="reference-item">
          <div style="display: flex; align-items: start; gap: 8px;">
            <span style="color: var(--primary-color); font-weight: 600; min-width: 24px;">${index + 1}.</span>
            <div style="flex: 1;">
              <a href="${url}" target="_blank" rel="noopener noreferrer" title="${url}">
                <i class="fas fa-external-link-alt" style="font-size: 11px; margin-right: 4px;"></i>
                ${displayUrl}
              </a>
              ${tags.length > 0 ? `
                <div style="margin-top: 6px;">
                  ${tags.map(tag => `
                    <span class="reference-tags">${tag}</span>
                  `).join('')}
                </div>
              ` : ''}
            </div>
          </div>
        </div>
      `;
    }).join('');
  },

  /**
   * 格式化描述信息
   */
  formatDescriptions(descriptions) {
    if (!descriptions || !Array.isArray(descriptions) || descriptions.length === 0) {
      return '<p style="color: var(--text-secondary);">暂无描述信息</p>';
    }

    return descriptions.map(desc => {
      const lang = desc.lang || 'en';
      const value = desc.value || '';
      const langDisplay = lang === 'en' ? '英文' : lang === 'zh' ? '中文' : lang.toUpperCase();
      
      return `
        <div class="description-item">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
            <i class="fas fa-language" style="color: var(--primary-color);"></i>
            <strong>${langDisplay}</strong>
          </div>
          <div style="line-height: 1.8; text-align: justify;">
            ${value}
          </div>
        </div>
      `;
    }).join('');
  },

  /**
   * 绑定详情页面事件
   */
  bindDetailsEvents(cve) {
    // 展开/收起按钮
    const expandBtns = this.modalBody.querySelectorAll('.expand-btn');
    expandBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const target = e.currentTarget.dataset.target;
        const content = document.getElementById(target);
        const icon = btn.querySelector('i');
        
        if (content) {
          content.classList.toggle('collapsed');
          icon.classList.toggle('fa-chevron-down');
          icon.classList.toggle('fa-chevron-up');
        }
      });
    });

    // 复制按钮
    const copyBtns = this.modalBody.querySelectorAll('.copy-btn');
    copyBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const text = e.currentTarget.dataset.copy;
        this.copyToClipboard(text);
      });
    });

    // 相关CVE点击
    const relatedCveItems = this.modalBody.querySelectorAll('.related-cve-item');
    relatedCveItems.forEach(item => {
      item.addEventListener('click', (e) => {
        const cveId = e.currentTarget.dataset.cve;
        this.showDetails(cveId);
      });
    });

    // 操作按钮
    const actionBtns = this.modalBody.querySelectorAll('.action-btn');
    actionBtns.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const action = e.currentTarget.dataset.action;
        const cveId = e.currentTarget.dataset.cve;
        this.handleAction(action, cveId, cve);
      });
    });
  },

  /**
   * 处理操作按钮点击
   */
  handleAction(action, cveId, cveData) {
    switch (action) {
      case 'copy-link':
        this.copyLink(cveId);
        break;
      case 'export':
        this.exportCveData(cveData);
        break;
      case 'open-official':
        this.openOfficialPage(cveId);
        break;
      default:
        Utils.log('warn', 'Unknown action', action);
    }
  },

  /**
   * 复制到剪贴板
   */
  async copyToClipboard(text) {
    try {
      await navigator.clipboard.writeText(text);
      Utils.showToast('已复制到剪贴板', 'success');
    } catch (error) {
      Utils.log('error', 'Failed to copy to clipboard', error);
      Utils.showToast('复制失败', 'error');
    }
  },

  /**
   * 复制CVE链接
   */
  copyLink(cveId) {
    const url = `${window.location.origin}${window.location.pathname}?cve=${cveId}`;
    this.copyToClipboard(url);
  },

  /**
   * 导出CVE数据
   */
  exportCveData(cveData) {
    const data = {
      cve_id: cveData.cve_id,
      category: cveData.category,
      summary: cveData.summary,
      key_points: cveData.key_points,
      severity_assessment: cveData.severity_assessment,
      technical_details: cveData.technical_details,
      classification_timestamp: cveData.classification_timestamp
    };

    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json'
    });
    
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${cveData.cve_id}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    Utils.showToast('CVE数据导出成功', 'success');
  },

  /**
   * 打开官方页面
   */
  openOfficialPage(cveId) {
    const url = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`;
    window.open(url, '_blank', 'noopener,noreferrer');
  },

  /**
   * 显示加载状态的模态框
   */
  showLoadingModal(cveId) {
    if (!this.modalTitle || !this.modalBody) return;

    this.modalTitle.textContent = cveId;
    this.modalBody.innerHTML = `
      <div class="loading-content">
        <div class="loading-spinner">
          <i class="fas fa-spinner fa-spin"></i>
          <p>加载CVE详情中...</p>
        </div>
      </div>
    `;
    
    this.showModal();
  },

  /**
   * 显示错误模态框
   */
  showErrorModal(cveId, message) {
    if (!this.modalTitle || !this.modalBody) return;

    this.modalTitle.textContent = cveId;
    this.modalBody.innerHTML = `
      <div class="error-content">
        <div class="error-message">
          <i class="fas fa-exclamation-triangle"></i>
          <h3>加载失败</h3>
          <p>${message}</p>
          <button class="retry-btn" onclick="CveDetails.showDetails('${cveId}')">
            <i class="fas fa-redo"></i>
            重试
          </button>
        </div>
      </div>
    `;
    
    this.showModal();
  },

  /**
   * 显示模态框
   */
  showModal() {
    if (this.modal) {
      this.modal.classList.add('active');
      document.body.style.overflow = 'hidden';
    }
  },

  /**
   * 隐藏模态框
   */
  hideModal() {
    if (this.modal) {
      this.modal.classList.remove('active');
      document.body.style.overflow = '';
      this.currentCve = null;
    }
  },

  /**
   * 从URL参数显示CVE详情
   */
  showFromUrlParams() {
    const cveId = Utils.getUrlParameter('cve');
    if (cveId) {
      this.showDetails(cveId);
    }
  }
};

// 导出CVE详情模块
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CveDetails;
}