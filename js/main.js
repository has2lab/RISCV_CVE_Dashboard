// RISC-V CVE Dashboard - 主应用程序
const App = {
  // 应用状态
  state: {
    initialized: false,
    currentSection: 'dashboard',
    data: null,
    theme: 'light'
  },

  /**
   * 应用程序初始化
   */
  async init() {
    try {
      Utils.log('info', 'App initializing...');
      
      // 初始化主题
      this.initTheme();
      
      // 初始化各个模块
      Charts.init();
      CveDetails.init();
      Filters.init();
      
      // 加载数据
      this.state.data = await DataLoader.init();
      
      // 初始化导航
      this.initNavigation();
      
      // 初始化各个页面
      await this.initDashboard();
      await this.initAnalysis();
      await this.initCveBrowser();
      await this.initCategories();
      
      // 绑定全局事件
      this.bindGlobalEvents();
      
      // 从URL恢复状态
      this.restoreFromUrl();
      
      // 标记为已初始化
      this.state.initialized = true;
      
      Utils.log('info', 'App initialized successfully');
      Utils.showToast('应用程序加载完成', 'success');

    } catch (error) {
      Utils.log('error', 'App initialization failed', error);
      Utils.showToast('应用程序初始化失败', 'error', 5000);
      
      // 显示错误页面
      this.showErrorPage(error.message);
    }
  },

  /**
   * 初始化主题
   */
  initTheme() {
    // 从本地存储恢复主题
    const savedTheme = localStorage.getItem(CONFIG.STORAGE_KEYS.THEME);
    if (savedTheme && CONFIG.THEMES[savedTheme.toUpperCase()]) {
      this.state.theme = savedTheme;
    }

    // 应用主题
    this.applyTheme(this.state.theme);
  },

  /**
   * 应用主题
   */
  applyTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    this.state.theme = theme;
    
    // 保存到本地存储
    localStorage.setItem(CONFIG.STORAGE_KEYS.THEME, theme);
    
    // 更新主题切换按钮图标
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      const icon = themeToggle.querySelector('i');
      if (icon) {
        icon.className = theme === 'dark' ? 'fas fa-sun' : 'fas fa-moon';
      }
    }

    Utils.log('info', 'Theme applied', theme);
  },

  /**
   * 初始化导航
   */
  initNavigation() {
    const navLinks = document.querySelectorAll('.nav-link[data-target]');
    
    navLinks.forEach(link => {
      link.addEventListener('click', (e) => {
        e.preventDefault();
        const target = e.currentTarget.dataset.target;
        this.switchSection(target);
      });
    });

    // 主题切换
    const themeToggle = document.getElementById('themeToggle');
    if (themeToggle) {
      themeToggle.addEventListener('click', () => {
        this.toggleTheme();
      });
    }

    // 导出按钮
    const exportBtn = document.getElementById('exportBtn');
    if (exportBtn) {
      exportBtn.addEventListener('click', () => {
        this.showExportDialog();
      });
    }
  },

  /**
   * 切换主题
   */
  toggleTheme() {
    const newTheme = this.state.theme === 'light' ? 'dark' : 'light';
    this.applyTheme(newTheme);
  },

  /**
   * 切换页面章节
   */
  switchSection(sectionName) {
    // 隐藏所有章节
    const sections = document.querySelectorAll('.content-section');
    sections.forEach(section => {
      section.classList.remove('active');
    });

    // 显示目标章节
    const targetSection = document.getElementById(sectionName);
    if (targetSection) {
      targetSection.classList.add('active');
    }

    // 更新导航状态
    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
      link.classList.remove('active');
    });

    const activeLink = document.querySelector(`.nav-link[data-target="${sectionName}"]`);
    if (activeLink) {
      activeLink.classList.add('active');
    }

    // 更新状态
    this.state.currentSection = sectionName;

    // 更新URL
    this.updateUrl();

    // 触发章节切换事件
    this.onSectionSwitch(sectionName);

    Utils.log('info', 'Section switched', sectionName);
  },

  /**
   * 章节切换事件处理
   */
  onSectionSwitch(sectionName) {
    switch (sectionName) {
      case 'dashboard':
        this.refreshDashboard();
        break;
      case 'analysis':
        this.refreshAnalysis();
        break;
      case 'cve-browser':
        this.refreshCveBrowser();
        break;
      case 'categories':
        this.refreshCategories();
        break;
    }
  },

  /**
   * 初始化总览仪表板
   */
  async initDashboard() {
    Utils.log('info', 'Initializing dashboard...');
    
    try {
      // 更新关键指标
      this.updateMetrics();
      
      // 创建分类分布图
      const categoryData = DataLoader.getCategoryDistribution();
      Charts.createCategoryChart('categoryChart', categoryData);
      
      // 创建年度趋势图
      const yearlyData = DataLoader.getYearlyDistribution();
      Charts.createTrendChart('trendChart', yearlyData);
      
      // 更新快速统计
      this.updateQuickStats();
      
      // 绑定图表控制器
      this.bindChartControls();

    } catch (error) {
      Utils.log('error', 'Failed to initialize dashboard', error);
    }
  },

  /**
   * 更新关键指标
   */
  updateMetrics() {
    const stats = DataLoader.getStatistics();
    if (!stats) return;

    // CVE总数
    const totalCvesEl = document.getElementById('totalCves');
    if (totalCvesEl) {
      totalCvesEl.textContent = Utils.formatNumber(stats.totalCves);
    }

    // CVE趋势 (本年度新增)
    const cveTrendEl = document.getElementById('cveTrend');
    if (cveTrendEl) {
      const yearlyData = DataLoader.getYearlyDistribution();
      const currentYear = new Date().getFullYear();
      const currentYearData = yearlyData.find(d => d.year === currentYear);
      const count = currentYearData ? currentYearData.total : 0;
      
      cveTrendEl.innerHTML = `
        <i class="fas fa-arrow-up"></i>
        <span>+${count} ${currentYear}年</span>
      `;
    }

    // 分类完成率
    const classificationRateEl = document.getElementById('classificationRate');
    if (classificationRateEl) {
      const rate = Math.round((stats.successfullyProcessed / stats.totalCves) * 100);
      classificationRateEl.textContent = `${rate}%`;
    }

    // 年份跨度
    const yearSpanEl = document.getElementById('yearSpan');
    if (yearSpanEl) {
      const yearlyData = DataLoader.getYearlyDistribution();
      if (yearlyData.length > 0) {
        const minYear = Math.min(...yearlyData.map(d => d.year));
        const maxYear = Math.max(...yearlyData.map(d => d.year));
        yearSpanEl.textContent = `${maxYear - minYear + 1}年`;
      }
    }

    // 漏洞数量
    const criticalCountEl = document.getElementById('criticalCount');
    if (criticalCountEl) {
      const severityData = DataLoader.getSeverityDistribution();
      const criticalData = severityData.find(item => item.severity === 'Critical' || item.severity === 'High');
      criticalCountEl.textContent = criticalData ? criticalData.count : '0';
    }

    // 最后更新时间
    const lastUpdateEl = document.getElementById('lastUpdate');
    if (lastUpdateEl && stats.lastUpdated) {
      lastUpdateEl.textContent = Utils.formatDate(stats.lastUpdated, 'MM月DD日');
    }
  },

  /**
   * 更新快速统计
   */
  updateQuickStats() {
    const stats = DataLoader.getStatistics();
    if (!stats) return;

    const elements = {
      'linuxKernelCount': 'Linux Kernel',
      'cpuSocCount': 'RISC-V CPU/SoC',
      'devToolsCount': 'RISC-V Development Tools',
      'simulatorCount': 'Simulator'
    };

    Object.entries(elements).forEach(([elementId, category]) => {
      const element = document.getElementById(elementId);
      if (element) {
        const count = stats.byCategory[category] || 0;
        element.textContent = Utils.formatNumber(count);
      }
    });
  },

  /**
   * 绑定图表控制器
   */
  bindChartControls() {
    // 分类图表类型切换
    const categoryControls = document.querySelectorAll('[data-chart]');
    categoryControls.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const chartType = e.currentTarget.dataset.chart;
        this.switchCategoryChart(chartType);
        
        // 更新按钮状态
        categoryControls.forEach(b => b.classList.remove('active'));
        e.currentTarget.classList.add('active');
      });
    });

    // 趋势图类型切换
    const trendControls = document.querySelectorAll('[data-trend]');
    trendControls.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const trendType = e.currentTarget.dataset.trend;
        this.switchTrendChart(trendType);
        
        // 更新按钮状态
        trendControls.forEach(b => b.classList.remove('active'));
        e.currentTarget.classList.add('active');
      });
    });
  },

  /**
   * 切换分类图表类型
   */
  switchCategoryChart(type) {
    const categoryData = DataLoader.getCategoryDistribution();
    Charts.createCategoryChart('categoryChart', categoryData, type);
  },

  /**
   * 切换趋势图表类型
   */
  switchTrendChart(type) {
    const yearlyData = DataLoader.getYearlyDistribution();
    const stacked = type === 'stacked';
    Charts.createTrendChart('trendChart', yearlyData, stacked);
  },

  /**
   * 初始化分析页面
   */
  async initAnalysis() {
    Utils.log('info', 'Initializing analysis...');
    
    try {
      // 创建严重程度分布图
      const severityData = DataLoader.getSeverityDistribution();
      Utils.log('info', `Severity data: ${severityData.length} levels`);
      Charts.createSeverityChart('severityChart', severityData);
      
      // 创建时间线图
      if (this.state.data && this.state.data.summary) {
        const cves = this.state.data.summary.classified_cves;
        Utils.log('info', `Creating timeline with ${cves ? cves.length : 0} CVEs`);
        if (cves && cves.length > 0) {
          Charts.createTimelineChart('timelineChart', cves);
        } else {
          Utils.log('warn', 'No CVEs data for timeline');
        }
      } else {
        Utils.log('warn', 'No summary data available');
      }
      
      // 创建词云
      Utils.log('info', 'Creating word cloud...');
      const keywords = DataLoader.getKeywordStatistics();
      Utils.log('info', `Keywords extracted: ${keywords.length}`);
      Charts.createWordCloud('wordcloudContainer', keywords);
      
      // 绑定时间线控制器
      this.bindTimelineControls();
      
      // 更新漏洞类型分布
      Utils.log('info', 'Updating vulnerability types...');
      this.updateVulnerabilityTypes();

      Utils.log('info', 'Analysis page initialized successfully');
    } catch (error) {
      Utils.log('error', 'Failed to initialize analysis', error);
      Utils.showToast('分析页面初始化失败', 'error');
    }
  },

  /**
   * 绑定时间线控制器
   */
  bindTimelineControls() {
    const timelineControls = document.querySelectorAll('.timeline-btn');
    timelineControls.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const period = e.currentTarget.dataset.period;
        this.switchTimelinePeriod(period);
        
        // 更新按钮状态
        timelineControls.forEach(b => b.classList.remove('active'));
        e.currentTarget.classList.add('active');
      });
    });
  },

  /**
   * 切换时间线周期
   */
  switchTimelinePeriod(period) {
    if (this.state.data && this.state.data.summary) {
      const cves = this.state.data.summary.classified_cves;
      Charts.createTimelineChart('timelineChart', cves, period);
    }
  },

  /**
   * 更新漏洞类型分布
   */
  updateVulnerabilityTypes() {
    const container = document.getElementById('vulnerabilityTypes');
    if (!container) {
      Utils.log('warn', 'Vulnerability types container not found');
      return;
    }

    if (!this.state.data || !this.state.data.summary) {
      container.innerHTML = '<p style="padding: 2rem; text-align: center; color: #999;">数据加载中...</p>';
      return;
    }

    try {
      // 从关键词中提取漏洞类型
      const keywords = DataLoader.getKeywordStatistics();
      
      // 定义漏洞类型关键词模式
      const typePatterns = {
        '缓冲区溢出': ['overflow', 'buffer', '溢出', '缓冲区'],
        '权限提升': ['privilege', 'escalation', '权限', '提升'],
        '拒绝服务': ['denial', 'dos', 'crash', '拒绝', '服务', '崩溃'],
        '内存相关': ['memory', 'leak', 'corruption', '内存', '泄露'],
        '空指针': ['null', 'pointer', '空指针'],
        '代码执行': ['execution', 'code', '执行', '代码'],
        '信息泄露': ['disclosure', 'information', '信息', '泄露'],
        '访问控制': ['access', 'control', '访问', '控制']
      };

      const vulnTypes = {};
      
      // 分析CVE摘要和关键词
      keywords.forEach(kw => {
        const word = kw.word.toLowerCase();
        for (const [type, patterns] of Object.entries(typePatterns)) {
          if (patterns.some(pattern => word.includes(pattern.toLowerCase()))) {
            vulnTypes[type] = (vulnTypes[type] || 0) + kw.count;
          }
        }
      });

      // 转换为数组并排序
      const vulnTypesArray = Object.entries(vulnTypes)
        .map(([type, count]) => ({ type, count }))
        .sort((a, b) => b.count - a.count)
        .slice(0, 10);

      if (vulnTypesArray.length === 0) {
        container.innerHTML = `
          <div style="padding: 2rem; text-align: center; color: #999;">
            <i class="fas fa-bug" style="font-size: 3rem; margin-bottom: 1rem; display: block;"></i>
            <p>暂无漏洞类型统计数据</p>
          </div>
        `;
        return;
      }

      const maxCount = Math.max(...vulnTypesArray.map(v => v.count));

      container.innerHTML = `
        <h3 style="margin: 0 0 1rem 0; padding: 1rem; background: var(--background-secondary); border-bottom: 1px solid var(--border-color);">
          <i class="fas fa-bug"></i> 漏洞类型分布
        </h3>
        <div style="padding: 1rem;">
          ${vulnTypesArray.map((type, index) => `
            <div class="vuln-type-item" style="display: flex; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid var(--border-color);">
              <span class="vuln-type-name" style="flex: 0 0 120px; font-weight: 500;">${type.type}</span>
              <div class="vuln-type-bar" style="flex: 1; height: 20px; background: var(--background-secondary); border-radius: 10px; margin: 0 1rem; overflow: hidden; position: relative;">
                <div class="vuln-type-fill" style="height: 100%; width: ${(type.count / maxCount) * 100}%; background: linear-gradient(90deg, ${CONFIG.WORDCLOUD.COLORS[index % CONFIG.WORDCLOUD.COLORS.length]}, ${CONFIG.WORDCLOUD.COLORS[index % CONFIG.WORDCLOUD.COLORS.length]}80); border-radius: 10px; transition: width 0.8s ease;"></div>
              </div>
              <span class="vuln-type-count" style="flex: 0 0 50px; text-align: right; font-weight: 600; color: ${CONFIG.WORDCLOUD.COLORS[index % CONFIG.WORDCLOUD.COLORS.length]};">${type.count}</span>
            </div>
          `).join('')}
        </div>
      `;

      Utils.log('info', `Vulnerability types updated: ${vulnTypesArray.length} types`);
    } catch (error) {
      Utils.log('error', 'Error updating vulnerability types', error);
      container.innerHTML = '<p style="padding: 2rem; text-align: center; color: #f44;">加载失败</p>';
    }
  },

  /**
   * 初始化CVE浏览器
   */
  async initCveBrowser() {
    Utils.log('info', 'Initializing CVE browser...');
    
    try {
      // 初始化筛选器选项（在数据加载后）
      Filters.initFilterOptions();
      
      // 应用初始筛选
      Filters.applyFilters();

    } catch (error) {
      Utils.log('error', 'Failed to initialize CVE browser', error);
    }
  },

  /**
   * 初始化分类分析
   */
  async initCategories() {
    Utils.log('info', 'Initializing categories...');

    try {
      // 根据实际数据动态生成分类标签按钮
      const defaultCategory = this.renderCategoryTabs();

      // 绑定分类标签事件（使用事件代理以兼容动态生成的按钮）
      this.bindCategoryTabs();

      // 显示默认分类内容（默认为条数最多的分类）
      if (defaultCategory) {
        this.showCategoryContent(defaultCategory);
      }

    } catch (error) {
      Utils.log('error', 'Failed to initialize categories', error);
    }
  },

  /**
   * 按条数降序渲染所有存在 CVE 的分类标签
   * @returns {string|null} 默认选中的分类（第一个 tab）
   */
  renderCategoryTabs() {
    const container = document.getElementById('categoryTabs');
    if (!container) return null;

    const stats = DataLoader.getStatistics();
    if (!stats || !stats.byCategory) {
      container.innerHTML = '';
      return null;
    }

    const sorted = Object.entries(stats.byCategory)
      .filter(([, count]) => count > 0)
      .sort(([, a], [, b]) => b - a);

    if (sorted.length === 0) {
      container.innerHTML = '';
      return null;
    }

    const tabsHtml = sorted.map(([category, count], idx) => {
      const name = Utils.getCategoryDisplayName(category);
      const active = idx === 0 ? ' active' : '';
      return `<button class="category-tab${active}" data-category="${category}">
        <span class="tab-name">${name}</span>
        <span class="tab-count">${count}</span>
      </button>`;
    }).join('');

    const allTab = `<button class="category-tab" data-category="all">
      <span class="tab-name">全部对比</span>
    </button>`;

    container.innerHTML = tabsHtml + allTab;
    return sorted[0][0];
  },

  /**
   * 绑定分类标签事件（事件代理，支持动态生成的按钮）
   */
  bindCategoryTabs() {
    const container = document.getElementById('categoryTabs');
    if (!container || container.dataset.bound === '1') return;

    container.addEventListener('click', (e) => {
      const tab = e.target.closest('.category-tab');
      if (!tab) return;
      const category = tab.dataset.category;
      this.switchCategoryTab(category);

      container.querySelectorAll('.category-tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
    });

    container.dataset.bound = '1';
  },

  /**
   * 切换分类标签
   */
  switchCategoryTab(category) {
    this.showCategoryContent(category);
  },

  /**
   * 显示分类内容
   */
  showCategoryContent(category) {
    const container = document.getElementById('categoryContent');
    if (!container) return;

    if (category === 'all') {
      // 切换到对比视图时销毁之前的 stacked chart
      if (this._categoryStackedChart) {
        this._categoryStackedChart.destroy();
        this._categoryStackedChart = null;
      }
      container.innerHTML = this.buildAllCategoriesContent();
    } else {
      container.innerHTML = this.buildSingleCategoryContent(category);
      // 内容插入 DOM 后再绘制 canvas 图表
      if (this.state.data && this.state.data.summary) {
        const cves = this.state.data.summary.classified_cves.filter(cve => cve.category === category);
        this.renderCategoryYearSeverityChart(cves);
      }
    }
  },

  /**
   * 构建单一分类内容
   */
  buildSingleCategoryContent(category) {
    if (!this.state.data || !this.state.data.summary) {
      return '<p>数据加载中...</p>';
    }

    const cves = this.state.data.summary.classified_cves.filter(cve => cve.category === category);
    const stats = DataLoader.getStatistics();
    const categoryCount = stats.byCategory[category] || 0;
    const categoryColor = CONFIG.CATEGORIES[category]?.color || '#3B82F6';

    return `
      <div class="category-detail-simple">
        <!-- 分类标题栏 -->
        <div class="category-title-section">
          <div class="category-icon-large" style="background: ${categoryColor}">
            <i class="fas ${this.getCategoryIcon(category)}"></i>
          </div>
          <div class="category-info">
            <h2>${Utils.getCategoryDisplayName(category)}</h2>
            <p class="category-desc">${this.getCategoryDescription(category)}</p>
            <div class="category-meta">
              <span class="meta-item">
                <i class="fas fa-database"></i>
                <strong>${categoryCount}</strong> 个CVE
              </span>
              <span class="meta-item">
                <i class="fas fa-percentage"></i>
                占比 <strong>${Utils.formatPercentage(categoryCount, stats.totalCves)}</strong>
              </span>
            </div>
          </div>
        </div>

        <!-- 统计数据卡片 -->
        <div class="stats-cards-row">
          ${this.buildStatsCards(cves)}
        </div>

        <!-- 主要内容区域 -->
        <div class="category-content-grid">
          <!-- 左侧：年度分布 -->
          <div class="content-section">
            <div class="section-header-simple">
              <h3><i class="fas fa-chart-line"></i> 年度分布</h3>
            </div>
            <div class="year-chart-area">
              ${this.buildYearDistribution(cves)}
            </div>
          </div>

          <!-- 右侧：严重程度 -->
          <div class="content-section">
            <div class="section-header-simple">
              <h3><i class="fas fa-shield-alt"></i> 严重程度</h3>
            </div>
            <div class="severity-chart-area">
              ${this.buildSeverityDistribution(cves)}
            </div>
          </div>
        </div>

        <!-- 年份 × 严重程度 堆叠趋势 -->
        <div class="content-section full-width">
          <div class="section-header-simple">
            <h3><i class="fas fa-chart-bar"></i> 年份 × 严重程度 趋势</h3>
          </div>
          <div class="year-severity-chart-wrapper">
            <canvas id="categoryYearSeverityChart"></canvas>
          </div>
        </div>

        <!-- 核心关键词 -->
        <div class="content-section full-width">
          <div class="section-header-simple">
            <h3><i class="fas fa-key"></i> 核心关键词 Top 12</h3>
          </div>
          <div class="top-keywords-cloud">
            ${this.buildTopKeywords(cves)}
          </div>
        </div>

        <!-- CVE列表 -->
        <div class="content-section full-width">
          <div class="section-header-simple">
            <h3><i class="fas fa-list"></i> 最新CVE</h3>
            <button class="view-all-link" onclick="Filters.setFilter('category', '${category}'); document.querySelector('[data-target=cve-browser]').click();">
              查看全部 <i class="fas fa-arrow-right"></i>
            </button>
          </div>
          <div class="cve-list-simple">
            ${[...cves]
              .sort((a, b) => b.cve_id.localeCompare(a.cve_id, undefined, { numeric: true }))
              .slice(0, 10)
              .map(cve => this.buildCategoryCveItem(cve)).join('')}
          </div>
        </div>
      </div>
    `;
  },

  /**
   * 聚合该分类所有 CVE 的文本，提取 Top 12 关键词
   * 同时利用 detailed JSON 中的英文 description 提升召回
   */
  buildTopKeywords(cves) {
    if (!cves || cves.length === 0) {
      return '<p class="empty-hint">暂无关键词数据</p>';
    }

    const detailed = (this.state.data && this.state.data.detailed)
      ? this.state.data.detailed.classified_cves
      : [];
    const detailedMap = {};
    detailed.forEach(c => { detailedMap[c.cve_id] = c; });

    const pieces = [];
    cves.forEach(cve => {
      if (cve.summary) pieces.push(cve.summary);
      if (cve.technical_details) pieces.push(cve.technical_details);
      if (Array.isArray(cve.key_points)) pieces.push(cve.key_points.join(' '));

      const d = detailedMap[cve.cve_id];
      const desc = d && d.original_data && d.original_data.containers
        && d.original_data.containers.cna
        && d.original_data.containers.cna.descriptions
        && d.original_data.containers.cna.descriptions[0]
        && d.original_data.containers.cna.descriptions[0].value;
      if (desc) pieces.push(desc);
    });

    const keywords = Utils.extractKeywords(pieces.join(' '), 12);
    if (!keywords || keywords.length === 0) {
      return '<p class="empty-hint">暂无可提取的英文技术术语</p>';
    }

    const maxCount = keywords[0].count;
    const minCount = keywords[keywords.length - 1].count;
    const range = Math.max(1, maxCount - minCount);

    return keywords.map(({ word, count }) => {
      const weight = (count - minCount) / range;
      const fontSize = (0.85 + weight * 0.65).toFixed(2);
      const opacity = (0.55 + weight * 0.45).toFixed(2);
      return `<span class="keyword-chip" style="font-size:${fontSize}rem;opacity:${opacity}"
        title="出现 ${count} 次">${word}
        <em class="keyword-count">${count}</em>
      </span>`;
    }).join('');
  },

  /**
   * 渲染年份 × 严重程度 堆叠条形图（Chart.js）
   */
  renderCategoryYearSeverityChart(cves) {
    const canvas = document.getElementById('categoryYearSeverityChart');
    if (!canvas || typeof Chart === 'undefined') return;

    // 清理已有 chart（切换 tab 时避免叠加）
    if (this._categoryStackedChart) {
      this._categoryStackedChart.destroy();
      this._categoryStackedChart = null;
    }

    // 聚合：{year -> {severity -> count}}
    const byYear = {};
    cves.forEach(cve => {
      const year = Utils.extractYearFromCveId(cve.cve_id);
      if (!year) return;
      const severity = Utils.parseSeverity(cve.severity_assessment);
      if (!byYear[year]) byYear[year] = {};
      byYear[year][severity] = (byYear[year][severity] || 0) + 1;
    });

    const years = Object.keys(byYear).sort();
    const severityOrder = ['Critical', 'High', 'Medium', 'Low', 'Unknown'];
    const datasets = severityOrder
      .filter(sev => years.some(y => byYear[y][sev]))
      .map(sev => ({
        label: CONFIG.SEVERITY_LEVELS[sev].label || sev,
        data: years.map(y => byYear[y][sev] || 0),
        backgroundColor: CONFIG.SEVERITY_LEVELS[sev].color,
        borderWidth: 0,
      }));

    this._categoryStackedChart = new Chart(canvas.getContext('2d'), {
      type: 'bar',
      data: { labels: years, datasets },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { position: 'bottom' },
          tooltip: { mode: 'index', intersect: false },
        },
        scales: {
          x: { stacked: true, grid: { display: false } },
          y: { stacked: true, beginAtZero: true, ticks: { precision: 0 } },
        },
      },
    });
  },

  /**
   * 构建统计卡片
   */
  buildStatsCards(cves) {
    const severityStats = {};
    const yearNumbers = [];

    cves.forEach(cve => {
      const severity = Utils.parseSeverity(cve.severity_assessment);
      severityStats[severity] = (severityStats[severity] || 0) + 1;

      const year = Utils.extractYearFromCveId(cve.cve_id);
      if (typeof year === 'number' && !isNaN(year)) {
        yearNumbers.push(year);
      }
    });

    const sortedYears = [...yearNumbers].sort((a, b) => a - b);
    const minYear = sortedYears[0];
    const maxYear = sortedYears[sortedYears.length - 1];
    const yearRange = (minYear === maxYear) ? `${minYear || '-'}` : `${minYear} – ${maxYear}`;

    const criticalCount = (severityStats['Critical'] || 0) + (severityStats['High'] || 0);

    // 最新 CVE：按 cve_id 排序取最后一个（CVE ID 单调递增足够近似）
    const sortedByCve = [...cves].sort((a, b) => a.cve_id.localeCompare(b.cve_id, undefined, { numeric: true }));
    const latestCve = sortedByCve[sortedByCve.length - 1];
    const latestCveId = latestCve ? latestCve.cve_id : '-';

    // 近 12 个月新增：CVE ID 年份 ≥ (今年-1)
    const currentYear = new Date().getFullYear();
    const recentCount = yearNumbers.filter(y => y >= currentYear - 1).length;

    const clickLatest = latestCve
      ? `onclick="CveDetails.showDetails('${latestCve.cve_id}')" style="cursor:pointer"`
      : '';

    return `
      <div class="stat-card">
        <div class="stat-icon red">
          <i class="fas fa-exclamation-triangle"></i>
        </div>
        <div class="stat-content">
          <div class="stat-number">${criticalCount}</div>
          <div class="stat-label">高危/严重</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon green">
          <i class="fas fa-clock"></i>
        </div>
        <div class="stat-content">
          <div class="stat-number stat-number-sm">${yearRange}</div>
          <div class="stat-label">年份跨度</div>
        </div>
      </div>
      <div class="stat-card" ${clickLatest}>
        <div class="stat-icon blue">
          <i class="fas fa-star"></i>
        </div>
        <div class="stat-content">
          <div class="stat-number stat-number-sm">${latestCveId}</div>
          <div class="stat-label">最新 CVE</div>
        </div>
      </div>
      <div class="stat-card">
        <div class="stat-icon purple">
          <i class="fas fa-bolt"></i>
        </div>
        <div class="stat-content">
          <div class="stat-number">${recentCount}</div>
          <div class="stat-label">近 12 月新增</div>
        </div>
      </div>
    `;
  },

  /**
   * 构建所有分类对比内容
   */
  buildAllCategoriesContent() {
    const stats = DataLoader.getStatistics();
    if (!stats) return '<p>数据加载中...</p>';

    const totalCves = stats.totalCves;
    const categoryData = Object.entries(stats.byCategory).sort(([,a], [,b]) => b - a);
    const data = this.state.data.summary;

    return `
      <div class="categories-comparison-simple">
        <div class="comparison-header-simple">
          <h2>
            <i class="fas fa-layer-group"></i>
            分类对比分析
          </h2>
          <p class="comparison-subtitle">全面对比各分类的CVE分布和特征</p>
        </div>
        
        <div class="comparison-grid-simple">
          ${categoryData.map(([category, count], index) => {
            const percentage = (count / totalCves * 100).toFixed(1);
            const color = CONFIG.CATEGORIES[category]?.color || '#6B7280';
            const rank = index + 1;
            
            // 计算该分类的统计数据
            const categoryCves = data.classified_cves.filter(cve => cve.category === category);
            const severityStats = {};
            categoryCves.forEach(cve => {
              const severity = Utils.parseSeverity(cve.severity_assessment);
              severityStats[severity] = (severityStats[severity] || 0) + 1;
            });
            const criticalCount = (severityStats['Critical'] || 0) + (severityStats['High'] || 0);
            
            const years = [...new Set(categoryCves.map(cve => Utils.extractYearFromCveId(cve.cve_id)))];
            const latestYear = Math.max(...years.map(Number));
            
            return `
              <div class="category-compare-card" style="border-top-color: ${color}">
                <div class="category-card-header">
                  <div class="category-card-icon" style="background: ${color}">
                    <i class="fas ${this.getCategoryIcon(category)}"></i>
                  </div>
                  <div class="category-card-title">
                    <h3>${Utils.getCategoryDisplayName(category)}</h3>
                    <span class="category-rank-badge">#${rank}</span>
                  </div>
                </div>
                
                <div class="category-card-stats">
                  <div>
                    <div class="category-card-number">${count}</div>
                    <div class="category-card-label">CVE 总数</div>
                  </div>
                  <div>
                    <div class="category-card-percent" style="color: ${color}">${percentage}%</div>
                    <div class="category-card-label">占比</div>
                  </div>
                </div>
                
                <div class="category-card-insights">
                  <div class="category-insight-item">
                    <i class="fas fa-exclamation-triangle" style="color: #EF4444"></i>
                    <span>${criticalCount} 个漏洞</span>
                  </div>
                  <div class="category-insight-item">
                    <i class="fas fa-calendar" style="color: #3B82F6"></i>
                    <span>最新年份: ${latestYear}</span>
                  </div>
                  <div class="category-insight-item">
                    <i class="fas fa-chart-bar" style="color: #10B981"></i>
                    <span>${years.length} 年数据跨度</span>
                  </div>
                </div>
                
                <div class="category-card-action" onclick="document.querySelector('[data-category=\\'${category}\\']').click();">
                  <i class="fas fa-arrow-right"></i> 查看详情
                </div>
              </div>
            `;
          }).join('')}
        </div>
      </div>
    `;
  },

  /**
   * 获取分类图标
   */
  getCategoryIcon(category) {
    const iconMap = {
      'Linux Kernel': 'fa-linux',
      'RISC-V CPU/SoC': 'fa-microchip',
      'RISC-V Development Tools': 'fa-tools',
      'Device-Specific Firmware & Applications': 'fa-code',
      'Simulator': 'fa-desktop',
      'RISC-V Instruction Set Manual': 'fa-book',
      'Other': 'fa-cube'
    };
    return iconMap[category] || 'fa-cube';
  },

  /**
   * 获取分类描述
   */
  getCategoryDescription(category) {
    const descMap = {
      'Linux Kernel': 'Linux内核中与RISC-V架构相关的漏洞，包括内存管理、进程调度、系统调用等核心功能',
      'RISC-V CPU/SoC': 'RISC-V处理器和片上系统的硬件级漏洞，涉及指令集实现、缓存一致性、特权级管理等',
      'RISC-V Development Tools': '开发工具链漏洞，包括编译器、链接器、调试器和构建系统等',
      'Device-Specific Firmware & Applications': '固件或应用程序的安全漏洞',
      'Simulator': 'RISC-V模拟器或虚拟化工具的漏洞',
      'RISC-V Instruction Set Manual': '指令集规范相关的问题和勘误',
      'Other': '其他未分类的RISC-V相关漏洞'
    };
    return descMap[category] || '暂无描述';
  },

  /**
   * 构建增强的年度分布
   */
  buildYearDistribution(cves) {
    const yearStats = {};
    cves.forEach(cve => {
      const year = Utils.extractYearFromCveId(cve.cve_id);
      yearStats[year] = (yearStats[year] || 0) + 1;
    });

    const years = Object.keys(yearStats).sort();
    const maxCount = Math.max(...Object.values(yearStats));

    return `
      <div class="simple-bar-chart">
        ${years.map(year => `
          <div class="bar-item">
            <div class="bar-label">${year}</div>
            <div class="bar-track">
              <div class="bar-fill" style="width: ${(yearStats[year] / maxCount * 100)}%">
                <span class="bar-value">${yearStats[year]}</span>
              </div>
            </div>
          </div>
        `).join('')}
      </div>
    `;
  },

  /**
   * 构建增强的严重程度分布
   */
  buildSeverityDistribution(cves) {
    const severityStats = {};
    cves.forEach(cve => {
      const severity = Utils.parseSeverity(cve.severity_assessment);
      severityStats[severity] = (severityStats[severity] || 0) + 1;
    });

    const total = cves.length;
    const severityOrder = ['Critical', 'High', 'Medium', 'Low'];

    return `
      <div class="simple-severity-chart">
        ${severityOrder.filter(sev => severityStats[sev]).map(severity => {
          const count = severityStats[severity];
          const percentage = ((count / total) * 100).toFixed(1);
          const config = CONFIG.SEVERITY_LEVELS[severity];
          
          return `
            <div class="severity-item">
              <div class="severity-header">
                <span class="severity-name">
                  <i class="fas ${config.icon}" style="color: ${config.color}"></i>
                  ${severity}
                </span>
                <span class="severity-count">${count} (${percentage}%)</span>
              </div>
              <div class="severity-bar-track">
                <div class="severity-bar-fill" style="width: ${percentage}%; background: ${config.color}"></div>
              </div>
            </div>
          `;
        }).join('')}
      </div>
    `;
  },

  /**
   * 构建CVE列表项（含关键要点预览）
   */
  buildCategoryCveItem(cve) {
    const severity = Utils.parseSeverity(cve.severity_assessment);
    const severityConfig = CONFIG.SEVERITY_LEVELS[severity];
    const year = Utils.extractYearFromCveId(cve.cve_id);
    const firstPoint = Array.isArray(cve.key_points) && cve.key_points.length > 0
      ? cve.key_points[0]
      : '';

    return `
      <div class="cve-item-simple" onclick="CveDetails.showDetails('${cve.cve_id}')">
        <div class="cve-item-header">
          <span class="cve-id">${cve.cve_id}</span>
          <span class="cve-severity-badge" style="background: ${severityConfig.color}20; color: ${severityConfig.color}; border: 1px solid ${severityConfig.color}40">
            <i class="fas ${severityConfig.icon}"></i>
            ${severity}
          </span>
        </div>
        <p class="cve-description">${Utils.truncateText(cve.summary || '暂无描述', 120)}</p>
        ${firstPoint ? `<div class="cve-keypoint"><i class="fas fa-lightbulb"></i> ${Utils.truncateText(firstPoint, 100)}</div>` : ''}
        <div class="cve-item-footer">
          <span class="cve-meta">
            <i class="fas fa-calendar"></i>
            ${year}
          </span>
          <span class="cve-action">
            查看详情 <i class="fas fa-chevron-right"></i>
          </span>
        </div>
      </div>
    `;
  },

  /**
   * 刷新总览仪表板
   */
  refreshDashboard() {
    if (!this.state.initialized) return;
    
    // 可以在这里添加实时数据更新逻辑
    Utils.log('debug', 'Dashboard refreshed');
  },

  /**
   * 刷新分析页面
   */
  refreshAnalysis() {
    if (!this.state.initialized) return;
    
    // 可以在这里添加分析数据更新逻辑
    Utils.log('debug', 'Analysis refreshed');
  },

  /**
   * 刷新CVE浏览器
   */
  refreshCveBrowser() {
    if (!this.state.initialized) return;
    
    // 应用筛选器
    Filters.applyFilters();
    Utils.log('debug', 'CVE browser refreshed');
  },

  /**
   * 刷新分类分析
   */
  refreshCategories() {
    if (!this.state.initialized) return;
    
    // 可以在这里添加分类数据更新逻辑
    Utils.log('debug', 'Categories refreshed');
  },

  /**
   * 显示导出对话框
   */
  showExportDialog() {
    // 简单的导出功能
    const formats = ['JSON', 'CSV'];
    const format = prompt(`选择导出格式 (${formats.join('/')}):`);
    
    if (format && formats.includes(format.toUpperCase())) {
      DataLoader.exportData(format.toUpperCase());
    }
  },

  /**
   * 绑定全局事件
   */
  bindGlobalEvents() {
    // 窗口大小改变
    window.addEventListener('resize', Utils.debounce(() => {
      this.handleResize();
    }, 250));

    // 错误处理
    window.addEventListener('error', (e) => {
      Utils.log('error', 'Uncaught error', e.error);
    });

    // 未处理的Promise拒绝
    window.addEventListener('unhandledrejection', (e) => {
      Utils.log('error', 'Unhandled promise rejection', e.reason);
    });

    // 页面可见性变化
    document.addEventListener('visibilitychange', () => {
      if (!document.hidden) {
        this.onPageVisible();
      }
    });
  },

  /**
   * 处理窗口大小改变
   */
  handleResize() {
    // 重新渲染图表以适应新尺寸
    Object.values(Charts.instances).forEach(chart => {
      if (chart && chart.resize) {
        chart.resize();
      }
    });
  },

  /**
   * 页面重新可见时的处理
   */
  onPageVisible() {
    // 可以在这里添加数据刷新逻辑
    Utils.log('debug', 'Page became visible');
  },

  /**
   * 更新URL
   */
  updateUrl() {
    const params = new URLSearchParams(window.location.search);
    
    if (this.state.currentSection !== 'dashboard') {
      params.set('section', this.state.currentSection);
    } else {
      params.delete('section');
    }

    const url = new URL(window.location);
    url.search = params.toString();
    window.history.replaceState({}, '', url);
  },

  /**
   * 从URL恢复状态
   */
  restoreFromUrl() {
    const params = new URLSearchParams(window.location.search);
    
    // 恢复章节
    const section = params.get('section');
    if (section && document.getElementById(section)) {
      this.switchSection(section);
    }

    // CVE详情
    CveDetails.showFromUrlParams();
  },

  /**
   * 显示错误页面
   */
  showErrorPage(message) {
    const mainContent = document.querySelector('.main-content');
    if (mainContent) {
      mainContent.innerHTML = `
        <div class="error-page">
          <div class="error-content">
            <i class="fas fa-exclamation-triangle"></i>
            <h1>应用程序初始化失败</h1>
            <p>${message}</p>
            <button class="retry-btn" onclick="location.reload()">
              <i class="fas fa-redo"></i>
              重新加载
            </button>
          </div>
        </div>
      `;
    }
  }
};

// 页面加载完成后初始化应用
document.addEventListener('DOMContentLoaded', () => {
  App.init().catch(error => {
    console.error('Failed to initialize app:', error);
  });
});

// 导出应用对象
if (typeof module !== 'undefined' && module.exports) {
  module.exports = App;
}