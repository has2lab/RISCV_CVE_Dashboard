// RISC-V CVE Dashboard - 筛选器模块
const Filters = {
  // 当前筛选状态
  currentFilters: {
    query: '',
    category: '',
    year: '',
    severity: ''
  },

  // 搜索防抖计时器
  searchDebounceTimer: null,

  // 分页状态
  pagination: {
    currentPage: 1,
    itemsPerPage: CONFIG.PAGINATION.ITEMS_PER_PAGE,
    totalItems: 0,
    totalPages: 0
  },

  // 排序状态
  sorting: {
    field: CONFIG.DEFAULTS.SORT_FIELD,
    order: CONFIG.DEFAULTS.SORT_ORDER
  },

  /**
   * 初始化筛选器
   */
  init() {
    Utils.log('info', 'Filters initializing...');
    
    // 绑定事件
    this.bindEvents();
    
    // 注意：不在这里初始化筛选选项，而是在数据加载后
    // 通过App调用initFilterOptions
    
    // 从URL恢复筛选状态
    this.restoreFromUrl();
  },

  /**
   * 绑定事件处理器
   */
  bindEvents() {
    // 搜索输入
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
      searchInput.addEventListener('input', (e) => {
        this.handleSearchInput(e.target.value);
      });
    }

    // 清除搜索
    const searchClear = document.getElementById('searchClear');
    if (searchClear) {
      searchClear.addEventListener('click', () => {
        this.clearSearch();
      });
    }

    // 筛选器
    const filterSelects = ['categoryFilter', 'yearFilter', 'severityFilter'];
    filterSelects.forEach(id => {
      const select = document.getElementById(id);
      if (select) {
        select.addEventListener('change', (e) => {
          this.handleFilterChange(id, e.target.value);
        });
      }
    });

    // 重置筛选
    const filterReset = document.getElementById('filterReset');
    if (filterReset) {
      filterReset.addEventListener('click', () => {
        this.resetFilters();
      });
    }

    // 排序
    const sortSelect = document.getElementById('sortSelect');
    if (sortSelect) {
      sortSelect.addEventListener('change', (e) => {
        this.handleSortChange(e.target.value);
      });
    }

    // 自定义事件监听
    this.bindCustomEvents();
  },

  /**
   * 绑定自定义事件
   */
  bindCustomEvents() {
    // 监听分类点击事件
    document.addEventListener('categoryClick', (e) => {
      const category = e.detail.category;
      this.setFilter('category', category);
      this.switchToCveBrowser();
    });

    // 监听年份点击事件
    document.addEventListener('yearClick', (e) => {
      const year = e.detail.year;
      this.setFilter('year', year.toString());
      this.switchToCveBrowser();
    });

    // 监听关键词点击事件
    document.addEventListener('keywordClick', (e) => {
      const keyword = e.detail.keyword;
      this.setFilter('query', keyword);
      this.switchToCveBrowser();
    });
  },

  /**
   * 初始化筛选选项
   */
  initFilterOptions() {
    this.initCategoryOptions();
    this.initYearOptions();
    this.initSeverityOptions();
  },

  /**
   * 初始化分类选项
   */
  initCategoryOptions() {
    const categoryFilter = document.getElementById('categoryFilter');
    if (!categoryFilter) {
      Utils.log('warn', 'Category filter element not found');
      return;
    }

    const stats = DataLoader.getStatistics();
    if (!stats || !stats.byCategory) {
      Utils.log('warn', 'No statistics data available for category filter');
      return;
    }

    // 保存当前选中的值
    const currentValue = categoryFilter.value;

    // 清空现有选项（保留默认选项）
    categoryFilter.innerHTML = '<option value="">所有分类</option>';

    // 添加分类选项
    Object.entries(stats.byCategory)
      .sort(([,a], [,b]) => b - a)  // 按数量排序
      .forEach(([category, count]) => {
        const option = document.createElement('option');
        option.value = category;
        option.textContent = `${Utils.getCategoryDisplayName(category)} (${count})`;
        categoryFilter.appendChild(option);
      });

    // 恢复之前的选中值
    if (currentValue) {
      categoryFilter.value = currentValue;
    }

    Utils.log('info', `Category filter initialized with ${Object.keys(stats.byCategory).length} options`);
  },

  /**
   * 初始化年份选项
   */
  initYearOptions() {
    const yearFilter = document.getElementById('yearFilter');
    if (!yearFilter) {
      Utils.log('warn', 'Year filter element not found');
      return;
    }

    const yearlyData = DataLoader.getYearlyDistribution();
    if (!yearlyData || yearlyData.length === 0) {
      Utils.log('warn', 'No yearly data available for year filter');
      return;
    }

    // 保存当前选中的值
    const currentValue = yearFilter.value;

    // 清空现有选项（保留默认选项）
    yearFilter.innerHTML = '<option value="">所有年份</option>';

    // 添加年份选项（倒序，最新的在前）
    yearlyData
      .sort((a, b) => b.year - a.year)
      .forEach(item => {
        const option = document.createElement('option');
        option.value = item.year;
        option.textContent = `${item.year}年 (${item.total})`;
        yearFilter.appendChild(option);
      });

    // 恢复之前的选中值
    if (currentValue) {
      yearFilter.value = currentValue;
    }

    Utils.log('info', `Year filter initialized with ${yearlyData.length} options`);
  },

  /**
   * 初始化严重程度选项
   */
  initSeverityOptions() {
    const severityFilter = document.getElementById('severityFilter');
    if (!severityFilter) return;

    const severityData = DataLoader.getSeverityDistribution();
    if (!severityData || severityData.length === 0) return;

    // 更新选项文本，添加数量
    const options = severityFilter.querySelectorAll('option[value]:not([value=""])');
    options.forEach(option => {
      const severity = option.value;
      const data = severityData.find(item => item.severity === severity);
      if (data) {
        const label = CONFIG.SEVERITY_LEVELS[severity]?.label || severity;
        option.textContent = `${label} (${data.count})`;
      }
    });
  },

  /**
   * 处理搜索输入
   */
  handleSearchInput(query) {
    // 清除之前的防抖计时器
    if (this.searchDebounceTimer) {
      clearTimeout(this.searchDebounceTimer);
    }

    // 设置新的防抖计时器
    this.searchDebounceTimer = setTimeout(() => {
      this.setFilter('query', query);
    }, CONFIG.SEARCH.DEBOUNCE_DELAY);

    // 显示/隐藏清除按钮
    const searchClear = document.getElementById('searchClear');
    if (searchClear) {
      searchClear.style.display = query ? 'block' : 'none';
    }
  },

  /**
   * 清除搜索
   */
  clearSearch() {
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
      searchInput.value = '';
    }

    const searchClear = document.getElementById('searchClear');
    if (searchClear) {
      searchClear.style.display = 'none';
    }

    this.setFilter('query', '');
  },

  /**
   * 处理筛选器变化
   */
  handleFilterChange(filterId, value) {
    const filterMapping = {
      'categoryFilter': 'category',
      'yearFilter': 'year',
      'severityFilter': 'severity'
    };

    const filterKey = filterMapping[filterId];
    if (filterKey) {
      this.setFilter(filterKey, value);
    }
  },

  /**
   * 处理排序变化
   */
  handleSortChange(value) {
    const [field, order] = value.split('_');
    this.sorting.field = field || this.sorting.field;
    this.sorting.order = order || this.sorting.order;
    
    this.applyFilters();
    this.updateUrl();
  },

  /**
   * 设置筛选器
   */
  setFilter(key, value) {
    if (this.currentFilters[key] !== value) {
      this.currentFilters[key] = value;
      this.pagination.currentPage = 1; // 重置到第一页
      this.applyFilters();
      this.updateUrl();
    }
  },

  /**
   * 重置所有筛选器
   */
  resetFilters() {
    // 重置筛选状态
    this.currentFilters = {
      query: '',
      category: '',
      year: '',
      severity: ''
    };

    this.pagination.currentPage = 1;

    // 重置UI元素
    const searchInput = document.getElementById('searchInput');
    if (searchInput) {
      searchInput.value = '';
    }

    const searchClear = document.getElementById('searchClear');
    if (searchClear) {
      searchClear.style.display = 'none';
    }

    const selects = ['categoryFilter', 'yearFilter', 'severityFilter'];
    selects.forEach(id => {
      const select = document.getElementById(id);
      if (select) {
        select.value = '';
      }
    });

    // 应用筛选
    this.applyFilters();
    this.updateUrl();

    Utils.showToast('筛选条件已重置', 'success');
  },

  /**
   * 应用筛选器
   */
  applyFilters() {
    // 获取筛选后的数据
    const filteredData = DataLoader.searchCves(
      this.currentFilters.query,
      {
        category: this.currentFilters.category,
        year: this.currentFilters.year,
        severity: this.currentFilters.severity
      }
    );

    // 排序数据
    const sortedData = this.sortData(filteredData);

    // 更新分页信息
    this.updatePagination(sortedData.length);

    // 获取当前页数据
    const startIndex = (this.pagination.currentPage - 1) * this.pagination.itemsPerPage;
    const endIndex = startIndex + this.pagination.itemsPerPage;
    const pageData = sortedData.slice(startIndex, endIndex);

    // 渲染结果
    this.renderResults(pageData, sortedData.length);
    this.renderPagination();

    // 更新结果信息
    this.updateResultInfo(sortedData.length);

    Utils.log('debug', 'Filters applied', {
      filters: this.currentFilters,
      totalResults: sortedData.length,
      currentPage: this.pagination.currentPage
    });
  },

  /**
   * 排序数据
   */
  sortData(data) {
    return [...data].sort((a, b) => {
      let aValue, bValue;

      switch (this.sorting.field) {
        case 'cve_id':
          aValue = a.cve_id;
          bValue = b.cve_id;
          break;
        case 'date':
          aValue = Utils.extractYearFromCveId(a.cve_id);
          bValue = Utils.extractYearFromCveId(b.cve_id);
          break;
        case 'category':
          aValue = a.category;
          bValue = b.category;
          break;
        case 'severity':
          const aSeverity = Utils.parseSeverity(a.severity_assessment);
          const bSeverity = Utils.parseSeverity(b.severity_assessment);
          aValue = CONFIG.SEVERITY_LEVELS[aSeverity]?.priority || 5;
          bValue = CONFIG.SEVERITY_LEVELS[bSeverity]?.priority || 5;
          break;
        default:
          return 0;
      }

      let comparison = 0;
      if (aValue < bValue) {
        comparison = -1;
      } else if (aValue > bValue) {
        comparison = 1;
      }

      return this.sorting.order === 'desc' ? -comparison : comparison;
    });
  },

  /**
   * 更新分页信息
   */
  updatePagination(totalItems) {
    this.pagination.totalItems = totalItems;
    this.pagination.totalPages = Math.ceil(totalItems / this.pagination.itemsPerPage);
    
    // 确保当前页不超出范围
    if (this.pagination.currentPage > this.pagination.totalPages) {
      this.pagination.currentPage = Math.max(1, this.pagination.totalPages);
    }
  },

  /**
   * 渲染搜索结果
   */
  renderResults(data, totalCount) {
    const container = document.getElementById('cveList');
    if (!container) return;

    if (data.length === 0) {
      container.innerHTML = this.buildNoResultsHTML();
      return;
    }

    container.innerHTML = data.map(cve => this.buildCveItemHTML(cve)).join('');

    // 绑定点击事件
    this.bindResultEvents(container);
  },

  /**
   * 构建CVE项目HTML
   */
  buildCveItemHTML(cve) {
    const severity = Utils.parseSeverity(cve.severity_assessment);
    const categoryClass = Utils.getCategoryCssClass(cve.category);
    const severityClass = Utils.getSeverityCssClass(severity);

    return `
      <div class="cve-item" data-cve="${cve.cve_id}">
        <div class="cve-id">${cve.cve_id}</div>
        <div class="cve-category ${categoryClass}">
          ${Utils.getCategoryDisplayName(cve.category)}
        </div>
        <div class="cve-summary">
          ${this.highlightSearchTerm(Utils.truncateText(cve.summary, 150))}
        </div>
        <div class="cve-severity ${severityClass}">
          ${CONFIG.SEVERITY_LEVELS[severity]?.label || severity}
        </div>
      </div>
    `;
  },

  /**
   * 构建无结果HTML
   */
  buildNoResultsHTML() {
    return `
      <div class="no-results">
        <div class="no-results-icon">
          <i class="fas fa-search"></i>
        </div>
        <h3>未找到匹配的CVE</h3>
        <p>请尝试调整搜索条件或筛选器</p>
        <button class="clear-filters-btn" onclick="Filters.resetFilters()">
          <i class="fas fa-undo"></i>
          清除所有筛选条件
        </button>
      </div>
    `;
  },

  /**
   * 高亮搜索词
   */
  highlightSearchTerm(text) {
    if (!this.currentFilters.query || this.currentFilters.query.length < CONFIG.SEARCH.MIN_QUERY_LENGTH) {
      return text;
    }

    return Utils.highlightText(text, this.currentFilters.query);
  },

  /**
   * 绑定结果事件
   */
  bindResultEvents(container) {
    const cveItems = container.querySelectorAll('.cve-item');
    cveItems.forEach(item => {
      item.addEventListener('click', (e) => {
        const cveId = e.currentTarget.dataset.cve;
        CveDetails.showDetails(cveId);
      });
    });
  },

  /**
   * 渲染分页
   */
  renderPagination() {
    const container = document.getElementById('pagination');
    if (!container) return;

    if (this.pagination.totalPages <= 1) {
      container.innerHTML = '';
      return;
    }

    container.innerHTML = this.buildPaginationHTML();
    this.bindPaginationEvents(container);
  },

  /**
   * 构建分页HTML
   */
  buildPaginationHTML() {
    const { currentPage, totalPages } = this.pagination;
    const maxVisible = CONFIG.PAGINATION.MAX_VISIBLE_PAGES;
    
    let html = '';

    // 上一页按钮
    html += `
      <button class="pagination-btn" data-page="${currentPage - 1}" 
              ${currentPage <= 1 ? 'disabled' : ''}>
        <i class="fas fa-chevron-left"></i>
        上一页
      </button>
    `;

    // 页码按钮
    const startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
    const endPage = Math.min(totalPages, startPage + maxVisible - 1);

    if (startPage > 1) {
      html += `<button class="pagination-btn" data-page="1">1</button>`;
      if (startPage > 2) {
        html += `<span class="pagination-ellipsis">...</span>`;
      }
    }

    for (let i = startPage; i <= endPage; i++) {
      html += `
        <button class="pagination-btn ${i === currentPage ? 'active' : ''}" 
                data-page="${i}">
          ${i}
        </button>
      `;
    }

    if (endPage < totalPages) {
      if (endPage < totalPages - 1) {
        html += `<span class="pagination-ellipsis">...</span>`;
      }
      html += `<button class="pagination-btn" data-page="${totalPages}">${totalPages}</button>`;
    }

    // 下一页按钮
    html += `
      <button class="pagination-btn" data-page="${currentPage + 1}" 
              ${currentPage >= totalPages ? 'disabled' : ''}>
        下一页
        <i class="fas fa-chevron-right"></i>
      </button>
    `;

    return html;
  },

  /**
   * 绑定分页事件
   */
  bindPaginationEvents(container) {
    const buttons = container.querySelectorAll('.pagination-btn[data-page]');
    buttons.forEach(btn => {
      btn.addEventListener('click', (e) => {
        const page = parseInt(e.currentTarget.dataset.page);
        if (page && page !== this.pagination.currentPage) {
          this.goToPage(page);
        }
      });
    });
  },

  /**
   * 跳转到指定页面
   */
  goToPage(page) {
    if (page < 1 || page > this.pagination.totalPages) return;
    
    this.pagination.currentPage = page;
    this.applyFilters();
    this.updateUrl();

    // 滚动到列表顶部
    const cveList = document.getElementById('cveList');
    if (cveList) {
      Utils.scrollToElement(cveList);
    }
  },

  /**
   * 更新结果信息
   */
  updateResultInfo(totalCount) {
    const resultInfo = document.getElementById('resultCount');
    if (!resultInfo) return;

    const { currentPage, itemsPerPage, totalPages } = this.pagination;
    const startIndex = (currentPage - 1) * itemsPerPage + 1;
    const endIndex = Math.min(currentPage * itemsPerPage, totalCount);

    if (totalCount === 0) {
      resultInfo.textContent = '未找到匹配的CVE';
    } else if (totalPages <= 1) {
      resultInfo.textContent = `共找到 ${totalCount} 个CVE`;
    } else {
      resultInfo.textContent = `显示第 ${startIndex}-${endIndex} 项，共 ${totalCount} 个CVE`;
    }
  },

  /**
   * 切换到CVE浏览器页面
   */
  switchToCveBrowser() {
    // 切换到CVE浏览器标签
    const cveBrowserTab = document.querySelector('.nav-link[data-target="cve-browser"]');
    if (cveBrowserTab) {
      cveBrowserTab.click();
    }
  },

  /**
   * 更新URL参数
   */
  updateUrl() {
    const params = new URLSearchParams();

    // 添加筛选参数
    Object.entries(this.currentFilters).forEach(([key, value]) => {
      if (value) {
        params.set(key, value);
      }
    });

    // 添加分页参数
    if (this.pagination.currentPage > 1) {
      params.set('page', this.pagination.currentPage);
    }

    // 添加排序参数
    if (this.sorting.field !== CONFIG.DEFAULTS.SORT_FIELD || 
        this.sorting.order !== CONFIG.DEFAULTS.SORT_ORDER) {
      params.set('sort', `${this.sorting.field}_${this.sorting.order}`);
    }

    // 更新URL
    const url = new URL(window.location);
    url.search = params.toString();
    window.history.replaceState({}, '', url);
  },

  /**
   * 从URL恢复筛选状态
   */
  restoreFromUrl() {
    const params = new URLSearchParams(window.location.search);

    // 恢复筛选器
    Object.keys(this.currentFilters).forEach(key => {
      const value = params.get(key);
      if (value) {
        this.currentFilters[key] = value;
      }
    });

    // 恢复分页
    const page = params.get('page');
    if (page) {
      this.pagination.currentPage = parseInt(page) || 1;
    }

    // 恢复排序
    const sort = params.get('sort');
    if (sort) {
      const [field, order] = sort.split('_');
      if (field) this.sorting.field = field;
      if (order) this.sorting.order = order;
    }

    // 更新UI
    this.updateUI();
  },

  /**
   * 更新UI状态
   */
  updateUI() {
    // 更新搜索框
    const searchInput = document.getElementById('searchInput');
    if (searchInput && this.currentFilters.query) {
      searchInput.value = this.currentFilters.query;
    }

    // 更新筛选器
    const filterMapping = {
      category: 'categoryFilter',
      year: 'yearFilter',
      severity: 'severityFilter'
    };

    Object.entries(filterMapping).forEach(([key, id]) => {
      const select = document.getElementById(id);
      if (select && this.currentFilters[key]) {
        select.value = this.currentFilters[key];
      }
    });

    // 更新排序
    const sortSelect = document.getElementById('sortSelect');
    if (sortSelect) {
      sortSelect.value = `${this.sorting.field}_${this.sorting.order}`;
    }
  }
};

// 导出筛选器模块
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Filters;
}