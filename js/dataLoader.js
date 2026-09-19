// RISC-V CVE Dashboard - 数据加载模块
const DataLoader = {
  // 缓存数据
  cache: {
    summary: null,
    detailed: null,
    lastUpdated: null
  },

  // 加载状态
  loading: {
    summary: false,
    detailed: false
  },

  /**
   * 初始化数据加载
   */
  async init() {
    Utils.log('info', 'DataLoader initializing...');
    
    try {
      // 显示加载状态
      this.showLoading(true);
      
      // 并行加载数据
      const [summaryData, detailedData] = await Promise.all([
        this.loadSummaryData(),
        this.loadDetailedData()
      ]);

      // 缓存数据
      this.cache.summary = summaryData;
      this.cache.detailed = detailedData;
      this.cache.lastUpdated = new Date();

      Utils.log('info', 'Data loaded successfully', {
        summaryCount: summaryData?.classified_cves?.length || 0,
        detailedCount: detailedData?.classified_cves?.length || 0
      });

      // 隐藏加载状态
      this.showLoading(false);

      return {
        summary: summaryData,
        detailed: detailedData
      };

    } catch (error) {
      Utils.log('error', 'Failed to load data', error);
      this.showLoading(false);
      Utils.showToast(CONFIG.ERROR_MESSAGES.DATA_LOAD_ERROR, 'error');
      throw error;
    }
  },

  /**
   * 加载摘要数据
   */
  async loadSummaryData() {
    if (this.loading.summary) {
      Utils.log('warn', 'Summary data already loading');
      return null;
    }

    this.loading.summary = true;

    try {
      // 检查缓存
      const cachedData = this.getCachedData('summary');
      if (cachedData) {
        Utils.log('info', 'Using cached summary data');
        this.loading.summary = false;
        return cachedData;
      }

      Utils.log('info', 'Loading summary data from:', CONFIG.DATA_SOURCES.SUMMARY);
      
      const response = await fetch(CONFIG.DATA_SOURCES.SUMMARY);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      
      // 验证数据结构
      this.validateSummaryData(data);
      
      // 缓存数据
      this.setCachedData('summary', data);
      
      this.loading.summary = false;
      return data;

    } catch (error) {
      this.loading.summary = false;
      Utils.log('error', 'Failed to load summary data', error);
      throw new Error(`加载摘要数据失败: ${error.message}`);
    }
  },

  /**
   * 加载详细数据
   */
  async loadDetailedData() {
    if (this.loading.detailed) {
      Utils.log('warn', 'Detailed data already loading');
      return null;
    }

    this.loading.detailed = true;

    try {
      // 检查缓存
      const cachedData = this.getCachedData('detailed');
      if (cachedData) {
        Utils.log('info', 'Using cached detailed data');
        this.loading.detailed = false;
        return cachedData;
      }

      Utils.log('info', 'Loading detailed data from:', CONFIG.DATA_SOURCES.DETAILED);
      
      const response = await fetch(CONFIG.DATA_SOURCES.DETAILED);
      
      if (!response.ok) {
        throw new Error(`HTTP ${response.status}: ${response.statusText}`);
      }

      const data = await response.json();
      
      // 验证数据结构
      this.validateDetailedData(data);
      
      // 缓存数据
      this.setCachedData('detailed', data);
      
      this.loading.detailed = false;
      return data;

    } catch (error) {
      this.loading.detailed = false;
      Utils.log('error', 'Failed to load detailed data', error);
      throw new Error(`加载详细数据失败: ${error.message}`);
    }
  },

  /**
   * 验证摘要数据结构
   */
  validateSummaryData(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('摘要数据格式无效');
    }

    const required = ['metadata', 'statistics', 'classified_cves'];
    for (const field of required) {
      if (!data[field]) {
        throw new Error(`摘要数据缺少必需字段: ${field}`);
      }
    }

    if (!Array.isArray(data.classified_cves)) {
      throw new Error('classified_cves 必须是数组');
    }

    Utils.log('info', 'Summary data validation passed', {
      totalCves: data.metadata.total_cves,
      categories: data.metadata.categories?.length || 0
    });
  },

  /**
   * 验证详细数据结构
   */
  validateDetailedData(data) {
    if (!data || typeof data !== 'object') {
      throw new Error('详细数据格式无效');
    }

    const required = ['metadata', 'statistics', 'classified_cves'];
    for (const field of required) {
      if (!data[field]) {
        throw new Error(`详细数据缺少必需字段: ${field}`);
      }
    }

    if (!Array.isArray(data.classified_cves)) {
      throw new Error('classified_cves 必须是数组');
    }

    Utils.log('info', 'Detailed data validation passed', {
      totalCves: data.metadata.total_cves,
      successfullyProcessed: data.statistics.successful
    });
  },

  /**
   * 获取缓存数据
   */
  getCachedData(type) {
    if (!CONFIG.CACHE.ENABLE) return null;

    try {
      const key = `${CONFIG.STORAGE_KEYS.CACHE}_${type}`;
      const cached = localStorage.getItem(key);
      
      if (!cached) return null;

      const { data, timestamp } = JSON.parse(cached);
      const now = Date.now();
      
      // 检查是否过期
      if (now - timestamp > CONFIG.CACHE.TTL) {
        localStorage.removeItem(key);
        return null;
      }

      Utils.log('debug', `Cache hit for ${type}`, {
        age: now - timestamp,
        ttl: CONFIG.CACHE.TTL
      });

      return data;

    } catch (error) {
      Utils.log('warn', 'Failed to get cached data', error);
      return null;
    }
  },

  /**
   * 设置缓存数据
   */
  setCachedData(type, data) {
    if (!CONFIG.CACHE.ENABLE) return;

    try {
      const key = `${CONFIG.STORAGE_KEYS.CACHE}_${type}`;
      const cached = {
        data,
        timestamp: Date.now()
      };

      localStorage.setItem(key, JSON.stringify(cached));
      Utils.log('debug', `Data cached for ${type}`);

    } catch (error) {
      Utils.log('warn', 'Failed to cache data', error);
    }
  },

  /**
   * 清除缓存
   */
  clearCache() {
    try {
      const keys = ['summary', 'detailed'];
      keys.forEach(type => {
        const key = `${CONFIG.STORAGE_KEYS.CACHE}_${type}`;
        localStorage.removeItem(key);
      });
      
      this.cache = {
        summary: null,
        detailed: null,
        lastUpdated: null
      };

      Utils.log('info', 'Cache cleared');
      Utils.showToast('缓存已清除', 'success');

    } catch (error) {
      Utils.log('error', 'Failed to clear cache', error);
    }
  },

  /**
   * 显示/隐藏加载状态
   */
  showLoading(show) {
    const overlay = document.getElementById('loadingOverlay');
    if (overlay) {
      overlay.style.display = show ? 'flex' : 'none';
    }
  },

  /**
   * 获取统计数据
   */
  getStatistics() {
    if (!this.cache.summary) return null;

    const data = this.cache.summary;
    const metadata = data.metadata;
    const statistics = data.statistics;

    return {
      totalCves: metadata.total_cves,
      classificationDate: metadata.classification_date,
      modelUsed: metadata.model_used,
      categories: metadata.categories,
      byCategory: statistics.by_category,
      successfullyProcessed: statistics.successful,
      failed: statistics.failed,
      lastUpdated: this.cache.lastUpdated
    };
  },

  /**
   * 获取分类分布数据
   */
  getCategoryDistribution() {
    const stats = this.getStatistics();
    if (!stats) return [];

    return Object.entries(stats.byCategory).map(([category, count]) => ({
      category,
      count,
      percentage: (count / stats.totalCves * 100).toFixed(1),
      color: CONFIG.CATEGORIES[category]?.color || '#6B7280'
    }));
  },

  /**
   * 获取年度分布数据
   */
  getYearlyDistribution() {
    if (!this.cache.summary) return [];

    const cves = this.cache.summary.classified_cves;
    const yearlyData = {};

    cves.forEach(cve => {
      const year = Utils.extractYearFromCveId(cve.cve_id);
      if (!yearlyData[year]) {
        yearlyData[year] = { total: 0, byCategory: {} };
      }
      
      yearlyData[year].total++;
      
      if (!yearlyData[year].byCategory[cve.category]) {
        yearlyData[year].byCategory[cve.category] = 0;
      }
      yearlyData[year].byCategory[cve.category]++;
    });

    return Object.entries(yearlyData)
      .map(([year, data]) => ({
        year: parseInt(year),
        total: data.total,
        byCategory: data.byCategory
      }))
      .sort((a, b) => a.year - b.year);
  },

  /**
   * 获取严重程度分布
   */
  getSeverityDistribution() {
    if (!this.cache.summary) return [];

    const cves = this.cache.summary.classified_cves;
    const severityData = {};

    cves.forEach(cve => {
      const severity = Utils.parseSeverity(cve.severity_assessment);
      if (!severityData[severity]) {
        severityData[severity] = 0;
      }
      severityData[severity]++;
    });

    return Object.entries(severityData)
      .map(([severity, count]) => ({
        severity,
        count,
        percentage: (count / cves.length * 100).toFixed(1),
        color: CONFIG.SEVERITY_LEVELS[severity]?.color || '#6B7280',
        priority: CONFIG.SEVERITY_LEVELS[severity]?.priority || 5
      }))
      .sort((a, b) => a.priority - b.priority);
  },

  /**
   * 搜索CVE
   */
  searchCves(query, filters = {}) {
    if (!this.cache.summary) return [];

    let cves = [...this.cache.summary.classified_cves];

    // 文本搜索
    if (query && query.length >= CONFIG.SEARCH.MIN_QUERY_LENGTH) {
      const normalizedQuery = query.toLowerCase();
      cves = cves.filter(cve => {
        return cve.cve_id.toLowerCase().includes(normalizedQuery) ||
               cve.summary.toLowerCase().includes(normalizedQuery) ||
               cve.key_points.some(point => point.toLowerCase().includes(normalizedQuery)) ||
               cve.technical_details.toLowerCase().includes(normalizedQuery);
      });
    }

    // 分类筛选
    if (filters.category) {
      cves = cves.filter(cve => cve.category === filters.category);
    }

    // 年份筛选
    if (filters.year) {
      cves = cves.filter(cve => {
        const year = Utils.extractYearFromCveId(cve.cve_id);
        return year === parseInt(filters.year);
      });
    }

    // 严重程度筛选
    if (filters.severity) {
      cves = cves.filter(cve => {
        const severity = Utils.parseSeverity(cve.severity_assessment);
        return severity === filters.severity;
      });
    }

    return cves;
  },

  /**
   * 获取CVE详情
   */
  getCveDetails(cveId) {
    if (!this.cache.detailed) return null;

    return this.cache.detailed.classified_cves.find(cve => cve.cve_id === cveId);
  },

  /**
   * 获取相关CVE
   */
  getRelatedCves(cveId, limit = 5) {
    if (!this.cache.summary) return [];

    const currentCve = this.cache.summary.classified_cves.find(cve => cve.cve_id === cveId);
    if (!currentCve) return [];

    // 基于分类和关键词找相关CVE
    const related = this.cache.summary.classified_cves
      .filter(cve => cve.cve_id !== cveId)
      .map(cve => {
        let score = 0;
        
        // 同分类加分
        if (cve.category === currentCve.category) {
          score += 3;
        }
        
        // 相同年份加分
        const currentYear = Utils.extractYearFromCveId(currentCve.cve_id);
        const cveYear = Utils.extractYearFromCveId(cve.cve_id);
        if (Math.abs(currentYear - cveYear) <= 1) {
          score += 2;
        }
        
        // 关键词匹配加分
        const currentKeywords = currentCve.key_points.join(' ').toLowerCase();
        const cveKeywords = cve.key_points.join(' ').toLowerCase();
        const commonWords = currentKeywords.split(' ')
          .filter(word => word.length > 3 && cveKeywords.includes(word));
        score += commonWords.length;

        return { ...cve, score };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, limit);

    return related;
  },

  /**
   * 获取关键词统计
   */
  getKeywordStatistics() {
    if (!this.cache.summary) {
      Utils.log('warn', 'No summary data for keyword statistics');
      return [];
    }

    try {
      const cves = this.cache.summary.classified_cves;
      if (!cves || cves.length === 0) {
        Utils.log('warn', 'No CVEs found for keyword statistics');
        return [];
      }

      // 提取所有文本
      const allText = cves
        .map(cve => {
          const summary = cve.summary || '';
          const keyPoints = (cve.key_points || []).join(' ');
          const technical = cve.technical_details || '';
          return `${summary} ${keyPoints} ${technical}`;
        })
        .join(' ');

      if (!allText.trim()) {
        Utils.log('warn', 'No text content for keyword extraction');
        return [];
      }

      const keywords = Utils.extractKeywords(allText, CONFIG.WORDCLOUD.MAX_WORDS);
      Utils.log('info', `Extracted ${keywords.length} keywords`);
      return keywords;
    } catch (error) {
      Utils.log('error', 'Error extracting keywords', error);
      return [];
    }
  },

  /**
   * 导出数据
   */
  exportData(format, filters = {}) {
    const cves = this.searchCves('', filters);
    const timestamp = Utils.formatDate(new Date(), 'YYYY-MM-DD');
    const filename = `${CONFIG.EXPORT.FILENAME_PREFIX}${timestamp}`;

    switch (format.toUpperCase()) {
      case 'JSON':
        this.exportAsJSON(cves, `${filename}.json`);
        break;
      case 'CSV':
        this.exportAsCSV(cves, `${filename}.csv`);
        break;
      case 'PDF':
        this.exportAsPDF(cves, `${filename}.pdf`);
        break;
      default:
        Utils.showToast('不支持的导出格式', 'error');
    }
  },

  /**
   * 导出为JSON
   */
  exportAsJSON(data, filename) {
    const blob = new Blob([JSON.stringify(data, null, 2)], {
      type: 'application/json'
    });
    this.downloadBlob(blob, filename);
    Utils.showToast('JSON导出成功', 'success');
  },

  /**
   * 导出为CSV
   */
  exportAsCSV(data, filename) {
    const headers = ['CVE ID', '分类', '严重程度', '摘要', '关键点', '分类时间'];
    const rows = data.map(cve => [
      cve.cve_id,
      cve.category,
      cve.severity_assessment,
      `"${cve.summary.replace(/"/g, '""')}"`,
      `"${cve.key_points.join('; ').replace(/"/g, '""')}"`,
      Utils.formatDate(cve.classification_timestamp)
    ]);

    const csvContent = [headers, ...rows]
      .map(row => row.join(','))
      .join('\n');

    const blob = new Blob(['\ufeff' + csvContent], {
      type: 'text/csv;charset=utf-8'
    });
    this.downloadBlob(blob, filename);
    Utils.showToast('CSV导出成功', 'success');
  },

  /**
   * 下载Blob
   */
  downloadBlob(blob, filename) {
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }
};

// 导出数据加载器
if (typeof module !== 'undefined' && module.exports) {
  module.exports = DataLoader;
}