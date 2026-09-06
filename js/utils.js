// RISC-V CVE Dashboard - 工具函数
const Utils = {
  /**
   * 防抖函数
   * @param {Function} func 要防抖的函数
   * @param {number} wait 等待时间（毫秒）
   * @param {boolean} immediate 是否立即执行
   * @returns {Function} 防抖后的函数
   */
  debounce(func, wait, immediate = false) {
    let timeout;
    return function executedFunction(...args) {
      const later = () => {
        timeout = null;
        if (!immediate) func(...args);
      };
      const callNow = immediate && !timeout;
      clearTimeout(timeout);
      timeout = setTimeout(later, wait);
      if (callNow) func(...args);
    };
  },

  /**
   * 节流函数
   * @param {Function} func 要节流的函数
   * @param {number} limit 时间间隔（毫秒）
   * @returns {Function} 节流后的函数
   */
  throttle(func, limit) {
    let inThrottle;
    return function(...args) {
      if (!inThrottle) {
        func.apply(this, args);
        inThrottle = true;
        setTimeout(() => inThrottle = false, limit);
      }
    };
  },

  /**
   * 格式化日期
   * @param {string|Date} date 日期
   * @param {string} format 格式
   * @returns {string} 格式化后的日期字符串
   */
  formatDate(date, format = CONFIG.DATE_FORMATS.DISPLAY) {
    if (!date) return '-';
    
    const d = new Date(date);
    if (isNaN(d.getTime())) return '-';

    const year = d.getFullYear();
    const month = String(d.getMonth() + 1).padStart(2, '0');
    const day = String(d.getDate()).padStart(2, '0');

    switch (format) {
      case 'YYYY-MM-DD':
        return `${year}-${month}-${day}`;
      case 'MMM YYYY':
        const monthNames = ['1月', '2月', '3月', '4月', '5月', '6月',
                           '7月', '8月', '9月', '10月', '11月', '12月'];
        return `${monthNames[d.getMonth()]} ${year}`;
      case 'YYYY年MM月DD日':
        return `${year}年${month}月${day}日`;
      default:
        return d.toLocaleDateString('zh-CN');
    }
  },

  /**
   * 从CVE ID提取年份
   * @param {string} cveId CVE ID
   * @returns {number} 年份
   */
  extractYearFromCveId(cveId) {
    const match = cveId.match(/CVE-(\d{4})-/);
    return match ? parseInt(match[1]) : new Date().getFullYear();
  },

  /**
   * 生成随机ID
   * @param {number} length ID长度
   * @returns {string} 随机ID
   */
  generateId(length = 8) {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    let result = '';
    for (let i = 0; i < length; i++) {
      result += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return result;
  },

  /**
   * 深拷贝对象
   * @param {any} obj 要拷贝的对象
   * @returns {any} 拷贝后的对象
   */
  deepClone(obj) {
    if (obj === null || typeof obj !== 'object') return obj;
    if (obj instanceof Date) return new Date(obj.getTime());
    if (obj instanceof Array) return obj.map(item => this.deepClone(item));
    if (typeof obj === 'object') {
      const copy = {};
      Object.keys(obj).forEach(key => {
        copy[key] = this.deepClone(obj[key]);
      });
      return copy;
    }
  },

  /**
   * 转义HTML特殊字符
   * @param {string} text 要转义的文本
   * @returns {string} 转义后的文本
   */
  escapeHtml(text) {
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
  },

  /**
   * 高亮搜索关键词
   * @param {string} text 原文本
   * @param {string} query 搜索关键词
   * @returns {string} 高亮后的HTML
   */
  highlightText(text, query) {
    if (!query || !text) return this.escapeHtml(text);
    
    const escapedText = this.escapeHtml(text);
    const escapedQuery = query.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const regex = new RegExp(`(${escapedQuery})`, 'gi');
    
    return escapedText.replace(regex, `<mark class="${CONFIG.SEARCH.HIGHLIGHT_CLASS}">$1</mark>`);
  },

  /**
   * 获取分类显示名称
   * @param {string} category 分类名称
   * @returns {string} 显示名称
   */
  getCategoryDisplayName(category) {
    const mapping = {
      'Linux Kernel': 'Linux内核',
      'RISC-V CPU/SoC': 'CPU/SoC',
      'RISC-V Development Tools': 'RISC-V Development Tools',
      'Device-Specific Firmware & Applications': '固件/应用程序',
      'Simulator': 'Simulator',
      'RISC-V Instruction Set Manual': 'RISC-V Instruction Set Manual',
      'Other': '其他'
    };
    return mapping[category] || category;
  },

  /**
   * 获取分类CSS类名
   * @param {string} category 分类名称
   * @returns {string} CSS类名
   */
  getCategoryCssClass(category) {
    const mapping = {
      'Linux Kernel': 'category-linux-kernel',
      'RISC-V CPU/SoC': 'category-cpu-soc',
      'RISC-V Development Tools': 'category-dev-tools',
      'Device-Specific Firmware & Applications': 'category-firmware',
      'Simulator': 'category-simulator',
      'RISC-V Instruction Set Manual': 'category-manual',
      'Other': 'category-other'
    };
    return mapping[category] || 'category-other';
  },

  /**
   * 获取严重程度CSS类名
   * @param {string} severity 严重程度
   * @returns {string} CSS类名
   */
  getSeverityCssClass(severity) {
    if (!severity) return 'severity-unknown';
    return `severity-${severity.toLowerCase()}`;
  },

  /**
   * 解析严重程度
   * @param {string} assessment 严重程度评估
   * @returns {string} 标准化的严重程度
   */
  parseSeverity(assessment) {
    if (!assessment) return 'Unknown';
    
    const normalized = assessment.toLowerCase();
    if (normalized.includes('critical')) return 'Critical';
    if (normalized.includes('high')) return 'High';
    if (normalized.includes('medium')) return 'Medium';
    if (normalized.includes('low')) return 'Low';
    return 'Unknown';
  },

  /**
   * 数字格式化
   * @param {number} num 数字
   * @param {number} decimals 小数位数
   * @returns {string} 格式化后的数字
   */
  formatNumber(num, decimals = 0) {
    if (isNaN(num)) return '0';
    return Number(num).toLocaleString('zh-CN', {
      minimumFractionDigits: decimals,
      maximumFractionDigits: decimals
    });
  },

  /**
   * 百分比格式化
   * @param {number} value 数值
   * @param {number} total 总数
   * @param {number} decimals 小数位数
   * @returns {string} 百分比字符串
   */
  formatPercentage(value, total, decimals = 1) {
    if (!total || total === 0) return '0%';
    const percentage = (value / total) * 100;
    return `${percentage.toFixed(decimals)}%`;
  },

  /**
   * 截断文本
   * @param {string} text 文本
   * @param {number} maxLength 最大长度
   * @param {string} suffix 后缀
   * @returns {string} 截断后的文本
   */
  truncateText(text, maxLength = 100, suffix = '...') {
    if (!text || text.length <= maxLength) return text;
    return text.slice(0, maxLength - suffix.length) + suffix;
  },

  /**
   * 检查是否为移动设备
   * @returns {boolean} 是否为移动设备
   */
  isMobile() {
    return window.innerWidth <= CONFIG.BREAKPOINTS.MOBILE;
  },

  /**
   * 检查是否为平板设备
   * @returns {boolean} 是否为平板设备
   */
  isTablet() {
    return window.innerWidth <= CONFIG.BREAKPOINTS.TABLET && 
           window.innerWidth > CONFIG.BREAKPOINTS.MOBILE;
  },

  /**
   * 获取设备类型
   * @returns {string} 设备类型
   */
  getDeviceType() {
    const width = window.innerWidth;
    if (width <= CONFIG.BREAKPOINTS.MOBILE) return 'mobile';
    if (width <= CONFIG.BREAKPOINTS.TABLET) return 'tablet';
    if (width <= CONFIG.BREAKPOINTS.DESKTOP) return 'desktop';
    return 'large';
  },

  /**
   * 滚动到元素
   * @param {Element|string} element 元素或选择器
   * @param {object} options 选项
   */
  scrollToElement(element, options = {}) {
    const target = typeof element === 'string' ? 
                   document.querySelector(element) : element;
    
    if (!target) return;

    const defaultOptions = {
      behavior: 'smooth',
      block: 'start',
      inline: 'nearest'
    };

    target.scrollIntoView({ ...defaultOptions, ...options });
  },

  /**
   * 显示提示消息
   * @param {string} message 消息内容
   * @param {string} type 消息类型
   * @param {number} duration 显示时长
   */
  showToast(message, type = 'info', duration = 3000) {
    // 创建提示元素
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    // 添加样式
    Object.assign(toast.style, {
      position: 'fixed',
      top: '20px',
      right: '20px',
      padding: '12px 20px',
      borderRadius: '8px',
      color: 'white',
      fontWeight: '500',
      zIndex: '9999',
      opacity: '0',
      transform: 'translateY(-20px)',
      transition: 'all 0.3s ease'
    });

    // 设置背景色
    const colors = {
      success: '#10B981',
      error: '#EF4444',
      warning: '#F59E0B',
      info: '#3B82F6'
    };
    toast.style.backgroundColor = colors[type] || colors.info;

    // 添加到页面
    document.body.appendChild(toast);

    // 显示动画
    setTimeout(() => {
      toast.style.opacity = '1';
      toast.style.transform = 'translateY(0)';
    }, 100);

    // 自动隐藏
    setTimeout(() => {
      toast.style.opacity = '0';
      toast.style.transform = 'translateY(-20px)';
      setTimeout(() => {
        if (toast.parentNode) {
          toast.parentNode.removeChild(toast);
        }
      }, 300);
    }, duration);
  },

  /**
   * 从文本中提取关键词（仅英文技术术语）
   * @param {string} text 文本
   * @param {number} maxWords 最大词数
   * @returns {Array} 关键词数组
   */
  extractKeywords(text, maxWords = 50) {
    if (!text) {
      console.log('[extractKeywords] No text provided');
      return [];
    }

    console.log('[extractKeywords] Text length:', text.length);

    // 扩展的英文停用词列表
    const stopWords = new Set([
      'the', 'a', 'an', 'and', 'or', 'but', 'in', 'on', 'at', 'to', 'for', 'of',
      'with', 'by', 'from', 'up', 'about', 'into', 'through', 'during', 'before',
      'after', 'above', 'below', 'between', 'among', 'since', 'without', 'under',
      'as', 'be', 'are', 'was', 'were', 'been', 'being', 'have', 'has', 'had',
      'do', 'does', 'did', 'will', 'would', 'should', 'could', 'may', 'might',
      'can', 'this', 'that', 'these', 'those', 'is', 'it', 'its', 'if', 'when',
      'where', 'which', 'who', 'what', 'how', 'there', 'their', 'they', 'them',
      'his', 'her', 'him', 'she', 'he', 'we', 'us', 'our', 'you', 'your', 'via',
      'all', 'any', 'both', 'each', 'few', 'more', 'most', 'other', 'some', 'such',
      'no', 'nor', 'not', 'only', 'own', 'same', 'so', 'than', 'too', 'very',
      'just', 'now', 'then', 'here', 'out', 'down', 'also', 'back', 'even',
      'still', 'way', 'well', 'get', 'make', 'go', 'see', 'know', 'take', 'use'
    ]);

    // 只提取英文单词
    const words = text
      .toLowerCase()
      .replace(/[^a-z0-9\s_]/g, ' ')  // 只保留英文字母、数字和下划线
      .split(/\s+/)
      .filter(word => {
        // 必须是纯英文（可以包含数字和下划线）
        if (!/^[a-z][a-z0-9_]*$/.test(word)) return false;
        // 长度限制：3-20个字符
        if (word.length < 3 || word.length > 20) return false;
        // 如果是纯数字，过滤掉
        if (/^\d+$/.test(word)) return false;
        // 停用词过滤
        if (stopWords.has(word)) return false;
        // 过滤包含过多数字的词
        const digitCount = (word.match(/\d/g) || []).length;
        if (digitCount > word.length * 0.5) return false;
        return true;
      });

    console.log('[extractKeywords] Filtered English words count:', words.length);

    // 统计词频
    const wordCount = {};
    words.forEach(word => {
      wordCount[word] = (wordCount[word] || 0) + 1;
    });

    // 技术术语权重提升
    const technicalTerms = new Set([
      'risc', 'riscv', 'linux', 'kernel', 'commit', 'cve', 'memory', 'access',
      'supervisor', 'user', 'mode', 'kvm', 'pmu', 'zkvm', 'boom', 'cpu', 'soc',
      'register', 'instruction', 'exception', 'interrupt', 'paging', 'tlb',
      'privilege', 'escalation', 'vulnerability', 'overflow', 'buffer', 'stack',
      'heap', 'pointer', 'null', 'dereference', 'corruption', 'leak', 'denial',
      'execution', 'remote', 'local', 'arbitrary', 'code', 'crash', 'panic',
      'fault', 'page', 'table', 'virtual', 'physical', 'address', 'control',
      'status', 'debug', 'performance', 'counter', 'timer', 'vector', 'trap',
      'handler', 'firmware', 'driver', 'module', 'syscall', 'function', 'context'
    ]);

    // 排序并返回
    const keywords = Object.entries(wordCount)
      .sort(([wordA, countA], [wordB, countB]) => {
        // 技术术语优先，并提升权重
        const isATech = technicalTerms.has(wordA.toLowerCase());
        const isBTech = technicalTerms.has(wordB.toLowerCase());
        if (isATech && !isBTech) return -1;
        if (!isATech && isBTech) return 1;
        // 按频率排序
        const weightA = isATech ? countA * 1.5 : countA;
        const weightB = isBTech ? countB * 1.5 : countB;
        return weightB - weightA;
      })
      .slice(0, maxWords)
      .map(([word, count]) => ({ word, count }));

    console.log('[extractKeywords] Top 10 English keywords:', keywords.slice(0, 10));
    return keywords;
  },

  /**
   * 检查对象是否为空
   * @param {object} obj 要检查的对象
   * @returns {boolean} 是否为空
   */
  isEmpty(obj) {
    if (obj === null || obj === undefined) return true;
    if (Array.isArray(obj)) return obj.length === 0;
    if (typeof obj === 'object') return Object.keys(obj).length === 0;
    if (typeof obj === 'string') return obj.trim().length === 0;
    return false;
  },

  /**
   * 获取URL参数
   * @param {string} name 参数名
   * @returns {string|null} 参数值
   */
  getUrlParameter(name) {
    const urlParams = new URLSearchParams(window.location.search);
    return urlParams.get(name);
  },

  /**
   * 设置URL参数
   * @param {string} name 参数名
   * @param {string} value 参数值
   */
  setUrlParameter(name, value) {
    const url = new URL(window.location);
    if (value) {
      url.searchParams.set(name, value);
    } else {
      url.searchParams.delete(name);
    }
    window.history.replaceState({}, '', url);
  },

  /**
   * 日志输出
   * @param {string} level 日志级别
   * @param {string} message 消息
   * @param {any} data 附加数据
   */
  log(level, message, data = null) {
    if (!CONFIG.DEBUG.ENABLED) return;

    const levels = ['error', 'warn', 'info', 'debug'];
    const configLevel = CONFIG.DEBUG.LOG_LEVEL;
    const currentLevelIndex = levels.indexOf(level);
    const configLevelIndex = levels.indexOf(configLevel);

    if (currentLevelIndex > configLevelIndex) return;

    const timestamp = new Date().toISOString();
    const prefix = `[${timestamp}] [${level.toUpperCase()}]`;

    switch (level) {
      case 'error':
        console.error(prefix, message, data);
        break;
      case 'warn':
        console.warn(prefix, message, data);
        break;
      case 'info':
        console.info(prefix, message, data);
        break;
      case 'debug':
        console.debug(prefix, message, data);
        break;
      default:
        console.log(prefix, message, data);
    }
  }
};

// 添加性能监控
if (CONFIG.DEBUG.SHOW_PERFORMANCE) {
  Utils.performance = {
    timers: {},
    
    start(name) {
      this.timers[name] = performance.now();
    },
    
    end(name) {
      if (this.timers[name]) {
        const duration = performance.now() - this.timers[name];
        Utils.log('debug', `Performance: ${name}`, `${duration.toFixed(2)}ms`);
        delete this.timers[name];
      }
    }
  };
}

// 导出工具函数
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Utils;
}