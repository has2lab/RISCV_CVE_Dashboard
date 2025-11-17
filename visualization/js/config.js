// RISC-V CVE Dashboard - 配置文件
const CONFIG = {
  // 数据文件路径
  DATA_SOURCES: {
    SUMMARY: '../riscv_cves_classified_summary.json',
    DETAILED: '../riscv_cves_classified.json'
  },

  // 分类配置
  CATEGORIES: {
    'Linux Kernel': {
      color: '#3B82F6',
      icon: 'fab fa-linux',
      description: 'Linux内核相关漏洞'
    },
    'RISC-V CPU/SoC': {
      color: '#F59E0B',
      icon: 'fas fa-microchip',
      description: 'RISC-V处理器和SoC硬件漏洞'
    },
    'RISC-V Development Tools': {
      color: '#10B981',
      icon: 'fas fa-tools',
      description: '开发工具链相关漏洞'
    },
    'Device-Specific Firmware & Applications': {
      color: '#8B5CF6',
      icon: 'fas fa-cogs',
      description: '固件或应用程序漏洞'
    },
    'Simulator': {
      color: '#EF4444',
      icon: 'fas fa-desktop',
      description: 'RISC-V模拟器相关漏洞'
    },
    'RISC-V Instruction Set Manual': {
      color: '#F59E0B',
      icon: 'fas fa-book',
      description: 'RISC-V指令集规范相关问题'
    },
    'Other': {
      color: '#6B7280',
      icon: 'fas fa-question-circle',
      description: '其他类型漏洞'
    }
  },

  // 严重程度配置
  SEVERITY_LEVELS: {
    'Critical': {
      color: '#DC2626',
      priority: 1,
      label: '严重',
      icon: 'fa-exclamation-circle'
    },
    'High': {
      color: '#EA580C', 
      priority: 2,
      label: '高危',
      icon: 'fa-exclamation-triangle'
    },
    'Medium': {
      color: '#D97706',
      priority: 3,
      label: '中等',
      icon: 'fa-exclamation'
    },
    'Low': {
      color: '#16A34A',
      priority: 4,
      label: '低危',
      icon: 'fa-info-circle'
    },
    'Unknown': {
      color: '#6B7280',
      priority: 5,
      label: '未知',
      icon: 'fa-question-circle'
    }
  },

  // 图表配置
  CHART_CONFIG: {
    COLORS: [
      '#3B82F6', // 蓝色 - Linux Kernel
      '#F59E0B', // 橙色 - CPU/SoC  
      '#10B981', // 绿色 - Dev Tools
      '#8B5CF6', // 紫色 - Firmware
      '#EF4444', // 红色 - Simulator
      '#F59E0B', // 黄色 - Manual
      '#6B7280'  // 灰色 - Other
    ],
    ANIMATION: {
      duration: 1000,
      easing: 'easeInOutQuart'
    },
    RESPONSIVE: true,
    MAINTAIN_ASPECT_RATIO: false
  },

  // 分页配置
  PAGINATION: {
    ITEMS_PER_PAGE: 20,
    MAX_VISIBLE_PAGES: 5
  },

  // 搜索配置
  SEARCH: {
    MIN_QUERY_LENGTH: 2,
    DEBOUNCE_DELAY: 300,
    HIGHLIGHT_CLASS: 'search-highlight'
  },

  // 缓存配置
  CACHE: {
    ENABLE: true,
    TTL: 3600000, // 1小时
    KEY_PREFIX: 'riscv_cve_'
  },

  // 导出配置
  EXPORT: {
    FORMATS: ['JSON', 'CSV', 'PDF'],
    FILENAME_PREFIX: 'riscv_cve_data_'
  },

  // 主题配置
  THEMES: {
    LIGHT: 'light',
    DARK: 'dark',
    AUTO: 'auto'
  },

  // API端点（如果需要）
  API: {
    BASE_URL: '',
    ENDPOINTS: {
      CVE_LIST: '/api/cves',
      CVE_DETAIL: '/api/cves/{id}',
      STATISTICS: '/api/statistics'
    }
  },

  // 时间格式配置
  DATE_FORMATS: {
    DISPLAY: 'YYYY-MM-DD',
    CHART: 'MMM YYYY',
    TOOLTIP: 'YYYY年MM月DD日'
  },

  // 动画配置
  ANIMATIONS: {
    FADE_DURATION: 300,
    SLIDE_DURATION: 250,
    CHART_ANIMATION: 1000
  },

  // 响应式断点
  BREAKPOINTS: {
    MOBILE: 480,
    TABLET: 768,
    DESKTOP: 1024,
    LARGE: 1200
  },

  // 词云配置
  WORDCLOUD: {
    MAX_WORDS: 100,
    MIN_FONT_SIZE: 12,
    MAX_FONT_SIZE: 48,
    COLORS: ['#3B82F6', '#10B981', '#F59E0B', '#EF4444', '#8B5CF6']
  },

  // 错误消息
  ERROR_MESSAGES: {
    DATA_LOAD_ERROR: '数据加载失败，请刷新页面重试',
    NETWORK_ERROR: '网络连接错误，请检查网络设置',
    PARSE_ERROR: '数据解析失败，请联系管理员',
    NOT_FOUND: '未找到相关数据',
    GENERAL_ERROR: '发生未知错误，请稍后重试'
  },

  // 成功消息
  SUCCESS_MESSAGES: {
    DATA_LOADED: '数据加载成功',
    EXPORT_SUCCESS: '导出成功',
    FILTER_APPLIED: '筛选条件已应用',
    SEARCH_COMPLETE: '搜索完成'
  },

  // 默认设置
  DEFAULTS: {
    THEME: 'light',
    CHART_TYPE: 'pie',
    SORT_ORDER: 'desc',
    SORT_FIELD: 'cve_id',
    ITEMS_PER_PAGE: 20
  },

  // 本地存储键名
  STORAGE_KEYS: {
    THEME: 'riscv_cve_theme',
    FILTERS: 'riscv_cve_filters',
    PREFERENCES: 'riscv_cve_preferences',
    CACHE: 'riscv_cve_cache'
  },

  // 调试配置
  DEBUG: {
    ENABLED: false, // 生产环境设为 false
    LOG_LEVEL: 'info', // error, warn, info, debug
    SHOW_PERFORMANCE: false
  }
};

// 导出配置（如果在模块环境中）
if (typeof module !== 'undefined' && module.exports) {
  module.exports = CONFIG;
}

// 冻结配置对象，防止意外修改
Object.freeze(CONFIG);