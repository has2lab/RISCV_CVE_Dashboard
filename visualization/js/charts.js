// RISC-V CVE Dashboard - 图表组件
const Charts = {
  // 图表实例缓存
  instances: {},

  /**
   * 初始化所有图表
   */
  init() {
    Utils.log('info', 'Charts initializing...');
    
    // 设置Chart.js全局配置
    Chart.defaults.font.family = CONFIG.CHART_CONFIG.FONT_FAMILY || '-apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif';
    Chart.defaults.font.size = 12;
    Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue('--text-secondary').trim();
    Chart.defaults.responsive = CONFIG.CHART_CONFIG.RESPONSIVE;
    Chart.defaults.maintainAspectRatio = CONFIG.CHART_CONFIG.MAINTAIN_ASPECT_RATIO;
    
    // 监听主题变化
    this.setupThemeListener();
  },

  /**
   * 创建分类分布饼图
   */
  createCategoryChart(containerId, data, type = 'pie') {
    const ctx = document.getElementById(containerId);
    if (!ctx) {
      Utils.log('error', `Chart container not found: ${containerId}`);
      return null;
    }

    // 如果图表已存在，先销毁
    if (this.instances[containerId]) {
      this.instances[containerId].destroy();
    }

    const chartData = {
      labels: data.map(item => Utils.getCategoryDisplayName(item.category)),
      datasets: [{
        data: data.map(item => item.count),
        backgroundColor: data.map(item => item.color),
        borderColor: data.map(item => item.color),
        borderWidth: 2,
        hoverBorderWidth: 3,
        hoverOffset: 10
      }]
    };

    const options = {
      plugins: {
        legend: {
          display: false // 使用自定义图例
        },
        tooltip: {
          callbacks: {
            label: (context) => {
              const label = context.label;
              const value = context.parsed;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = ((value / total) * 100).toFixed(1);
              return `${label}: ${value} (${percentage}%)`;
            }
          }
        }
      },
      animation: {
        duration: CONFIG.CHART_CONFIG.ANIMATION.duration,
        easing: CONFIG.CHART_CONFIG.ANIMATION.easing
      },
      onHover: (event, elements) => {
        event.native.target.style.cursor = elements.length > 0 ? 'pointer' : 'default';
      },
      onClick: (event, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          const category = data[index].category;
          this.onCategoryClick(category);
        }
      }
    };

    const chart = new Chart(ctx, {
      type: type,
      data: chartData,
      options: options
    });

    this.instances[containerId] = chart;
    
    // 创建自定义图例
    this.createCustomLegend(containerId + 'Legend', data);
    
    return chart;
  },

  /**
   * 创建年度趋势图
   */
  createTrendChart(containerId, data, stacked = false) {
    const ctx = document.getElementById(containerId);
    if (!ctx) {
      Utils.log('error', `Chart container not found: ${containerId}`);
      return null;
    }

    // 如果图表已存在，先销毁
    if (this.instances[containerId]) {
      this.instances[containerId].destroy();
    }

    const labels = data.map(item => item.year);
    const datasets = [];

    if (stacked) {
      // 分类堆叠柱状图
      const categories = [...new Set(
        data.flatMap(item => Object.keys(item.byCategory))
      )];

      categories.forEach((category, index) => {
        const categoryData = data.map(item => item.byCategory[category] || 0);
        datasets.push({
          label: Utils.getCategoryDisplayName(category),
          data: categoryData,
          backgroundColor: CONFIG.CATEGORIES[category]?.color || CONFIG.CHART_CONFIG.COLORS[index % CONFIG.CHART_CONFIG.COLORS.length],
          borderColor: CONFIG.CATEGORIES[category]?.color || CONFIG.CHART_CONFIG.COLORS[index % CONFIG.CHART_CONFIG.COLORS.length],
          borderWidth: 1
        });
      });
    } else {
      // 总计柱状图
      datasets.push({
        label: 'CVE 数量',
        data: data.map(item => item.total),
        backgroundColor: CONFIG.CHART_CONFIG.COLORS[0],
        borderColor: CONFIG.CHART_CONFIG.COLORS[0],
        borderWidth: 2,
        borderRadius: 4,
        borderSkipped: false
      });
    }

    const options = {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          title: {
            display: true,
            text: '年份'
          },
          grid: {
            display: false
          }
        },
        y: {
          title: {
            display: true,
            text: 'CVE 数量'
          },
          beginAtZero: true,
          ticks: {
            stepSize: 1
          }
        }
      },
      plugins: {
        legend: {
          display: stacked,
          position: 'top'
        },
        tooltip: {
          mode: 'index',
          intersect: false,
          callbacks: {
            title: (items) => `${items[0].label}年`,
            label: (context) => {
              if (stacked) {
                return `${context.dataset.label}: ${context.parsed.y}`;
              } else {
                return `CVE 数量: ${context.parsed.y}`;
              }
            },
            footer: (items) => {
              if (!stacked) return '';
              const total = items.reduce((sum, item) => sum + item.parsed.y, 0);
              return `总计: ${total}`;
            }
          }
        }
      },
      animation: {
        duration: CONFIG.CHART_CONFIG.ANIMATION.duration,
        easing: CONFIG.CHART_CONFIG.ANIMATION.easing
      },
      onClick: (event, elements) => {
        if (elements.length > 0) {
          const index = elements[0].index;
          const year = data[index].year;
          this.onYearClick(year);
        }
      }
    };

    const chart = new Chart(ctx, {
      type: 'bar',
      data: { labels, datasets },
      options: options
    });

    this.instances[containerId] = chart;
    return chart;
  },

  /**
   * 创建严重程度分布图
   */
  createSeverityChart(containerId, data) {
    const ctx = document.getElementById(containerId);
    if (!ctx) {
      Utils.log('error', `Chart container not found: ${containerId}`);
      return null;
    }

    // 如果图表已存在，先销毁
    if (this.instances[containerId]) {
      this.instances[containerId].destroy();
    }

    const chartData = {
      labels: data.map(item => CONFIG.SEVERITY_LEVELS[item.severity]?.label || item.severity),
      datasets: [{
        data: data.map(item => item.count),
        backgroundColor: data.map(item => item.color),
        borderColor: data.map(item => item.color),
        borderWidth: 2
      }]
    };

    const options = {
      plugins: {
        legend: {
          position: 'bottom'
        },
        tooltip: {
          callbacks: {
            label: (context) => {
              const label = context.label;
              const value = context.parsed;
              const total = context.dataset.data.reduce((a, b) => a + b, 0);
              const percentage = ((value / total) * 100).toFixed(1);
              return `${label}: ${value} (${percentage}%)`;
            }
          }
        }
      },
      animation: {
        duration: CONFIG.CHART_CONFIG.ANIMATION.duration
      }
    };

    const chart = new Chart(ctx, {
      type: 'doughnut',
      data: chartData,
      options: options
    });

    this.instances[containerId] = chart;
    return chart;
  },

  /**
   * 创建时间线图
   */
  createTimelineChart(containerId, data, period = 'year') {
    const ctx = document.getElementById(containerId);
    if (!ctx) {
      Utils.log('error', `Chart container not found: ${containerId}`);
      return null;
    }

    // 如果图表已存在，先销毁
    if (this.instances[containerId]) {
      this.instances[containerId].destroy();
      delete this.instances[containerId];
    }

    // 检查数据
    if (!data || data.length === 0) {
      Utils.log('warn', 'No data provided for timeline chart');
      return null;
    }

    // 根据period聚合数据
    const aggregatedData = this.aggregateTimelineDataByPeriod(data, period);
    
    if (aggregatedData.length === 0) {
      Utils.log('warn', 'No aggregated data for timeline chart');
      return null;
    }

    Utils.log('info', `Timeline data aggregated by ${period}: ${aggregatedData.length} points`);

    const chartData = {
      labels: aggregatedData.map(item => item.label),
      datasets: [{
        label: 'CVE 发现数量',
        data: aggregatedData.map(item => item.count),
        borderColor: CONFIG.CHART_CONFIG.COLORS[0],
        backgroundColor: CONFIG.CHART_CONFIG.COLORS[0] + '30',
        borderWidth: 3,
        pointRadius: period === 'month' ? 3 : 6,
        pointHoverRadius: period === 'month' ? 5 : 8,
        pointBorderColor: '#fff',
        pointBackgroundColor: CONFIG.CHART_CONFIG.COLORS[0],
        pointBorderWidth: 2,
        tension: 0.4,
        fill: true
      }]
    };

    const periodLabels = {
      'year': '年份',
      'quarter': '季度',
      'month': '月份'
    };

    const options = {
      responsive: true,
      maintainAspectRatio: false,
      scales: {
        x: {
          title: {
            display: true,
            text: periodLabels[period] || '时间',
            font: {
              size: 14,
              weight: 'bold'
            }
          },
          grid: {
            display: true,
            color: 'rgba(0, 0, 0, 0.05)'
          },
          ticks: {
            maxRotation: period === 'month' ? 45 : 0,
            minRotation: period === 'month' ? 45 : 0
          }
        },
        y: {
          title: {
            display: true,
            text: 'CVE 数量',
            font: {
              size: 14,
              weight: 'bold'
            }
          },
          beginAtZero: true,
          ticks: {
            stepSize: 1,
            precision: 0
          },
          grid: {
            display: true,
            color: 'rgba(0, 0, 0, 0.05)'
          }
        }
      },
      plugins: {
        legend: {
          display: false
        },
        title: {
          display: true,
          text: `CVE 发现时间线（按${periodLabels[period]}）`,
          font: {
            size: 16,
            weight: 'bold'
          },
          padding: {
            top: 10,
            bottom: 20
          }
        },
        tooltip: {
          callbacks: {
            title: (items) => items[0].label,
            label: (context) => `发现 ${context.parsed.y} 个CVE`
          },
          backgroundColor: 'rgba(0, 0, 0, 0.8)',
          titleFont: {
            size: 14
          },
          bodyFont: {
            size: 13
          },
          padding: 12,
          cornerRadius: 6
        }
      },
      animation: {
        duration: 1000,
        easing: 'easeInOutQuart'
      },
      interaction: {
        intersect: false,
        mode: 'index'
      }
    };

    try {
      const chart = new Chart(ctx, {
        type: 'line',
        data: chartData,
        options: options
      });

      this.instances[containerId] = chart;
      Utils.log('info', `Timeline chart created successfully with ${aggregatedData.length} ${period} periods`);
      return chart;
    } catch (error) {
      Utils.log('error', 'Failed to create timeline chart', error);
      return null;
    }
  },

  /**
   * 根据period聚合时间线数据
   */
  aggregateTimelineDataByPeriod(cves, period) {
    if (!cves || cves.length === 0) {
      Utils.log('warn', 'No CVEs data for timeline aggregation');
      return [];
    }

    const data = {};

    cves.forEach(cve => {
      try {
        const year = Utils.extractYearFromCveId(cve.cve_id);
        if (!year) {
          Utils.log('warn', `Could not extract year from ${cve.cve_id}`);
          return;
        }

        let key, label;
        
        switch (period) {
          case 'month':
            // 按月聚合 - 简化处理，在1月到12月平均分布
            for (let month = 1; month <= 12; month++) {
              const monthKey = `${year}-${String(month).padStart(2, '0')}`;
              if (!data[monthKey]) {
                data[monthKey] = {
                  key: monthKey,
                  label: `${year}年${month}月`,
                  count: 0
                };
              }
            }
            // 将该年的CVE平均分配到12个月（简化处理）
            const monthKey = `${year}-01`;
            if (data[monthKey]) {
              data[monthKey].count++;
            }
            break;
            
          case 'quarter':
            // 按季度聚合
            for (let quarter = 1; quarter <= 4; quarter++) {
              const quarterKey = `${year}-Q${quarter}`;
              if (!data[quarterKey]) {
                data[quarterKey] = {
                  key: quarterKey,
                  label: `${year}年Q${quarter}`,
                  count: 0
                };
              }
            }
            // 将该年的CVE平均分配到4个季度（简化处理）
            const quarterKey = `${year}-Q1`;
            if (data[quarterKey]) {
              data[quarterKey].count++;
            }
            break;
            
          default: // year
            key = `${year}`;
            if (!data[key]) {
              data[key] = {
                key: key,
                label: `${year}年`,
                count: 0
              };
            }
            data[key].count++;
        }
      } catch (error) {
        Utils.log('warn', `Error processing CVE ${cve.cve_id}`, error);
      }
    });

    // 转换为数组并排序
    const result = Object.values(data)
      .filter(item => item.count > 0)  // 只保留有数据的时间点
      .sort((a, b) => a.key.localeCompare(b.key));

    Utils.log('info', `Aggregated ${period} data: ${result.length} points, total CVEs: ${result.reduce((sum, item) => sum + item.count, 0)}`);
    return result;
  },

  /**
   * 创建自定义图例
   */
  createCustomLegend(containerId, data) {
    const container = document.getElementById(containerId);
    if (!container) return;

    container.innerHTML = '';

    data.forEach(item => {
      const legendItem = document.createElement('div');
      legendItem.className = 'legend-item';
      legendItem.innerHTML = `
        <div class="legend-color" style="background-color: ${item.color}"></div>
        <span>${Utils.getCategoryDisplayName(item.category)} (${item.count})</span>
      `;
      
      legendItem.addEventListener('click', () => {
        this.onCategoryClick(item.category);
      });

      container.appendChild(legendItem);
    });
  },

  /**
   * 创建词云
   */
  createWordCloud(containerId, keywords) {
    const container = document.getElementById(containerId);
    if (!container) {
      Utils.log('warn', `Container not found: ${containerId}`);
      return;
    }

    container.innerHTML = '';

    if (!keywords || keywords.length === 0) {
      container.innerHTML = `
        <div style="padding: 2rem; text-align: center; color: var(--text-tertiary);">
          <i class="fas fa-cloud" style="font-size: 3rem; margin-bottom: 1rem; display: block;"></i>
          <p>暂无关键词数据</p>
        </div>
      `;
      Utils.log('warn', 'No keywords data for word cloud');
      return;
    }

    Utils.log('info', `Creating word cloud with ${keywords.length} keywords`);

    // 计算字体大小
    const maxCount = Math.max(...keywords.map(k => k.count));
    const minCount = Math.min(...keywords.map(k => k.count));
    
    // 创建词云容器
    const wordCloudDiv = document.createElement('div');
    wordCloudDiv.style.cssText = `
      display: flex;
      flex-wrap: wrap;
      justify-content: center;
      align-items: center;
      padding: 1.5rem;
      gap: 0.75rem;
      width: 100%;
      height: 100%;
      box-sizing: border-box;
      overflow: hidden;
    `;
    
    keywords.forEach((keyword, index) => {
      const span = document.createElement('span');
      const fontSize = this.calculateWordSize(keyword.count, minCount, maxCount);
      const color = CONFIG.WORDCLOUD.COLORS[index % CONFIG.WORDCLOUD.COLORS.length];
      
      span.textContent = keyword.word;
      span.title = `${keyword.word}: 出现 ${keyword.count} 次`;
      span.className = 'wordcloud-word';
      span.style.cssText = `
        font-size: ${fontSize}px;
        color: ${color};
        margin: 2px 6px;
        padding: 2px 4px;
        display: inline-block;
        cursor: pointer;
        transition: all 0.2s ease;
        font-weight: ${keyword.count > maxCount * 0.7 ? '600' : '400'};
        opacity: ${0.75 + (keyword.count / maxCount) * 0.25};
        white-space: nowrap;
        user-select: none;
        line-height: 1.2;
      `;
      
      span.addEventListener('mouseenter', () => {
        span.style.transform = 'scale(1.1)';
        span.style.opacity = '1';
        span.style.fontWeight = '600';
        span.style.zIndex = '10';
      });
      
      span.addEventListener('mouseleave', () => {
        span.style.transform = 'scale(1)';
        span.style.opacity = `${0.75 + (keyword.count / maxCount) * 0.25}`;
        span.style.fontWeight = keyword.count > maxCount * 0.7 ? '600' : '400';
        span.style.zIndex = '1';
      });
      
      span.addEventListener('click', () => {
        this.onKeywordClick(keyword.word);
      });

      wordCloudDiv.appendChild(span);
    });

    container.appendChild(wordCloudDiv);
    Utils.log('info', 'Word cloud created successfully');
  },

  /**
   * 计算词云字体大小
   */
  calculateWordSize(count, minCount, maxCount) {
    const minSize = CONFIG.WORDCLOUD.MIN_FONT_SIZE;
    const maxSize = CONFIG.WORDCLOUD.MAX_FONT_SIZE;
    
    if (maxCount === minCount) return minSize;
    
    const ratio = (count - minCount) / (maxCount - minCount);
    return Math.round(minSize + (maxSize - minSize) * ratio);
  },

  /**
   * 更新图表主题
   */
  updateTheme() {
    const textColor = getComputedStyle(document.documentElement)
      .getPropertyValue('--text-secondary').trim();
    
    Chart.defaults.color = textColor;
    
    // 重新渲染所有图表
    Object.values(this.instances).forEach(chart => {
      if (chart && chart.update) {
        chart.update();
      }
    });
  },

  /**
   * 设置主题监听器
   */
  setupThemeListener() {
    const observer = new MutationObserver((mutations) => {
      mutations.forEach((mutation) => {
        if (mutation.type === 'attributes' && 
            mutation.attributeName === 'data-theme') {
          this.updateTheme();
        }
      });
    });

    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme']
    });
  },

  /**
   * 销毁图表
   */
  destroy(containerId) {
    if (this.instances[containerId]) {
      this.instances[containerId].destroy();
      delete this.instances[containerId];
      Utils.log('debug', `Chart destroyed: ${containerId}`);
    }
  },

  /**
   * 销毁所有图表
   */
  destroyAll() {
    Object.keys(this.instances).forEach(id => {
      this.destroy(id);
    });
    Utils.log('info', 'All charts destroyed');
  },

  /**
   * 导出图表
   */
  exportChart(containerId, format = 'png') {
    const chart = this.instances[containerId];
    if (!chart) {
      Utils.showToast('图表不存在', 'error');
      return;
    }

    try {
      const url = chart.toBase64Image();
      const link = document.createElement('a');
      link.download = `chart_${containerId}_${Date.now()}.${format}`;
      link.href = url;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      
      Utils.showToast('图表导出成功', 'success');
    } catch (error) {
      Utils.log('error', 'Failed to export chart', error);
      Utils.showToast('图表导出失败', 'error');
    }
  },

  /**
   * 分类点击事件
   */
  onCategoryClick(category) {
    Utils.log('info', 'Category clicked', category);
    
    // 触发自定义事件
    const event = new CustomEvent('categoryClick', {
      detail: { category }
    });
    document.dispatchEvent(event);
  },

  /**
   * 年份点击事件
   */
  onYearClick(year) {
    Utils.log('info', 'Year clicked', year);
    
    // 触发自定义事件
    const event = new CustomEvent('yearClick', {
      detail: { year }
    });
    document.dispatchEvent(event);
  },

  /**
   * 关键词点击事件
   */
  onKeywordClick(keyword) {
    Utils.log('info', 'Keyword clicked', keyword);
    
    // 触发自定义事件
    const event = new CustomEvent('keywordClick', {
      detail: { keyword }
    });
    document.dispatchEvent(event);
  }
};

// 导出图表组件
if (typeof module !== 'undefined' && module.exports) {
  module.exports = Charts;
}