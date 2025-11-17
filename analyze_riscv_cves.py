#!/usr/bin/env python3
"""
分析RISC-V CVE数据的统计脚本
"""

import json
from collections import Counter, defaultdict
from pathlib import Path


def analyze_riscv_cves():
    """分析RISC-V CVE数据并生成统计信息"""
    
    # 读取所有CVE数据
    with open('riscv_cves/all_riscv_cves.json', 'r', encoding='utf-8') as f:
        cves = json.load(f)
    
    print("=" * 70)
    print("RISC-V CVE 数据分析报告")
    print("=" * 70)
    print(f"\n总计: {len(cves)} 个RISC-V相关CVE\n")
    
    # 1. 按年份统计
    print("-" * 70)
    print("📅 按年份统计:")
    print("-" * 70)
    years = [cve['cveMetadata']['cveId'].split('-')[1] for cve in cves]
    year_counts = Counter(years)
    for year, count in sorted(year_counts.items()):
        bar = "█" * (count // 2) if count > 1 else "▌"
        print(f"  {year}: {count:3d} 个 {bar}")
    
    # 2. 按状态统计
    print("\n" + "-" * 70)
    print("📊 按状态统计:")
    print("-" * 70)
    states = [cve['cveMetadata'].get('state', 'UNKNOWN') for cve in cves]
    state_counts = Counter(states)
    for state, count in sorted(state_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"  {state}: {count} 个")
    
    # 3. 按严重程度统计（如果有CVSS分数）
    print("\n" + "-" * 70)
    print("⚠️  按严重程度统计:")
    print("-" * 70)
    severity_counts = defaultdict(int)
    cvss_scores = []
    
    for cve in cves:
        containers = cve.get('containers', {})
        cna = containers.get('cna', {})
        metrics = cna.get('metrics', [])
        
        for metric in metrics:
            if 'cvssV3_1' in metric:
                cvss = metric['cvssV3_1']
                severity = cvss.get('baseSeverity', 'UNKNOWN')
                score = cvss.get('baseScore', 0)
                severity_counts[severity] += 1
                cvss_scores.append(score)
    
    if severity_counts:
        severity_order = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN']
        for severity in severity_order:
            if severity in severity_counts:
                print(f"  {severity}: {severity_counts[severity]} 个")
    else:
        print("  (大部分CVE没有CVSS评分信息)")
    
    if cvss_scores:
        print(f"\n  平均CVSS分数: {sum(cvss_scores)/len(cvss_scores):.2f}")
        print(f"  最高CVSS分数: {max(cvss_scores):.1f}")
        print(f"  最低CVSS分数: {min(cvss_scores):.1f}")
    
    # 4. 查找描述中的常见关键词
    print("\n" + "-" * 70)
    print("🔑 描述中的常见关键词:")
    print("-" * 70)
    keywords = []
    for cve in cves:
        containers = cve.get('containers', {})
        cna = containers.get('cna', {})
        descriptions = cna.get('descriptions', [])
        for desc in descriptions:
            value = desc.get('value', '').lower()
            if 'kernel' in value:
                keywords.append('kernel')
            if 'linux' in value:
                keywords.append('linux')
            if 'memory' in value:
                keywords.append('memory')
            if 'overflow' in value:
                keywords.append('overflow')
            if 'vector' in value:
                keywords.append('vector')
            if 'nommu' in value:
                keywords.append('nommu')
            if 'module' in value:
                keywords.append('module')
    
    keyword_counts = Counter(keywords)
    for keyword, count in keyword_counts.most_common(10):
        print(f"  {keyword}: {count} 次")
    
    # 5. 最近的CVE
    print("\n" + "-" * 70)
    print("🆕 最新的5个RISC-V CVE:")
    print("-" * 70)
    
    # 按CVE ID排序（较新的在前）
    sorted_cves = sorted(cves, key=lambda x: x['cveMetadata']['cveId'], reverse=True)
    
    for cve in sorted_cves[:5]:
        cve_id = cve['cveMetadata']['cveId']
        state = cve['cveMetadata'].get('state', 'UNKNOWN')
        
        # 获取简短描述
        containers = cve.get('containers', {})
        cna = containers.get('cna', {})
        descriptions = cna.get('descriptions', [])
        desc = "无描述"
        if descriptions:
            desc = descriptions[0].get('value', '无描述')
            # 只取第一行
            desc = desc.split('\n')[0]
            if len(desc) > 80:
                desc = desc[:80] + "..."
        
        print(f"\n  {cve_id} [{state}]")
        print(f"    {desc}")
    
    # 6. 保存统计结果到文件
    stats = {
        "total_cves": len(cves),
        "by_year": dict(year_counts),
        "by_state": dict(state_counts),
        "by_severity": dict(severity_counts),
        "common_keywords": dict(keyword_counts.most_common(10)),
        "cvss_stats": {
            "average": sum(cvss_scores)/len(cvss_scores) if cvss_scores else None,
            "max": max(cvss_scores) if cvss_scores else None,
            "min": min(cvss_scores) if cvss_scores else None,
            "count": len(cvss_scores)
        }
    }
    
    with open('riscv_cves/statistics.json', 'w', encoding='utf-8') as f:
        json.dump(stats, f, indent=4, ensure_ascii=False)
    
    print("\n" + "=" * 70)
    print("统计数据已保存到: riscv_cves/statistics.json")
    print("=" * 70)


if __name__ == "__main__":
    analyze_riscv_cves()
