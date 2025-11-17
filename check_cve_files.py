#!/usr/bin/env python3
"""
CVE文件检查脚本
检查vuldb_riscv_list文件中的CVE编号是否在riscv_cves目录下都有对应的JSON文件
"""

import os
import sys
from pathlib import Path


def read_cve_list(file_path):
    """读取CVE列表文件"""
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            cve_ids = [line.strip() for line in f if line.strip()]
        return cve_ids
    except FileNotFoundError:
        print(f"错误: 找不到文件 {file_path}")
        return None
    except Exception as e:
        print(f"错误: 读取文件 {file_path} 时发生异常: {e}")
        return None


def get_existing_cve_files(directory):
    """获取riscv_cves目录下所有CVE JSON文件"""
    try:
        cve_dir = Path(directory)
        if not cve_dir.exists():
            print(f"错误: 目录 {directory} 不存在")
            return None
        
        # 获取所有以CVE开头、以.json结尾的文件
        cve_files = []
        for file_path in cve_dir.glob("CVE-*.json"):
            # 从文件名中提取CVE编号（去掉.json后缀）
            cve_id = file_path.stem
            cve_files.append(cve_id)
        
        return set(cve_files)
    except Exception as e:
        print(f"错误: 扫描目录 {directory} 时发生异常: {e}")
        return None


def check_cve_coverage(cve_list, existing_files):
    """检查CVE覆盖情况"""
    missing_files = []
    found_files = []
    
    for cve_id in cve_list:
        if cve_id in existing_files:
            found_files.append(cve_id)
        else:
            missing_files.append(cve_id)
    
    return found_files, missing_files


def main():
    # 设置文件路径
    script_dir = Path(__file__).parent
    vuldb_file = script_dir / "vuldb_riscv_list"
    riscv_cves_dir = script_dir / "riscv_cves"
    
    print("=== CVE文件检查工具 ===")
    print(f"检查文件: {vuldb_file}")
    print(f"目标目录: {riscv_cves_dir}")
    print("-" * 50)
    
    # 读取CVE列表
    cve_list = read_cve_list(vuldb_file)
    if cve_list is None:
        sys.exit(1)
    
    print(f"从vuldb_riscv_list读取到 {len(cve_list)} 个CVE编号")
    
    # 获取现有的CVE文件
    existing_files = get_existing_cve_files(riscv_cves_dir)
    if existing_files is None:
        sys.exit(1)
    
    print(f"在riscv_cves目录下找到 {len(existing_files)} 个CVE JSON文件")
    print("-" * 50)
    
    # 检查覆盖情况
    found_files, missing_files = check_cve_coverage(cve_list, existing_files)
    
    # 输出结果
    print(f"✅ 找到对应文件的CVE: {len(found_files)} 个")
    if found_files:
        print("已找到的CVE:")
        for cve in sorted(found_files):
            print(f"  - {cve}")
    
    print()
    print(f"❌ 缺失文件的CVE: {len(missing_files)} 个")
    if missing_files:
        print("缺失的CVE:")
        for cve in sorted(missing_files):
            print(f"  - {cve}")
    
    print("-" * 50)
    
    # 统计信息
    total_cves = len(cve_list)
    coverage_rate = (len(found_files) / total_cves * 100) if total_cves > 0 else 0
    
    print(f"📊 统计信息:")
    print(f"  总CVE数量: {total_cves}")
    print(f"  已找到文件: {len(found_files)}")
    print(f"  缺失文件: {len(missing_files)}")
    print(f"  覆盖率: {coverage_rate:.1f}%")
    
    # 检查是否有多余的文件（在riscv_cves中但不在vuldb_riscv_list中）
    extra_files = existing_files - set(cve_list)
    if extra_files:
        print()
        print(f"📁 额外文件 (在riscv_cves中但不在vuldb_riscv_list中): {len(extra_files)} 个")
        for cve in sorted(extra_files):
            print(f"  + {cve}")
    
    # 返回适当的退出码
    if missing_files:
        print(f"\n⚠️  存在 {len(missing_files)} 个缺失的CVE文件!")
        sys.exit(1)
    else:
        print(f"\n✅ 所有CVE都有对应的文件!")
        sys.exit(0)


if __name__ == "__main__":
    main()