#!/usr/bin/env python3
"""
使用大模型对RISC-V CVE进行总结和分类
支持多种LLM提供商（OpenAI、Anthropic、本地模型等）
"""

import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Tuple
import time
from datetime import datetime
from llm_config_manager import LLMConfig


class CVEClassifier:
    """使用LLM对CVE进行分类和总结"""
    
    def __init__(
        self, 
        input_dir: str = "riscv_cves",
        output_file: str = "riscv_cves_classified.json",
        config_file: str = "llm_config.json",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None
    ):
        """
        初始化分类器
        
        Args:
            input_dir: 输入目录（包含CVE JSON文件）
            output_file: 输出文件路径
            config_file: LLM配置文件路径
            api_key: API密钥（可选，覆盖配置文件）
            model: 使用的模型名称（可选，覆盖配置文件）
            provider: LLM提供商（可选，覆盖配置文件）
        """
        self.input_dir = Path(input_dir)
        self.output_file = Path(output_file)
        
        # 加载配置
        self.config = LLMConfig(config_file)
        
        # 命令行参数可覆盖配置文件
        self.provider = (provider or self.config.get_default_provider()).lower()
        self.model = model or self.config.get_default_model(self.provider)
        self.api_key = api_key or self.config.get_api_key(self.provider)
        
        # 从配置获取其他参数
        self.temperature = self.config.get_temperature(self.provider)
        self.max_tokens = self.config.get_max_tokens(self.provider)
        self.timeout = self.config.get_timeout(self.provider)
        self.rate_limit_delay = self.config.get_rate_limit_delay(self.provider)
        self.system_prompt = self.config.get_system_prompt()
        
        # 动态维护的分类列表
        self.categories = self.config.get_predefined_categories().copy()
        self.allow_new_categories = self.config.allow_new_categories()
        
        # 分类结果
        self.classified_cves: List[Dict] = []
        
        # 统计信息
        self.stats = {
            "total_processed": 0,
            "successful": 0,
            "failed": 0,
            "new_categories_created": 0,
            "by_category": {}
        }
        
    def _init_llm_client(self):
        """初始化LLM客户端"""
        if self.provider == "openai":
            try:
                from openai import OpenAI
                # 支持自定义base_url
                base_url = self.config.get_base_url(self.provider)
                if base_url:
                    self.client = OpenAI(api_key=self.api_key, base_url=base_url)
                else:
                    self.client = OpenAI(api_key=self.api_key)
                return True
            except ImportError:
                print("⚠️  OpenAI库未安装，请运行: pip install openai")
                return False
        elif self.provider == "anthropic":
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
                return True
            except ImportError:
                print("⚠️  Anthropic库未安装，请运行: pip install anthropic")
                return False
        elif self.provider == "local":
            # 本地模型或模拟模式
            print("⚠️  使用本地/模拟模式（不调用实际API）")
            self.client = None
            return True
        else:
            print(f"⚠️  不支持的提供商: {self.provider}")
            return False
    
    def _create_classification_prompt(self, cve_data: Dict) -> str:
        """
        创建分类提示词
        
        Args:
            cve_data: CVE数据
            
        Returns:
            提示词字符串
        """
        cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
        
        # 提取描述
        description = "No description available"
        containers = cve_data.get('containers', {})
        cna = containers.get('cna', {})
        descriptions = cna.get('descriptions', [])
        if descriptions:
            description = descriptions[0].get('value', 'No description available')
        
        # 提取影响的产品
        affected_products = []
        affected = cna.get('affected', [])
        for item in affected:
            product = item.get('product', '')
            vendor = item.get('vendor', '')
            if product or vendor:
                affected_products.append(f"{vendor} {product}".strip())
        
        # 当前可用的分类
        categories_str = "\n".join([f"- {cat}" for cat in self.categories])
        
        prompt = f"""Please analyze the following RISC-V related CVE and provide:

1. A concise summary (2-3 sentences in Chinese)
2. Classification into one of the existing categories, OR suggest a new category if none fit well
3. Key technical details (in Chinese)

CVE ID: {cve_id}

Description:
{description}

Affected Products:
{', '.join(affected_products) if affected_products else 'Not specified'}

Available Categories:
{categories_str}

Please respond in the following JSON format:
{{
    "summary": "简短的中文总结（2-3句话）",
    "category": "分类名称（选择现有的或提出新的）",
    "is_new_category": false,
    "key_points": [
        "关键点1",
        "关键点2",
        "关键点3"
    ],
    "severity_assessment": "严重程度评估（Critical/High/Medium/Low）",
    "technical_details": "技术细节说明"
}}

If you suggest a new category, set "is_new_category" to true and provide a clear category name in English.
"""
        return prompt
    
    def _call_llm(self, prompt: str) -> Optional[Dict]:
        """
        调用LLM获取分类结果
        
        Args:
            prompt: 提示词
            
        Returns:
            LLM返回的分类结果
        """
        if self.provider == "openai":
            try:
                response = self.client.chat.completions.create(
                    model=self.model,
                    messages=[
                        {"role": "system", "content": self.system_prompt},
                        {"role": "user", "content": prompt}
                    ],
                    temperature=self.temperature,
                    max_tokens=self.max_tokens
                )
                content = response.choices[0].message.content
                # 尝试解析JSON
                return self._parse_llm_response(content)
            except Exception as e:
                print(f"  ✗ OpenAI API调用失败: {e}")
                return None
                
        elif self.provider == "anthropic":
            try:
                message = self.client.messages.create(
                    model=self.model,
                    max_tokens=self.max_tokens,
                    messages=[
                        {"role": "user", "content": prompt}
                    ]
                )
                content = message.content[0].text
                return self._parse_llm_response(content)
            except Exception as e:
                print(f"  ✗ Anthropic API调用失败: {e}")
                return None
                
        elif self.provider == "local":
            # 模拟模式：基于规则的简单分类
            return self._simulate_classification(prompt)
        
        return None
    
    def _parse_llm_response(self, response: str) -> Optional[Dict]:
        """解析LLM返回的JSON响应"""
        try:
            # 尝试提取JSON部分
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
        except Exception as e:
            print(f"  ✗ JSON解析失败: {e}")
        return None
    
    def _simulate_classification(self, prompt: str) -> Dict:
        """
        模拟分类（当无法访问真实LLM时使用）
        基于关键词的简单规则
        """
        # 从prompt中提取描述部分
        description = ""
        if "Description:" in prompt:
            desc_start = prompt.find("Description:") + len("Description:")
            desc_end = prompt.find("Affected Products:")
            description = prompt[desc_start:desc_end].strip().lower()
        
        # 基于关键词的分类规则
        category = "Other"
        key_points = []
        
        if "linux" in description and "kernel" in description:
            category = "Linux Kernel"
            key_points = [
                "Linux内核中的RISC-V相关漏洞",
                "可能影响系统稳定性和安全性",
                "需要内核补丁修复"
            ]
        elif any(word in description for word in ["cpu", "processor", "soc", "core", "boom", "rocket"]):
            category = "RISC-V CPU/SoC"
            key_points = [
                "RISC-V处理器或SoC相关漏洞",
                "可能涉及硬件设计问题",
                "需要固件或硬件更新"
            ]
        elif any(word in description for word in ["simulator", "emulator", "qemu", "spike", "sail"]):
            category = "Simulator"
            key_points = [
                "RISC-V模拟器漏洞",
                "可能影响差分测试的结果",
                "建议检查更新RISC-V模拟器版本"
            ]
        elif any(word in description for word in ["compiler", "toolchain", "gcc", "llvm"]):
            category = "RISC-V Development Tools"
            key_points = [
                "RISC-V开发工具链相关",
                "可能影响编译结果",
                "建议更新工具链版本"
            ]
        elif any(word in description for word in ["firmware", "driver", "device", "application", "app"]):
            category = "Device-Specific Firmware & Applications"
            key_points = [
                "设备固件或应用程序相关漏洞",
                "可能影响特定设备的安全性",
                "建议更新固件或应用版本"
            ]
        elif any(word in description for word in ["instruction", "isa", "specification", "manual", "standard"]):
            category = "RISC-V Instruction Set Manual"
            key_points = [
                "RISC-V指令集规范相关问题",
                "可能涉及架构定义或标准解释",
                "需要参考最新的ISA手册"
            ]
        
        # 评估严重程度
        severity = "Medium"
        if any(word in description for word in ["critical", "remote", "execute", "overflow", "injection"]):
            severity = "High"
        elif any(word in description for word in ["denial", "leak", "information"]):
            severity = "Medium"
        else:
            severity = "Low"
        
        return {
            "summary": f"这是一个RISC-V相关的{category}漏洞，可能影响系统的安全性和稳定性。",
            "category": category,
            "is_new_category": False,
            "key_points": key_points if key_points else ["需要进一步分析", "建议查看详细描述"],
            "severity_assessment": severity,
            "technical_details": "基于关键词的自动分类，建议使用LLM进行更详细的分析"
        }
    
    def classify_cve(self, cve_file: Path) -> Optional[Dict]:
        """
        分类单个CVE
        
        Args:
            cve_file: CVE文件路径
            
        Returns:
            分类结果
        """
        try:
            # 读取CVE数据
            with open(cve_file, 'r', encoding='utf-8') as f:
                cve_data = json.load(f)
            
            cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
            
            # 创建提示词
            prompt = self._create_classification_prompt(cve_data)
            
            # 调用LLM
            llm_result = self._call_llm(prompt)
            
            if not llm_result:
                return None
            
            # 处理新分类
            category = llm_result.get('category', 'Other')
            is_new = llm_result.get('is_new_category', False)
            
            if is_new and category not in self.categories and self.allow_new_categories:
                self.categories.append(category)
                self.stats['new_categories_created'] += 1
                print(f"  ✨ 创建新分类: {category}")
            elif is_new and not self.allow_new_categories:
                print(f"  ⚠️  不允许创建新分类，使用'Other'代替: {category}")
                category = "Other"
            
            # 构建结果
            result = {
                "cve_id": cve_id,
                "category": category,
                "summary": llm_result.get('summary', ''),
                "key_points": llm_result.get('key_points', []),
                "severity_assessment": llm_result.get('severity_assessment', 'Unknown'),
                "technical_details": llm_result.get('technical_details', ''),
                "original_data": cve_data,
                "classification_timestamp": datetime.now().isoformat()
            }
            
            return result
            
        except Exception as e:
            print(f"  ✗ 处理CVE文件失败 {cve_file}: {e}")
            return None
    
    def process_all_cves(self):
        """处理所有CVE文件"""
        print("=" * 70)
        print("RISC-V CVE 分类和总结")
        print("=" * 70)
        print(f"输入目录: {self.input_dir}")
        print(f"输出文件: {self.output_file}")
        print(f"LLM提供商: {self.provider}")
        print(f"模型: {self.model}")
        print(f"Temperature: {self.temperature}")
        print(f"Max Tokens: {self.max_tokens}")
        print(f"允许新分类: {self.allow_new_categories}")
        print("-" * 70)
        
        # 初始化LLM客户端
        if not self._init_llm_client():
            print("✗ LLM客户端初始化失败")
            return
        
        # 获取所有CVE文件（排除summary等文件）
        cve_files = sorted(self.input_dir.glob("CVE-*.json"))
        total_files = len(cve_files)
        
        print(f"找到 {total_files} 个CVE文件")
        print("-" * 70)
        
        # 处理每个CVE
        for idx, cve_file in enumerate(cve_files, 1):
            cve_id = cve_file.stem
            print(f"\n[{idx}/{total_files}] 处理 {cve_id}...")
            
            self.stats['total_processed'] += 1
            
            result = self.classify_cve(cve_file)
            
            if result:
                self.classified_cves.append(result)
                self.stats['successful'] += 1
                
                category = result['category']
                self.stats['by_category'][category] = self.stats['by_category'].get(category, 0) + 1
                
                print(f"  ✓ 分类: {category}")
                print(f"  ✓ 总结: {result['summary'][:60]}...")
            else:
                self.stats['failed'] += 1
            
            # 避免API限流
            if self.provider in ["openai", "anthropic"]:
                time.sleep(self.rate_limit_delay)
        
        # 保存结果
        self._save_results()
        
        # 显示统计
        self._print_statistics()
    
    def _save_results(self):
        """保存分类结果"""
        output_data = {
            "metadata": {
                "total_cves": len(self.classified_cves),
                "classification_date": datetime.now().isoformat(),
                "model_used": self.model,
                "provider": self.provider,
                "categories": self.categories,
                "config_file": str(self.config.config_file)
            },
            "statistics": self.stats,
            "classified_cves": self.classified_cves
        }
        
        # 根据配置决定是否保存原始数据
        if not self.config.should_save_original_data():
            for cve in output_data["classified_cves"]:
                cve.pop("original_data", None)
        
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(output_data, f, indent=4, ensure_ascii=False)
        
        print(f"\n✓ 结果已保存到: {self.output_file}")
        
        # 根据配置生成简化版本
        if self.config.should_generate_summary():
            simplified_output = self.output_file.parent / f"{self.output_file.stem}_summary.json"
            simplified_data = {
                "metadata": output_data["metadata"],
                "statistics": output_data["statistics"],
                "classified_cves": [
                    {k: v for k, v in cve.items() if k != "original_data"}
                    for cve in self.classified_cves
                ]
            }
            
            with open(simplified_output, 'w', encoding='utf-8') as f:
                json.dump(simplified_data, f, indent=4, ensure_ascii=False)
            
            print(f"✓ 简化版本已保存到: {simplified_output}")
        
        # 根据配置生成人类可读的报告
        if self.config.should_generate_report():
            self._generate_report()
    
    def _generate_report(self):
        """生成人类可读的分类报告"""
        report_file = self.output_file.parent / f"{self.output_file.stem}_report.txt"
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("=" * 70 + "\n")
            f.write("RISC-V CVE 分类和总结报告\n")
            f.write("=" * 70 + "\n\n")
            
            f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"处理CVE总数: {self.stats['total_processed']}\n")
            f.write(f"成功分类: {self.stats['successful']}\n")
            f.write(f"失败数量: {self.stats['failed']}\n\n")
            
            # 按分类统计
            f.write("-" * 70 + "\n")
            f.write("分类统计:\n")
            f.write("-" * 70 + "\n")
            for category, count in sorted(self.stats['by_category'].items(), key=lambda x: x[1], reverse=True):
                percentage = (count / self.stats['successful'] * 100) if self.stats['successful'] > 0 else 0
                bar = "█" * (count // 2) if count > 1 else "▌"
                f.write(f"{category:30s}: {count:3d} 个 ({percentage:5.1f}%) {bar}\n")
            
            f.write("\n" + "=" * 70 + "\n")
            f.write("详细分类结果\n")
            f.write("=" * 70 + "\n\n")
            
            # 按分类分组显示
            by_category = {}
            for cve in self.classified_cves:
                category = cve['category']
                if category not in by_category:
                    by_category[category] = []
                by_category[category].append(cve)
            
            for category in sorted(by_category.keys()):
                cves = by_category[category]
                f.write(f"\n{'=' * 70}\n")
                f.write(f"分类: {category} ({len(cves)}个)\n")
                f.write(f"{'=' * 70}\n\n")
                
                for cve in cves:
                    f.write(f"CVE ID: {cve['cve_id']}\n")
                    f.write(f"严重程度: {cve['severity_assessment']}\n")
                    f.write(f"总结: {cve['summary']}\n")
                    f.write(f"关键点:\n")
                    for point in cve['key_points']:
                        f.write(f"  • {point}\n")
                    f.write(f"技术细节: {cve['technical_details']}\n")
                    f.write(f"{'-' * 70}\n\n")
        
        print(f"✓ 详细报告已保存到: {report_file}")
    
    def _print_statistics(self):
        """打印统计信息"""
        print("\n" + "=" * 70)
        print("处理完成!")
        print("=" * 70)
        print(f"总计处理: {self.stats['total_processed']} 个CVE")
        print(f"成功分类: {self.stats['successful']} 个")
        print(f"失败数量: {self.stats['failed']} 个")
        print(f"新建分类: {self.stats['new_categories_created']} 个")
        
        print("\n" + "-" * 70)
        print("分类分布:")
        print("-" * 70)
        for category, count in sorted(self.stats['by_category'].items(), key=lambda x: x[1], reverse=True):
            percentage = (count / self.stats['successful'] * 100) if self.stats['successful'] > 0 else 0
            bar = "█" * (count // 2) if count > 1 else "▌"
            print(f"  {category:30s}: {count:3d} 个 ({percentage:5.1f}%) {bar}")
        
        print("\n" + "-" * 70)
        print("所有分类:")
        print("-" * 70)
        for idx, category in enumerate(self.categories, 1):
            print(f"  {idx}. {category}")
        print("=" * 70)


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="使用LLM对RISC-V CVE进行分类和总结"
    )
    parser.add_argument(
        '--input-dir',
        default='riscv_cves',
        help='输入目录（包含CVE JSON文件，默认: riscv_cves）'
    )
    parser.add_argument(
        '--output',
        default='riscv_cves_classified.json',
        help='输出文件路径（默认: riscv_cves_classified.json）'
    )
    parser.add_argument(
        '--config',
        default='llm_config.json',
        help='配置文件路径（默认: llm_config.json）'
    )
    parser.add_argument(
        '--provider',
        choices=['openai', 'anthropic', 'local'],
        help='LLM提供商（覆盖配置文件设置）'
    )
    parser.add_argument(
        '--model',
        help='模型名称（覆盖配置文件设置）'
    )
    parser.add_argument(
        '--api-key',
        help='API密钥（覆盖配置文件和环境变量）'
    )
    parser.add_argument(
        '--show-config',
        action='store_true',
        help='显示配置信息后退出'
    )
    
    args = parser.parse_args()
    
    # 如果只是查看配置
    if args.show_config:
        config = LLMConfig(args.config)
        config.print_config_summary()
        return
    
    # 创建分类器
    classifier = CVEClassifier(
        input_dir=args.input_dir,
        output_file=args.output,
        config_file=args.config,
        api_key=args.api_key,
        model=args.model,
        provider=args.provider
    )
    
    # 处理所有CVE
    classifier.process_all_cves()


if __name__ == "__main__":
    main()
