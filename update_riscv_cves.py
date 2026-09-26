#!/usr/bin/env python3
"""
RISC-V CVE增量更新脚本
整合提取和分类功能，用于下载CVE增量包，提取RISC-V相关CVE，并更新分类JSON文件
支持北京时间上午9:30下载前一天的增量包

作者：自动生成
日期：2025-11-17
"""

import json
import os
import re
import sys
import zipfile
import requests
from pathlib import Path
from typing import Dict, List, Set, Optional
from datetime import datetime, timedelta
import time

# 添加父目录到路径以导入配置管理器
sys.path.insert(0, str(Path(__file__).parent.parent))
from llm_config_manager import LLMConfig


class RISCVCVEUpdater:
    """RISC-V CVE增量更新器"""
    
    # RISC-V关键字模式（与extract_riscv_cves.py保持一致）
    RISCV_PATTERNS = [
        r'\brisc-v\b',
        r'\briscv\b',
        r'\brisc\s*v\b',
        r'\bRISC-V\b',
        r'\bRISCV\b',
        r'\bRISC\s*V\b',
        r'\barch/riscv\b',  # Linux kernel architecture path
        r'\briscv:',        # Linux kernel subsystem prefix
    ]
    
    # Extended keywords that may be RISC-V related (require LLM verification)
    EXTENDED_KEYWORDS = [
        (r'\bBOOM\b', 'BOOM'),           # Berkeley Out-of-Order Machine
        (r'\brocket\b', 'rocket'),        # Rocket Chip
        (r'\bXiangShan\b', 'XiangShan'),  # 香山处理器
        (r'\b香山\b', 'XiangShan'),
        (r'\bopentitan\b', 'opentitan'),  # OpenTitan
        (r'\bSpike\b', 'Spike'),          # RISC-V ISA Simulator
        (r'\bNEMU\b', 'NEMU'),            # NEMU Emulator
        (r'\bXuanTie\b', 'XuanTie'),      # 平头哥玄铁 RISC-V 处理器
        (r'\bcva6\b', 'CORE-V CVA6'),     # CORE-V CVA6 RISC-V application processor
    ]
    
    def __init__(
        self,
        cves_dir: str = "../cves",
        output_dir: str = "../riscv_cves",
        classified_file: str = "../riscv_cves_classified.json",
        summary_file: str = "../riscv_cves_classified_summary.json",
        config_file: str = "../llm_config.json",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None
    ):
        """
        初始化更新器
        
        Args:
            cves_dir: CVE数据库目录
            output_dir: RISC-V CVE输出目录
            classified_file: 分类后的完整JSON文件
            summary_file: 分类摘要JSON文件
            config_file: LLM配置文件
            api_key: API密钥（可选）
            model: 使用的模型名称（可选）
            provider: LLM提供商（可选）
        """
        self.cves_dir = Path(cves_dir)
        self.output_dir = Path(output_dir)
        self.classified_file = Path(classified_file)
        self.summary_file = Path(summary_file)
        
        # 确保目录存在
        self.output_dir.mkdir(exist_ok=True, parents=True)
        
        # 加载LLM配置
        self.config = LLMConfig(config_file)
        self.provider = (provider or self.config.get_default_provider()).lower()
        self.model = model or self.config.get_default_model(self.provider)
        
        # API密钥优先级：命令行参数 > 环境变量 > 配置文件
        self.api_key = (
            api_key or 
            os.environ.get('OPENAI_API_KEY') if self.provider == 'openai' else
            os.environ.get('ANTHROPIC_API_KEY') if self.provider == 'anthropic' else
            self.config.get_api_key(self.provider)
        )
        
        # 从配置获取其他参数
        self.temperature = self.config.get_temperature(self.provider)
        self.max_tokens = self.config.get_max_tokens(self.provider)
        self.rate_limit_delay = self.config.get_rate_limit_delay(self.provider)
        self.system_prompt = self.config.get_system_prompt()
        
        # 动态维护的分类列表
        self.categories = self.config.get_predefined_categories().copy()
        self.allow_new_categories = self.config.allow_new_categories()
        
        # 编译正则表达式
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.RISCV_PATTERNS
        ]
        self.compiled_extended = [
            (re.compile(pattern, re.IGNORECASE), name) 
            for pattern, name in self.EXTENDED_KEYWORDS
        ]
        
        # 加载现有分类数据
        self.existing_classified_data = self._load_existing_classified_data()
        self.existing_summary_data = self._load_existing_summary_data()
        
        # 已知的CVE ID集合（用于去重）
        self.known_cve_ids = set(
            cve['cve_id'] for cve in self.existing_classified_data.get('classified_cves', [])
        )
        
        # 新发现的CVE
        self.new_cves: List[Dict] = []
        
        # Extended keyword candidates (for LLM verification)
        self.extended_candidates: Dict[str, Dict] = {}  # cve_id -> cve_data
        self.extended_match_keywords: Dict[str, Set[str]] = {}  # cve_id -> matched keywords
        self.verified_extended_cves: List[Dict] = []  # LLM-verified extended CVEs
        self.direct_match_ids: Set[str] = set()  # CVE IDs matched by direct RISC-V patterns
        
        # Retry configuration
        self.max_retries = 5
        self.initial_retry_delay = 1.0
        self.max_retry_delay = 60.0
        self.retry_multiplier = 2.0
        
        # 统计信息
        self.stats = {
            "delta_downloaded": 0,
            "new_riscv_cves_found": 0,
            "extended_candidates": 0,
            "extended_verified": 0,
            "extended_rejected": 0,
            "by_keyword": {},
            "classification_successful": 0,
            "classification_failed": 0,
            "new_categories_created": 0
        }
        
    def _load_existing_classified_data(self) -> Dict:
        """加载现有的分类数据"""
        if not self.classified_file.exists():
            print(f"⚠️  分类文件不存在: {self.classified_file}")
            return {
                "metadata": {
                    "total_cves": 0,
                    "classification_date": datetime.now().isoformat(),
                    "model_used": self.model,
                    "provider": self.provider,
                    "categories": self.categories,
                    "config_file": str(self.config.config_file)
                },
                "statistics": {
                    "total_processed": 0,
                    "successful": 0,
                    "failed": 0,
                    "new_categories_created": 0,
                    "by_category": {}
                },
                "classified_cves": []
            }
        
        try:
            with open(self.classified_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"✓ 已加载现有分类数据: {len(data.get('classified_cves', []))} 个CVE")
            return data
        except Exception as e:
            print(f"✗ 加载分类文件失败: {e}")
            return {"classified_cves": []}
    
    def _load_existing_summary_data(self) -> Dict:
        """加载现有的摘要数据"""
        if not self.summary_file.exists():
            print(f"⚠️  摘要文件不存在: {self.summary_file}")
            return {
                "metadata": {
                    "total_cves": 0,
                    "classification_date": datetime.now().isoformat(),
                    "model_used": self.model,
                    "provider": self.provider,
                    "categories": self.categories,
                    "config_file": str(self.config.config_file)
                },
                "statistics": {
                    "total_processed": 0,
                    "successful": 0,
                    "failed": 0,
                    "new_categories_created": 0,
                    "by_category": {}
                },
                "classified_cves": []
            }
        
        try:
            with open(self.summary_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
            print(f"✓ 已加载现有摘要数据")
            return data
        except Exception as e:
            print(f"✗ 加载摘要文件失败: {e}")
            return {"classified_cves": []}
    
    def download_delta_cve_package(self, date: Optional[datetime] = None) -> Optional[Path]:
        """
        下载CVE增量包
        
        Args:
            date: 下载指定日期的增量包，默认为昨天
            
        Returns:
            下载的zip文件路径，失败返回None
        """
        if date is None:
            # 默认下载昨天的增量包
            date = datetime.now() - timedelta(days=1)
        
        date_str = date.strftime("%Y-%m-%d")
        url = f"https://github.com/CVEProject/cvelistV5/releases/download/cve_{date_str}_at_end_of_day/{date_str}_delta_CVEs_at_end_of_day.zip"
        
        print(f"\n{'='*70}")
        print(f"下载CVE增量包: {date_str}")
        print(f"{'='*70}")
        print(f"URL: {url}")
        
        zip_path = Path(f"delta_cves_{date_str}.zip")
        
        try:
            print(f"开始下载...")
            response = requests.get(url, stream=True, timeout=60)
            response.raise_for_status()
            
            # 下载文件
            total_size = int(response.headers.get('content-length', 0))
            downloaded_size = 0
            
            with open(zip_path, 'wb') as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        if total_size > 0:
                            progress = (downloaded_size / total_size) * 100
                            print(f"\r下载进度: {progress:.1f}%", end='', flush=True)
            
            print(f"\n✓ 下载完成: {zip_path} ({downloaded_size / 1024:.1f} KB)")
            self.stats['delta_downloaded'] = 1
            return zip_path
            
        except requests.exceptions.RequestException as e:
            print(f"\n✗ 下载失败: {e}")
            if zip_path.exists():
                zip_path.unlink()
            return None
    
    def extract_delta_package(self, zip_path: Path) -> int:
        """
        解压增量包到cves目录
        
        Args:
            zip_path: zip文件路径
            
        Returns:
            解压的文件数量
        """
        print(f"\n解压增量包到: {self.cves_dir}")
        
        try:
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                # 获取所有文件列表
                file_list = zip_ref.namelist()
                total_files = len(file_list)
                
                print(f"包含 {total_files} 个文件")
                
                # 解压所有文件
                zip_ref.extractall(self.cves_dir)
                
                print(f"✓ 解压完成")
                return total_files
                
        except Exception as e:
            print(f"✗ 解压失败: {e}")
            return 0
    
    def is_riscv_related(self, content: str) -> bool:
        """
        检查内容是否包含RISC-V关键字
        
        Args:
            content: 要检查的内容
            
        Returns:
            True表示相关，False表示不相关
        """
        for pattern in self.compiled_patterns:
            if pattern.search(content):
                return True
        return False
    
    def check_extended_keywords(self, content: str) -> Set[str]:
        """
        Check if content matches any extended keywords.
        
        Args:
            content: String content to check
            
        Returns:
            Set of matched keyword names
        """
        matched = set()
        for pattern, name in self.compiled_extended:
            if pattern.search(content):
                matched.add(name)
        return matched
    
    def _get_cve_description(self, cve_data: Dict) -> str:
        """Extract description from CVE data."""
        containers = cve_data.get('containers', {})
        cna = containers.get('cna', {})
        descriptions = cna.get('descriptions', [])
        if descriptions:
            return descriptions[0].get('value', '')
        return ''
    
    def scan_for_new_riscv_cves(self, delta_files: Optional[List[Path]] = None) -> List[Dict]:
        """
        扫描新的RISC-V相关CVE（直接匹配和扩展关键词匹配）
        
        Args:
            delta_files: 增量文件列表，如果为None则扫描整个cves目录
            
        Returns:
            新发现的RISC-V CVE列表（直接匹配的）
        """
        print(f"\n{'='*70}")
        print(f"扫描新的RISC-V相关CVE")
        print(f"{'='*70}")
        
        new_riscv_cves = []
        
        if delta_files is None:
            # 扫描整个cves目录
            json_files = list(self.cves_dir.rglob("*.json"))
        else:
            json_files = delta_files
        
        print(f"待扫描文件数: {len(json_files)}")
        
        for idx, file_path in enumerate(json_files, 1):
            if idx % 100 == 0:
                print(f"进度: {idx}/{len(json_files)} 文件已扫描...")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Check for direct RISC-V match first
                is_direct_match = self.is_riscv_related(content)
                
                # Check for extended keywords
                extended_matches = self.check_extended_keywords(content)
                
                if not is_direct_match and not extended_matches:
                    continue
                
                # 解析JSON
                cve_data = json.loads(content)
                cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                
                # 检查是否已存在
                if cve_id in self.known_cve_ids:
                    continue
                
                if is_direct_match:
                    # Direct RISC-V match - add immediately
                    print(f"✓ 发现新的RISC-V CVE: {cve_id}")
                    new_riscv_cves.append(cve_data)
                    self.known_cve_ids.add(cve_id)
                    self.direct_match_ids.add(cve_id)
                    
                    # 保存单个CVE文件
                    output_file = self.output_dir / f"{cve_id}.json"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(cve_data, f, indent=4, ensure_ascii=False)
                        
                elif extended_matches and cve_id not in self.direct_match_ids:
                    # Extended keyword match - add to candidates for LLM verification
                    self.extended_candidates[cve_id] = cve_data
                    if cve_id not in self.extended_match_keywords:
                        self.extended_match_keywords[cve_id] = set()
                    self.extended_match_keywords[cve_id].update(extended_matches)
                    
                    # Update keyword statistics
                    for kw in extended_matches:
                        self.stats["by_keyword"][kw] = self.stats["by_keyword"].get(kw, 0) + 1
                
            except Exception as e:
                print(f"✗ 处理文件失败 {file_path}: {e}")
                continue
        
        self.stats['new_riscv_cves_found'] = len(new_riscv_cves)
        self.stats['extended_candidates'] = len(self.extended_candidates)
        print(f"\n✓ 发现 {len(new_riscv_cves)} 个新的RISC-V CVE（直接匹配）")
        print(f"✓ 发现 {len(self.extended_candidates)} 个扩展关键词候选CVE（待LLM验证）")
        return new_riscv_cves
    
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
    
    def _call_llm_with_retry(self, prompt: str, system_prompt: str = None) -> Optional[str]:
        """
        Call LLM API with exponential backoff retry.
        
        Args:
            prompt: The prompt to send
            system_prompt: Optional system prompt
            
        Returns:
            Response content or None if all retries failed
        """
        if system_prompt is None:
            system_prompt = self.system_prompt
            
        delay = self.initial_retry_delay
        
        for attempt in range(self.max_retries):
            try:
                if self.provider == "openai" and self.client:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=self.temperature,
                        max_tokens=self.max_tokens
                    )
                    return response.choices[0].message.content
                    
                elif self.provider == "anthropic" and self.client:
                    message = self.client.messages.create(
                        model=self.model,
                        max_tokens=self.max_tokens,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    return message.content[0].text
                    
            except Exception as e:
                error_msg = str(e).lower()
                is_retryable = any(x in error_msg for x in ["timeout", "rate", "limit", "503", "429", "connection"])
                
                if attempt < self.max_retries - 1 and is_retryable:
                    print(f"  ⚠️  API调用失败 (尝试 {attempt + 1}/{self.max_retries}): {e}")
                    print(f"  ⏳ {delay:.1f}秒后重试...")
                    time.sleep(delay)
                    delay = min(delay * self.retry_multiplier, self.max_retry_delay)
                else:
                    print(f"  ✗ API调用失败，共尝试 {attempt + 1} 次: {e}")
                    return None
        
        return None
    
    def verify_extended_candidates(self) -> List[Dict]:
        """
        Verify extended keyword candidates using LLM.
        
        Returns:
            List of verified CVE data that are RISC-V related
        """
        if not self.extended_candidates:
            print("\n没有扩展关键词候选CVE需要验证")
            return []
        
        print(f"\n{'='*70}")
        print(f"使用LLM验证扩展关键词候选CVE")
        print(f"{'='*70}")
        print(f"待验证CVE数量: {len(self.extended_candidates)}")
        print(f"LLM提供商: {self.provider}")
        print(f"模型: {self.model}")
        
        # Initialize LLM client
        if not self._init_llm_client():
            print("✗ LLM客户端初始化失败，跳过扩展关键词验证")
            return []
        
        verified_cves = []
        candidates = list(self.extended_candidates.values())
        max_batch_size = 5  # Process 5 CVEs per batch
        
        total = len(candidates)
        verified_count = 0
        rejected_count = 0
        
        for i in range(0, total, max_batch_size):
            batch = candidates[i:i + max_batch_size]
            batch_num = i // max_batch_size + 1
            total_batches = (total + max_batch_size - 1) // max_batch_size
            
            print(f"\n验证批次 {batch_num}/{total_batches}...")
            
            results = self._verify_batch(batch)
            
            for cve, (cve_id, is_related, reason) in zip(batch, results):
                if is_related:
                    verified_cves.append(cve)
                    self.verified_extended_cves.append(cve)
                    self.known_cve_ids.add(cve_id)
                    verified_count += 1
                    print(f"  ✓ {cve_id}: RISC-V相关 - {reason}")
                    
                    # Save individual CVE file
                    output_file = self.output_dir / f"{cve_id}.json"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(cve, f, indent=4, ensure_ascii=False)
                else:
                    rejected_count += 1
                    print(f"  ✗ {cve_id}: 不相关 - {reason}")
            
            # Rate limit between batches
            if i + max_batch_size < total:
                time.sleep(self.rate_limit_delay)
        
        self.stats["extended_verified"] = verified_count
        self.stats["extended_rejected"] = rejected_count
        print(f"\n✓ 验证完成: {verified_count} 个通过, {rejected_count} 个拒绝")
        
        return verified_cves
    
    def _verify_batch(self, cves: List[Dict]) -> List[tuple]:
        """
        Verify a batch of CVEs for RISC-V relevance.
        
        Args:
            cves: List of CVE data dictionaries (max 5)
            
        Returns:
            List of tuples: (cve_id, is_riscv_related, reason)
        """
        if not self.client:
            return [(cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN'), False, "No LLM") for cve in cves]
        
        # Build prompt with CVE information
        riscv_criteria = [
            "RISC-V processor", "RISC-V SoC", "RISC-V instruction set", "RISC-V simulator",
            "RISC-V vulnerabilities", "RISC-V development tools", "RISC-V firmware or applications"
        ]
        criteria_str = ", ".join(riscv_criteria)
        cve_info_list = []
        
        for cve in cves:
            cve_id = cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
            description = self._get_cve_description(cve)
            cve_info_list.append(f"CVE ID: {cve_id}\nDescription: {description[:500]}")
        
        cve_info = "\n\n---\n\n".join(cve_info_list)
        
        prompt = f"""Please determine whether the following CVE vulnerabilities are related to the RISC-V ecosystem.

Criteria for RISC-V relevance include: {criteria_str}

Please analyze the following CVEs and determine whether each is related to RISC-V:

{cve_info}

Please return results in JSON format as follows:
{{
    "results": [
        {{"cve_id": "CVE-XXXX-XXXXX", "is_riscv_related": true/false, "reason": "Brief explanation"}}
    ]
}}

Important notes:
1. BOOM refers to Berkeley Out-of-Order Machine (a RISC-V processor)
2. Rocket refers to Rocket Chip Generator (a RISC-V SoC generator)
3. XiangShan is an open-source RISC-V processor project
4. OpenTitan is an open-source secure chip project that typically uses RISC-V cores
5. Spike is the official RISC-V ISA simulator
6. NEMU is a RISC-V emulator
7. CVA6 is an open-source RISC-V application processor (CORE-V family)
8. XuanTie / T-Head refers to Alibaba T-Head's RISC-V processor family (e.g., C906/C910/C920)
9. accel/rocket in the Linux kernel is the Rockchip NPU driver, NOT the RISC-V Rocket Chip

Please judge carefully. If the CVE is clearly related to other technologies (such as unrelated software with the same name), it should be marked as not related."""

        system_prompt = "You are a cybersecurity expert specializing in RISC-V architecture. Your task is to determine whether CVEs are related to RISC-V ecosystem."
        response = self._call_llm_with_retry(prompt, system_prompt)
        
        if response:
            try:
                # Parse JSON response
                start_idx = response.find('{')
                end_idx = response.rfind('}') + 1
                if start_idx != -1 and end_idx > start_idx:
                    result = json.loads(response[start_idx:end_idx])
                    results = result.get("results", [])
                    return [
                        (r.get("cve_id", "UNKNOWN"), 
                         r.get("is_riscv_related", False), 
                         r.get("reason", ""))
                        for r in results
                    ]
            except json.JSONDecodeError as e:
                print(f"  ✗ JSON解析失败: {e}")
        
        # Return default (not related) for all CVEs if parsing failed
        return [(cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN'), False, "Parse failed") for cve in cves]
    
    def _create_classification_prompt(self, cve_data: Dict) -> str:
        """创建分类提示词"""
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
        """调用LLM获取分类结果"""
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
            return self._simulate_classification(prompt)
        
        return None
    
    def _parse_llm_response(self, response: str) -> Optional[Dict]:
        """解析LLM返回的JSON响应"""
        try:
            start_idx = response.find('{')
            end_idx = response.rfind('}') + 1
            if start_idx != -1 and end_idx > start_idx:
                json_str = response[start_idx:end_idx]
                return json.loads(json_str)
        except Exception as e:
            print(f"  ✗ JSON解析失败: {e}")
        return None
    
    def _simulate_classification(self, prompt: str) -> Dict:
        """模拟分类（基于规则）"""
        description = ""
        if "Description:" in prompt:
            desc_start = prompt.find("Description:") + len("Description:")
            desc_end = prompt.find("Affected Products:")
            description = prompt[desc_start:desc_end].strip().lower()
        
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
        elif any(word in description for word in ["compiler", "toolchain", "gcc", "llvm"]):
            category = "RISC-V Development Tools"
            key_points = [
                "RISC-V开发工具链相关",
                "可能影响编译结果",
                "建议更新工具链版本"
            ]
        elif any(word in description for word in ["simulator", "emulator", "spike", "qemu"]):
            category = "Simulator"
            key_points = [
                "RISC-V模拟器漏洞",
                "可能影响模拟测试的结果",
                "建议检查更新模拟器版本"
            ]
        
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
    
    def classify_new_cves(self, new_cves: List[Dict]) -> List[Dict]:
        """
        对新CVE进行分类
        
        Args:
            new_cves: 新的CVE列表
            
        Returns:
            分类后的CVE列表
        """
        if not new_cves:
            print("\n没有新的CVE需要分类")
            return []
        
        print(f"\n{'='*70}")
        print(f"对新CVE进行分类")
        print(f"{'='*70}")
        print(f"待分类CVE数量: {len(new_cves)}")
        print(f"LLM提供商: {self.provider}")
        print(f"模型: {self.model}")
        print(f"{'='*70}")
        
        # 初始化LLM客户端
        if not self._init_llm_client():
            print("✗ LLM客户端初始化失败")
            return []
        
        classified_results = []
        
        for idx, cve_data in enumerate(new_cves, 1):
            cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
            print(f"\n[{idx}/{len(new_cves)}] 分类 {cve_id}...")
            
            # 创建提示词
            prompt = self._create_classification_prompt(cve_data)
            
            # 调用LLM
            llm_result = self._call_llm(prompt)
            
            if not llm_result:
                print(f"  ✗ 分类失败")
                self.stats['classification_failed'] += 1
                continue
            
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
            
            classified_results.append(result)
            self.stats['classification_successful'] += 1
            
            print(f"  ✓ 分类: {category}")
            print(f"  ✓ 总结: {result['summary'][:60]}...")
            
            # 避免API限流
            if self.provider in ["openai", "anthropic"]:
                time.sleep(self.rate_limit_delay)
        
        return classified_results
    
    def update_json_files(self, new_classified_cves: List[Dict]):
        """
        更新JSON文件
        
        Args:
            new_classified_cves: 新分类的CVE列表
        """
        if not new_classified_cves:
            print("\n没有新的分类数据需要更新")
            return
        
        print(f"\n{'='*70}")
        print(f"更新JSON文件")
        print(f"{'='*70}")
        
        # 更新完整分类数据
        self.existing_classified_data['classified_cves'].extend(new_classified_cves)
        self.existing_classified_data['metadata']['total_cves'] = len(
            self.existing_classified_data['classified_cves']
        )
        self.existing_classified_data['metadata']['classification_date'] = datetime.now().isoformat()
        self.existing_classified_data['metadata']['categories'] = self.categories
        
        # 更新统计信息
        stats = self.existing_classified_data['statistics']
        stats['total_processed'] = len(self.existing_classified_data['classified_cves'])
        stats['successful'] = stats['total_processed']
        
        # 按分类统计
        for cve in self.existing_classified_data['classified_cves']:
            category = cve['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0)
        
        # 重新统计分类
        stats['by_category'] = {}
        for cve in self.existing_classified_data['classified_cves']:
            category = cve['category']
            stats['by_category'][category] = stats['by_category'].get(category, 0) + 1
        
        # 保存完整分类数据
        with open(self.classified_file, 'w', encoding='utf-8') as f:
            json.dump(self.existing_classified_data, f, indent=4, ensure_ascii=False)
        print(f"✓ 已更新: {self.classified_file}")
        
        # 生成简化摘要版本（移除original_data）
        summary_data = {
            "metadata": self.existing_classified_data["metadata"].copy(),
            "statistics": self.existing_classified_data["statistics"].copy(),
            "classified_cves": [
                {k: v for k, v in cve.items() if k != "original_data"}
                for cve in self.existing_classified_data['classified_cves']
            ]
        }
        
        with open(self.summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary_data, f, indent=4, ensure_ascii=False)
        print(f"✓ 已更新: {self.summary_file}")
    
    def print_statistics(self):
        """打印统计信息"""
        print(f"\n{'='*70}")
        print(f"更新完成统计")
        print(f"{'='*70}")
        print(f"下载增量包: {self.stats['delta_downloaded']} 个")
        print(f"新发现RISC-V CVE: {self.stats['new_riscv_cves_found']} 个")
        print(f"扩展关键词候选: {self.stats['extended_candidates']} 个")
        print(f"扩展关键词LLM验证通过: {self.stats['extended_verified']} 个")
        print(f"扩展关键词LLM验证拒绝: {self.stats['extended_rejected']} 个")
        if self.stats["by_keyword"]:
            print(f"扩展关键词分布:")
            for kw, count in sorted(self.stats["by_keyword"].items()):
                print(f"    {kw}: {count}")
        print(f"分类成功: {self.stats['classification_successful']} 个")
        print(f"分类失败: {self.stats['classification_failed']} 个")
        print(f"新建分类: {self.stats['new_categories_created']} 个")
        
        print(f"\n当前分类分布:")
        print(f"{'-'*70}")
        stats = self.existing_classified_data.get('statistics', {})
        by_category = stats.get('by_category', {})
        total = stats.get('total_processed', 1)
        
        for category, count in sorted(by_category.items(), key=lambda x: x[1], reverse=True):
            percentage = (count / total * 100) if total > 0 else 0
            bar = "█" * (count // 2) if count > 1 else "▌"
            print(f"  {category:30s}: {count:3d} 个 ({percentage:5.1f}%) {bar}")
        
        print(f"{'='*70}")
    
    def run_update(self, download_delta: bool = True, delta_date: Optional[datetime] = None):
        """
        运行完整的更新流程
        
        Args:
            download_delta: 是否下载增量包
            delta_date: 增量包日期，默认为昨天
        """
        print(f"\n{'='*70}")
        print(f"RISC-V CVE增量更新")
        print(f"{'='*70}")
        print(f"当前时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"分类文件: {self.classified_file}")
        print(f"摘要文件: {self.summary_file}")
        print(f"已知CVE数量: {len(self.known_cve_ids)}")
        print(f"{'='*70}")
        
        # 1. 下载增量包
        zip_path = None
        if download_delta:
            zip_path = self.download_delta_cve_package(delta_date)
            if zip_path:
                # 2. 解压增量包
                self.extract_delta_package(zip_path)
                # 清理zip文件
                zip_path.unlink()
                print(f"✓ 已清理增量包: {zip_path}")
        
        # 3. 扫描新的RISC-V CVE
        new_riscv_cves = self.scan_for_new_riscv_cves()
        
        # 4. 验证扩展关键词候选CVE
        verified_extended_cves = self.verify_extended_candidates()
        
        # 合并所有新CVE
        all_new_cves = new_riscv_cves + verified_extended_cves
        
        if not all_new_cves:
            print("\n没有发现新的RISC-V CVE，无需更新")
            self.print_statistics()
            return
        
        # 5. 分类新CVE
        classified_cves = self.classify_new_cves(all_new_cves)
        
        # 6. 更新JSON文件
        self.update_json_files(classified_cves)
        
        # 7. 打印统计信息
        self.print_statistics()


def main():
    """主函数"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="RISC-V CVE增量更新脚本",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  # 下载昨天的增量包并更新
  python update_riscv_cves.py
  
  # 下载指定日期的增量包
  python update_riscv_cves.py --date 2025-11-16
  
  # 只扫描现有CVE目录，不下载增量包
  python update_riscv_cves.py --no-download
  
  # 指定LLM提供商
  python update_riscv_cves.py --provider openai --model gpt-4
        """
    )
    
    parser.add_argument(
        '--date',
        type=str,
        help='增量包日期 (格式: YYYY-MM-DD)，默认为昨天'
    )
    parser.add_argument(
        '--no-download',
        action='store_true',
        help='不下载增量包，只扫描现有CVE目录'
    )
    parser.add_argument(
        '--cves-dir',
        default='../cves',
        help='CVE数据库目录 (默认: ../cves)'
    )
    parser.add_argument(
        '--output-dir',
        default='../riscv_cves',
        help='RISC-V CVE输出目录 (默认: ../riscv_cves)'
    )
    parser.add_argument(
        '--classified-file',
        default='../riscv_cves_classified.json',
        help='分类后的完整JSON文件 (默认: ../riscv_cves_classified.json)'
    )
    parser.add_argument(
        '--summary-file',
        default='../riscv_cves_classified_summary.json',
        help='分类摘要JSON文件 (默认: ../riscv_cves_classified_summary.json)'
    )
    parser.add_argument(
        '--config',
        default='../llm_config.json',
        help='LLM配置文件路径 (默认: ../llm_config.json)'
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
    
    args = parser.parse_args()
    
    # 解析日期
    delta_date = None
    if args.date:
        try:
            delta_date = datetime.strptime(args.date, "%Y-%m-%d")
        except ValueError:
            print(f"✗ 日期格式错误: {args.date}，应为 YYYY-MM-DD")
            sys.exit(1)
    
    # 创建更新器
    updater = RISCVCVEUpdater(
        cves_dir=args.cves_dir,
        output_dir=args.output_dir,
        classified_file=args.classified_file,
        summary_file=args.summary_file,
        config_file=args.config,
        api_key=args.api_key,
        model=args.model,
        provider=args.provider
    )
    
    # 运行更新
    updater.run_update(
        download_delta=not args.no_download,
        delta_date=delta_date
    )


if __name__ == "__main__":
    main()
