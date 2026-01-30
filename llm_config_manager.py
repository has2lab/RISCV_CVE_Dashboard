#!/usr/bin/env python3
"""
LLM配置管理模块
负责读取和管理LLM API配置
仅支持JSON格式配置文件
"""

import os
import json
from pathlib import Path
from typing import Dict, Optional, Any, List


class LLMConfig:
    """LLM配置管理类"""
    
    def __init__(self, config_file: str = "llm_config.json"):
        """
        初始化配置管理器
        
        Args:
            config_file: 配置文件路径（JSON格式）
        """
        self.config_file = Path(config_file)
        self.config: Dict[str, Any] = {}
        self._load_config()
    
    def _load_config(self):
        """加载JSON配置文件"""
        if not self.config_file.exists():
            print(f"⚠️  配置文件不存在: {self.config_file}")
            print(f"⚠️  将使用默认配置")
            self._use_default_config()
            return
        
        try:
            with open(self.config_file, 'r', encoding='utf-8') as f:
                self.config = json.load(f) or {}
            print(f"✓ 已加载配置文件: {self.config_file}")
        except Exception as e:
            print(f"⚠️  配置文件加载失败: {e}")
            print(f"⚠️  将使用默认配置")
            self._use_default_config()
    
    def _use_default_config(self):
        """使用默认配置"""
        self.config = {
            "default": {
                "provider": "local",
                "model": "gpt-3.5-turbo"
            },
            "openai": {
                "api_key": "",
                "temperature": 0.3,
                "max_tokens": 1000,
                "timeout": 30,
                "rate_limit_delay": 0.5
            },
            "local": {
                "temperature": 0.3,
                "max_tokens": 1000
            },
            "classification": {
                "predefined_categories": [
                    "Linux Kernel",
                    "RISC-V CPU/SoC",
                    "Simulator",
                    "RISC-V Development Tools",
                    "Other"
                ],
                "allow_new_categories": True,
                "system_prompt": "You are a cybersecurity expert specializing in RISC-V architecture vulnerabilities."
            },
            "output": {
                "save_original_data": True,
                "generate_report": True,
                "generate_summary": True
            }
        }
    
    def get_default_provider(self) -> str:
        """获取默认提供商"""
        return self.config.get("default", {}).get("provider", "local")
    
    def get_default_model(self, provider: Optional[str] = None) -> str:
        """获取默认模型"""
        if provider is None:
            provider = self.get_default_provider()
        
        # 先尝试从default配置获取
        default_model = self.config.get("default", {}).get("model")
        if default_model:
            return default_model
        
        # 否则从对应提供商配置获取
        provider_config = self.config.get(provider, {})
        return provider_config.get("default_model", "gpt-3.5-turbo")
    
    def get_api_key(self, provider: str) -> Optional[str]:
        """
        获取API密钥
        优先从配置文件读取，如果为空则从环境变量读取
        
        Args:
            provider: 提供商名称
            
        Returns:
            API密钥
        """
        provider_config = self.config.get(provider, {})
        api_key = provider_config.get("api_key", "")
        
        if not api_key:
            # 从环境变量读取
            env_var_map = {
                "openai": "OPENAI_API_KEY",
                "anthropic": "ANTHROPIC_API_KEY"
            }
            env_var = env_var_map.get(provider)
            if env_var:
                api_key = os.getenv(env_var, "")
        
        return api_key if api_key else None
    
    def get_base_url(self, provider: str) -> Optional[str]:
        """获取API基础URL"""
        provider_config = self.config.get(provider, {})
        return provider_config.get("base_url")
    
    def get_temperature(self, provider: str) -> float:
        """获取温度参数"""
        provider_config = self.config.get(provider, {})
        return provider_config.get("temperature", 0.3)
    
    def get_max_tokens(self, provider: str) -> int:
        """获取最大token数"""
        provider_config = self.config.get(provider, {})
        return provider_config.get("max_tokens", 1000)
    
    def get_timeout(self, provider: str) -> int:
        """获取超时时间"""
        provider_config = self.config.get(provider, {})
        return provider_config.get("timeout", 30)
    
    def get_rate_limit_delay(self, provider: str) -> float:
        """获取请求延迟"""
        provider_config = self.config.get(provider, {})
        return provider_config.get("rate_limit_delay", 0.5)
    
    def get_predefined_categories(self) -> list:
        """获取预定义分类"""
        classification_config = self.config.get("classification", {})
        return classification_config.get("predefined_categories", [
            "Linux Kernel",
            "RISC-V CPU/SoC",
            "Simulator",
            "RISC-V Development Tools",
            "Other"
        ])
    
    def allow_new_categories(self) -> bool:
        """是否允许创建新分类"""
        classification_config = self.config.get("classification", {})
        return classification_config.get("allow_new_categories", True)
    
    def get_system_prompt(self) -> str:
        """获取系统提示词"""
        classification_config = self.config.get("classification", {})
        return classification_config.get(
            "system_prompt",
            "You are a cybersecurity expert specializing in RISC-V architecture vulnerabilities."
        )
    
    def should_save_original_data(self) -> bool:
        """是否保存原始数据"""
        output_config = self.config.get("output", {})
        return output_config.get("save_original_data", True)
    
    def should_generate_report(self) -> bool:
        """是否生成报告"""
        output_config = self.config.get("output", {})
        return output_config.get("generate_report", True)
    
    def should_generate_summary(self) -> bool:
        """是否生成摘要"""
        output_config = self.config.get("output", {})
        return output_config.get("generate_summary", True)
    
    # ========== Embedding Configuration ==========
    
    def get_embedding_config(self) -> Dict[str, Any]:
        """获取嵌入模型配置"""
        return self.config.get("embedding", {})
    
    def get_embedding_api_key(self) -> Optional[str]:
        """获取嵌入模型API密钥"""
        embedding_config = self.config.get("embedding", {})
        api_key = embedding_config.get("api_key", "")
        if not api_key:
            env_var = embedding_config.get("env_var", "DASHSCOPE_API_KEY")
            api_key = os.getenv(env_var, "")
        return api_key if api_key else None
    
    def get_embedding_model(self) -> str:
        """获取嵌入模型名称"""
        return self.config.get("embedding", {}).get("model", "text-embedding-v4")
    
    def get_embedding_base_url(self) -> str:
        """获取嵌入模型API地址"""
        return self.config.get("embedding", {}).get(
            "base_url", "https://dashscope.aliyuncs.com/compatible-mode/v1"
        )
    
    # ========== Verification Configuration ==========
    
    def get_verification_config(self) -> Dict[str, Any]:
        """获取验证配置"""
        return self.config.get("verification", {})
    
    def get_max_cves_per_batch(self) -> int:
        """获取每批次最大CVE数量"""
        return self.config.get("verification", {}).get("max_cves_per_batch", 5)
    
    def get_clustering_method(self) -> str:
        """获取聚类方法"""
        return self.config.get("verification", {}).get("clustering_method", "hdbscan")
    
    def get_min_cluster_size(self) -> int:
        """获取最小聚类大小"""
        return self.config.get("verification", {}).get("min_cluster_size", 3)
    
    def get_max_retries(self) -> int:
        """获取最大重试次数"""
        return self.config.get("verification", {}).get("max_retries", 5)
    
    def get_retry_config(self) -> Dict[str, float]:
        """获取重试配置"""
        verification = self.config.get("verification", {})
        return {
            "max_retries": verification.get("max_retries", 5),
            "initial_delay": verification.get("initial_retry_delay", 1.0),
            "max_delay": verification.get("max_retry_delay", 60.0),
            "multiplier": verification.get("retry_multiplier", 2.0)
        }
    
    def get_verification_system_prompt(self) -> str:
        """获取验证系统提示词"""
        return self.config.get("verification", {}).get(
            "system_prompt",
            "You are a cybersecurity expert specializing in RISC-V architecture."
        )
    
    def get_riscv_criteria(self) -> List[str]:
        """获取RISC-V相关性判断标准"""
        return self.config.get("verification", {}).get("riscv_criteria", [
            "RISC-V处理器", "RISC-V SoC", "RISC-V指令集", "RISC-V模拟器",
            "RISC-V漏洞", "RISC-V开发工具", "RISC-V固件或应用"
        ])
    
    def get_provider_config(self, provider: str) -> Dict[str, Any]:
        """
        获取完整的提供商配置
        
        Args:
            provider: 提供商名称
            
        Returns:
            提供商配置字典
        """
        return {
            "provider": provider,
            "model": self.get_default_model(provider),
            "api_key": self.get_api_key(provider),
            "base_url": self.get_base_url(provider),
            "temperature": self.get_temperature(provider),
            "max_tokens": self.get_max_tokens(provider),
            "timeout": self.get_timeout(provider),
            "rate_limit_delay": self.get_rate_limit_delay(provider)
        }
    
    def print_config_summary(self):
        """打印配置摘要"""
        print("\n" + "=" * 70)
        print("LLM 配置摘要")
        print("=" * 70)
        
        default_provider = self.get_default_provider()
        print(f"默认提供商: {default_provider}")
        print(f"默认模型: {self.get_default_model()}")
        
        print("\n提供商配置:")
        for provider in ["openai", "anthropic", "local", "custom"]:
            if provider in self.config:
                print(f"\n  [{provider}]")
                api_key = self.get_api_key(provider)
                if api_key:
                    masked_key = api_key[:8] + "..." if len(api_key) > 8 else "***"
                    print(f"    API密钥: {masked_key}")
                else:
                    print(f"    API密钥: 未配置")
                
                base_url = self.get_base_url(provider)
                if base_url:
                    print(f"    Base URL: {base_url}")
                
                print(f"    Temperature: {self.get_temperature(provider)}")
                print(f"    Max Tokens: {self.get_max_tokens(provider)}")
        
        print("\n分类配置:")
        print(f"  预定义分类: {len(self.get_predefined_categories())} 个")
        print(f"  允许新分类: {self.allow_new_categories()}")
        
        print("\n输出配置:")
        print(f"  保存原始数据: {self.should_save_original_data()}")
        print(f"  生成报告: {self.should_generate_report()}")
        print(f"  生成摘要: {self.should_generate_summary()}")
        
        print("=" * 70)


def create_sample_config(output_file: str = "llm_config.json"):
    """
    创建示例配置文件（JSON格式）
    
    Args:
        output_file: 输出文件路径
    """
    sample_config = {
        "default": {
            "provider": "local",
            "model": "gpt-3.5-turbo"
        },
        "openai": {
            "api_key": "",
            "base_url": "",
            "models": ["gpt-3.5-turbo", "gpt-4", "gpt-4-turbo"],
            "default_model": "gpt-3.5-turbo",
            "temperature": 0.3,
            "max_tokens": 1000,
            "timeout": 30,
            "rate_limit_delay": 0.5
        },
        "anthropic": {
            "api_key": "",
            "models": [
                "claude-3-opus-20240229",
                "claude-3-sonnet-20240229",
                "claude-3-haiku-20240307"
            ],
            "default_model": "claude-3-sonnet-20240229",
            "max_tokens": 1000,
            "timeout": 30,
            "rate_limit_delay": 0.5
        },
        "local": {
            "base_url": "http://localhost:11434",
            "models": ["llama2", "mistral", "qwen"],
            "default_model": "llama2",
            "temperature": 0.3,
            "max_tokens": 1000,
            "timeout": 60
        },
        "classification": {
            "predefined_categories": [
                "Linux Kernel",
                "RISC-V CPU/SoC",
                "Simulator",
                "RISC-V Development Tools",
                "Other"
            ],
            "allow_new_categories": True,
            "system_prompt": "You are a cybersecurity expert specializing in RISC-V architecture vulnerabilities."
        },
        "output": {
            "save_original_data": True,
            "generate_report": True,
            "generate_summary": True
        }
    }
    
    output_path = Path(output_file)
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(sample_config, f, indent=2, ensure_ascii=False)
    
    print(f"✓ 示例配置文件已创建: {output_path}")


if __name__ == "__main__":
    # 测试配置加载
    config = LLMConfig()
    config.print_config_summary()
