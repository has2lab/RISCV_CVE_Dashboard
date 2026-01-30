#!/usr/bin/env python3
"""
Extract RISC-V related CVEs from the cves directory.
This script searches for various RISC-V keyword patterns and saves matching CVEs.

Extended features:
- Additional keyword matching (BOOM, rocket, XiangShan, opentitan, Spike, NEMU)
- HDBSCAN clustering for candidate CVEs
- LLM verification for RISC-V relevance
- Exponential backoff retry for API calls
"""

import json
import os
import re
import time
from pathlib import Path
from typing import Dict, List, Set, Optional, Tuple, Any
from datetime import datetime
import sys

# Optional dependencies for extended features
try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False

try:
    import hdbscan
    HDBSCAN_AVAILABLE = True
except ImportError:
    HDBSCAN_AVAILABLE = False

try:
    from sklearn.cluster import DBSCAN
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False


class EmbeddingClient:
    """Embedding client for Alibaba Cloud DashScope (Bailian)."""
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize embedding client.
        
        Args:
            config: Embedding configuration from llm_config.json
        """
        self.api_key = config.get("api_key") or os.getenv(config.get("env_var", "DASHSCOPE_API_KEY"), "")
        self.base_url = config.get("base_url", "https://dashscope.aliyuncs.com/compatible-mode/v1")
        self.model = config.get("model", "text-embedding-v4")
        self.dimensions = config.get("dimensions", 1024)
        self.batch_size = min(config.get("batch_size", 10), 10)  # DashScope API limit is 10
        self.timeout = config.get("timeout", 60)
        
        if not self.api_key:
            raise ValueError("Embedding API key not configured. Set DASHSCOPE_API_KEY or configure in llm_config.json")
    
    def get_embeddings(self, texts: List[str]) -> Optional[np.ndarray]:
        """
        Get embeddings for a list of texts.
        
        Args:
            texts: List of text strings to embed
            
        Returns:
            numpy array of embeddings, or None if failed
        """
        if not NUMPY_AVAILABLE:
            print("⚠️  NumPy not available, cannot compute embeddings")
            return None
            
        try:
            from openai import OpenAI
            client = OpenAI(api_key=self.api_key, base_url=self.base_url)
            
            all_embeddings = []
            for i in range(0, len(texts), self.batch_size):
                batch = texts[i:i + self.batch_size]
                response = client.embeddings.create(
                    model=self.model,
                    input=batch,
                    dimensions=self.dimensions
                )
                batch_embeddings = [item.embedding for item in response.data]
                all_embeddings.extend(batch_embeddings)
                
                if i + self.batch_size < len(texts):
                    time.sleep(0.5)  # Rate limit between batches
            
            return np.array(all_embeddings)
            
        except Exception as e:
            print(f"⚠️  Embedding API call failed: {e}")
            return None


class LLMVerifier:
    """LLM client for verifying RISC-V relevance with retry logic."""
    
    def __init__(self, config: Dict[str, Any], verification_config: Dict[str, Any]):
        """
        Initialize LLM verifier.
        
        Args:
            config: LLM provider configuration
            verification_config: Verification-specific configuration
        """
        self.provider = config.get("provider", "openai")
        self.api_key = config.get("api_key", "")
        self.base_url = config.get("base_url", "")
        self.model = config.get("model", "deepseek-chat")
        self.temperature = config.get("temperature", 0.3)
        self.max_tokens = config.get("max_tokens", 1000)
        self.timeout = config.get("timeout", 60)
        
        # Retry configuration
        self.max_retries = verification_config.get("max_retries", 5)
        self.initial_retry_delay = verification_config.get("initial_retry_delay", 1.0)
        self.max_retry_delay = verification_config.get("max_retry_delay", 60.0)
        self.retry_multiplier = verification_config.get("retry_multiplier", 2.0)
        
        # Verification configuration
        self.system_prompt = verification_config.get("system_prompt", 
            "You are a cybersecurity expert specializing in RISC-V architecture.")
        self.riscv_criteria = verification_config.get("riscv_criteria", [
            "RISC-V processor", "RISC-V SoC", "RISC-V instruction set", "RISC-V simulator",
            "RISC-V vulnerabilities", "RISC-V development tools", "RISC-V firmware or applications"
        ])
        
        self.client = None
        self._init_client()
    
    def _init_client(self):
        """Initialize LLM client."""
        if self.provider == "openai":
            try:
                from openai import OpenAI
                if self.base_url:
                    self.client = OpenAI(api_key=self.api_key, base_url=self.base_url)
                else:
                    self.client = OpenAI(api_key=self.api_key)
            except ImportError:
                print("⚠️  OpenAI library not installed")
        elif self.provider == "anthropic":
            try:
                import anthropic
                self.client = anthropic.Anthropic(api_key=self.api_key)
            except ImportError:
                print("⚠️  Anthropic library not installed")
    
    def _call_with_retry(self, prompt: str) -> Optional[str]:
        """
        Call LLM API with exponential backoff retry.
        
        Args:
            prompt: The prompt to send
            
        Returns:
            Response content or None if all retries failed
        """
        delay = self.initial_retry_delay
        
        for attempt in range(self.max_retries):
            try:
                if self.provider == "openai" and self.client:
                    response = self.client.chat.completions.create(
                        model=self.model,
                        messages=[
                            {"role": "system", "content": self.system_prompt},
                            {"role": "user", "content": prompt}
                        ],
                        temperature=self.temperature,
                        max_tokens=self.max_tokens,
                        timeout=self.timeout
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
                    print(f"  ⚠️  API call failed (attempt {attempt + 1}/{self.max_retries}): {e}")
                    print(f"  ⏳ Retrying in {delay:.1f}s...")
                    time.sleep(delay)
                    delay = min(delay * self.retry_multiplier, self.max_retry_delay)
                else:
                    print(f"  ✗ API call failed after {attempt + 1} attempts: {e}")
                    return None
        
        return None
    
    def verify_batch(self, cves: List[Dict]) -> List[Tuple[str, bool, str]]:
        """
        Verify a batch of CVEs for RISC-V relevance.
        
        Args:
            cves: List of CVE data dictionaries (max 5)
            
        Returns:
            List of tuples: (cve_id, is_riscv_related, reason)
        """
        if not self.client:
            print("⚠️  LLM client not initialized, skipping verification")
            return [(cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN'), False, "No LLM") for cve in cves]
        
        # Build prompt with CVE information
        criteria_str = "、".join(self.riscv_criteria)
        cve_info_list = []
        
        for cve in cves:
            cve_id = cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
            description = self._get_description(cve)
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

Please judge carefully. If the CVE is clearly related to other technologies (such as unrelated software with the same name), it should be marked as not related."""

        response = self._call_with_retry(prompt)
        
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
                print(f"  ✗ Failed to parse LLM response: {e}")
        
        # Return default (not related) for all CVEs if parsing failed
        return [(cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN'), False, "Parse failed") for cve in cves]
    
    def _get_description(self, cve: Dict) -> str:
        """Extract description from CVE data."""
        containers = cve.get('containers', {})
        cna = containers.get('cna', {})
        descriptions = cna.get('descriptions', [])
        if descriptions:
            return descriptions[0].get('value', 'No description available')
        return 'No description available'


class RISCVCVEExtractor:
    """Extract RISC-V related CVEs from CVE database."""
    
    # Various ways RISC-V might be written
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
    ]
    
    def __init__(self, cves_dir: str = "cves", output_dir: str = "riscv_cves",
                 config_file: str = "llm_config.json", enable_extended: bool = True):
        """
        Initialize the extractor.
        
        Args:
            cves_dir: Path to the CVEs directory
            output_dir: Path to save extracted RISC-V CVEs
            config_file: Path to LLM configuration file
            enable_extended: Enable extended keyword matching with LLM verification
        """
        self.cves_dir = Path(cves_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        self.config_file = Path(config_file)
        self.enable_extended = enable_extended
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.RISCV_PATTERNS
        ]
        self.compiled_extended = [
            (re.compile(pattern, re.IGNORECASE), name) 
            for pattern, name in self.EXTENDED_KEYWORDS
        ]
        
        # Results storage
        self.matched_cves: List[Dict] = []
        self.matched_files: Set[str] = set()
        self.direct_match_ids: Set[str] = set()  # CVE IDs matched by RISC-V patterns
        
        # Extended matching results
        self.extended_candidates: Dict[str, Dict] = {}  # cve_id -> cve_data
        self.extended_match_keywords: Dict[str, Set[str]] = {}  # cve_id -> matched keywords
        self.verified_extended_cves: List[Dict] = []  # LLM-verified extended CVEs
        
        # Statistics
        self.stats = {
            "direct_match": 0,
            "extended_candidates": 0,
            "extended_verified": 0,
            "extended_rejected": 0,
            "by_keyword": {}
        }
        
        # Load configuration
        self.config = self._load_config()
        
        # Initialize LLM components if extended matching is enabled
        self.embedding_client = None
        self.llm_verifier = None
        if self.enable_extended:
            self._init_llm_components()
    
    def _load_config(self) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        if self.config_file.exists():
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception as e:
                print(f"⚠️  Failed to load config: {e}")
        return {}
    
    def _init_llm_components(self):
        """Initialize embedding client and LLM verifier."""
        # Initialize embedding client
        embedding_config = self.config.get("embedding", {})
        if embedding_config.get("api_key") or os.getenv(embedding_config.get("env_var", "")):
            try:
                self.embedding_client = EmbeddingClient(embedding_config)
                print("✓ Embedding client initialized (DashScope)")
            except Exception as e:
                print(f"⚠️  Failed to initialize embedding client: {e}")
        else:
            print("⚠️  Embedding API key not configured, clustering will use fallback method")
        
        # Initialize LLM verifier
        provider = self.config.get("default", {}).get("provider", "openai")
        provider_config = self.config.get(provider, {})
        verification_config = self.config.get("verification", {})
        
        # Build LLM config
        llm_config = {
            "provider": provider,
            "api_key": provider_config.get("api_key") or os.getenv(
                {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY"}.get(provider, ""), ""
            ),
            "base_url": provider_config.get("base_url", ""),
            "model": self.config.get("default", {}).get("model") or provider_config.get("default_model", ""),
            "temperature": provider_config.get("temperature", 0.3),
            "max_tokens": provider_config.get("max_tokens", 1000),
            "timeout": provider_config.get("timeout", 60)
        }
        
        if llm_config["api_key"]:
            self.llm_verifier = LLMVerifier(llm_config, verification_config)
            print(f"✓ LLM verifier initialized ({provider}, {llm_config['model']})")
        else:
            print("⚠️  LLM API key not configured, extended verification will be skipped")
        
    def is_riscv_related(self, content: str) -> bool:
        """
        Check if the content contains RISC-V related keywords.
        
        Args:
            content: String content to check
            
        Returns:
            True if RISC-V related, False otherwise
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
    
    def extract_cve_from_file(self, file_path: Path) -> None:
        """
        Extract CVE data from a JSON file if it's RISC-V related.
        Also collects extended keyword candidates.
        
        Args:
            file_path: Path to the CVE JSON file
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            # Check for direct RISC-V match first
            is_direct_match = self.is_riscv_related(content)
            
            # Check for extended keywords
            extended_matches = self.check_extended_keywords(content) if self.enable_extended else set()
            
            if not is_direct_match and not extended_matches:
                return
            
            # Parse JSON
            cve_data = json.loads(content)
            cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
            
            if is_direct_match:
                # Direct RISC-V match - add immediately
                self.matched_cves.append(cve_data)
                self.matched_files.add(str(file_path))
                self.direct_match_ids.add(cve_id)
                self.stats["direct_match"] += 1
                print(f"✓ Found RISC-V CVE: {cve_id}")
                
                # Save individual CVE file
                output_file = self.output_dir / f"{cve_id}.json"
                with open(output_file, 'w', encoding='utf-8') as f:
                    json.dump(cve_data, f, indent=4, ensure_ascii=False)
                    
            elif extended_matches and cve_id not in self.direct_match_ids:
                # Extended keyword match - add to candidates for verification
                self.extended_candidates[cve_id] = cve_data
                if cve_id not in self.extended_match_keywords:
                    self.extended_match_keywords[cve_id] = set()
                self.extended_match_keywords[cve_id].update(extended_matches)
                
                # Update keyword statistics
                for kw in extended_matches:
                    self.stats["by_keyword"][kw] = self.stats["by_keyword"].get(kw, 0) + 1
                
        except json.JSONDecodeError as e:
            print(f"✗ Error parsing JSON in {file_path}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"✗ Error processing {file_path}: {e}", file=sys.stderr)
    
    def scan_directory(self) -> None:
        """Recursively scan the CVEs directory for RISC-V related CVEs."""
        print(f"Scanning {self.cves_dir} for RISC-V related CVEs...")
        print(f"Output directory: {self.output_dir}")
        print(f"Extended keyword matching: {'Enabled' if self.enable_extended else 'Disabled'}")
        print("-" * 70)
        
        # Find all JSON files
        json_files = list(self.cves_dir.rglob("*.json"))
        total_files = len(json_files)
        
        print(f"Total CVE files to scan: {total_files}")
        print("-" * 70)
        
        # Process each file
        for idx, file_path in enumerate(json_files, 1):
            if idx % 1000 == 0:
                print(f"Progress: {idx}/{total_files} files scanned...")
            self.extract_cve_from_file(file_path)
        
        # Process extended candidates if enabled
        if self.enable_extended and self.extended_candidates:
            print("-" * 70)
            self.stats["extended_candidates"] = len(self.extended_candidates)
            print(f"Extended keyword candidates: {len(self.extended_candidates)}")
            self._process_extended_candidates()
    
    def _process_extended_candidates(self) -> None:
        """Process extended keyword candidates with clustering and LLM verification."""
        if not self.extended_candidates:
            return
        
        candidates = list(self.extended_candidates.values())
        cve_ids = list(self.extended_candidates.keys())
        
        print(f"\nProcessing {len(candidates)} extended keyword candidates...")
        
        # Decide processing strategy based on count
        if len(candidates) <= 50:
            # Small dataset - verify directly in batches
            print("Using direct batch verification (≤50 candidates)")
            self._verify_candidates_in_batches(candidates)
        else:
            # Large dataset - cluster first, then verify
            print("Using clustering + verification (>50 candidates)")
            self._cluster_and_verify(candidates, cve_ids)
    
    def _cluster_and_verify(self, candidates: List[Dict], cve_ids: List[str]) -> None:
        """Cluster candidates and verify each cluster."""
        # Get descriptions for embedding
        descriptions = [self._get_cve_description(cve) for cve in candidates]
        
        # Try to get embeddings
        embeddings = None
        if self.embedding_client and NUMPY_AVAILABLE:
            print("Computing embeddings...")
            embeddings = self.embedding_client.get_embeddings(descriptions)
        
        if embeddings is not None:
            # Use HDBSCAN for clustering (no predefined cluster count)
            clusters = self._hdbscan_cluster(embeddings)
        else:
            # Fallback: cluster by matched keywords
            print("⚠️  Using keyword-based clustering (embedding unavailable)")
            clusters = self._keyword_cluster(cve_ids)
        
        # Process each cluster
        unique_clusters = set(clusters)
        print(f"Found {len([c for c in unique_clusters if c >= 0])} clusters + noise points")
        
        cluster_cves: Dict[int, List[Dict]] = {}
        for idx, cluster_id in enumerate(clusters):
            if cluster_id not in cluster_cves:
                cluster_cves[cluster_id] = []
            cluster_cves[cluster_id].append(candidates[idx])
        
        # Verify each cluster
        for cluster_id, cves in cluster_cves.items():
            cluster_name = f"Cluster {cluster_id}" if cluster_id >= 0 else "Noise"
            print(f"\n{cluster_name}: {len(cves)} CVEs")
            self._verify_candidates_in_batches(cves)
    
    def _hdbscan_cluster(self, embeddings: np.ndarray) -> List[int]:
        """Cluster embeddings using HDBSCAN."""
        if HDBSCAN_AVAILABLE:
            min_cluster_size = self.config.get("verification", {}).get("min_cluster_size", 3)
            clusterer = hdbscan.HDBSCAN(
                min_cluster_size=min_cluster_size,
                metric='cosine',
                cluster_selection_method='eom'
            )
            clusters = clusterer.fit_predict(embeddings)
            return clusters.tolist()
        elif SKLEARN_AVAILABLE:
            # Fallback to DBSCAN
            print("⚠️  HDBSCAN unavailable, using DBSCAN")
            clusterer = DBSCAN(eps=0.3, min_samples=3, metric='cosine')
            clusters = clusterer.fit_predict(embeddings)
            return clusters.tolist()
        else:
            # No clustering available
            print("⚠️  No clustering library available")
            return [0] * len(embeddings)
    
    def _keyword_cluster(self, cve_ids: List[str]) -> List[int]:
        """Cluster by matched keywords (fallback method)."""
        keyword_to_cluster = {}
        clusters = []
        
        for cve_id in cve_ids:
            keywords = self.extended_match_keywords.get(cve_id, set())
            # Use first keyword as cluster key
            key = sorted(keywords)[0] if keywords else "other"
            if key not in keyword_to_cluster:
                keyword_to_cluster[key] = len(keyword_to_cluster)
            clusters.append(keyword_to_cluster[key])
        
        return clusters
    
    def _verify_candidates_in_batches(self, candidates: List[Dict]) -> None:
        """Verify candidates in batches of 5."""
        if not self.llm_verifier:
            print("⚠️  LLM verifier not available, skipping verification")
            return
        
        max_batch_size = self.config.get("verification", {}).get("max_cves_per_batch", 5)
        rate_limit_delay = self.config.get(
            self.config.get("default", {}).get("provider", "openai"), {}
        ).get("rate_limit_delay", 1.0)
        
        total = len(candidates)
        verified_count = 0
        rejected_count = 0
        
        for i in range(0, total, max_batch_size):
            batch = candidates[i:i + max_batch_size]
            batch_num = i // max_batch_size + 1
            total_batches = (total + max_batch_size - 1) // max_batch_size
            
            print(f"  Verifying batch {batch_num}/{total_batches}...")
            
            results = self.llm_verifier.verify_batch(batch)
            
            for cve, (cve_id, is_related, reason) in zip(batch, results):
                if is_related:
                    self.verified_extended_cves.append(cve)
                    self.matched_cves.append(cve)
                    verified_count += 1
                    print(f"    ✓ {cve_id}: RISC-V related - {reason}")
                    
                    # Save individual CVE file
                    output_file = self.output_dir / f"{cve_id}.json"
                    with open(output_file, 'w', encoding='utf-8') as f:
                        json.dump(cve, f, indent=4, ensure_ascii=False)
                else:
                    rejected_count += 1
                    print(f"    ✗ {cve_id}: Not related - {reason}")
            
            # Rate limit between batches
            if i + max_batch_size < total:
                time.sleep(rate_limit_delay)
        
        self.stats["extended_verified"] += verified_count
        self.stats["extended_rejected"] += rejected_count
        print(f"  Batch complete: {verified_count} verified, {rejected_count} rejected")
    
    def generate_summary(self) -> None:
        """Generate a summary report of extracted CVEs."""
        print("-" * 70)
        print(f"Extraction complete!")
        print(f"Total RISC-V related CVEs found: {len(self.matched_cves)}")
        print(f"  - Direct RISC-V matches: {self.stats['direct_match']}")
        if self.enable_extended:
            print(f"  - Extended keyword candidates: {self.stats['extended_candidates']}")
            print(f"  - LLM verified: {self.stats['extended_verified']}")
            print(f"  - LLM rejected: {self.stats['extended_rejected']}")
            if self.stats["by_keyword"]:
                print(f"  - By keyword:")
                for kw, count in sorted(self.stats["by_keyword"].items()):
                    print(f"      {kw}: {count}")
        
        # Save all CVEs in a single file
        all_cves_file = self.output_dir / "all_riscv_cves.json"
        with open(all_cves_file, 'w', encoding='utf-8') as f:
            json.dump(self.matched_cves, f, indent=4, ensure_ascii=False)
        print(f"All CVEs saved to: {all_cves_file}")
        
        # Generate summary report
        summary = {
            "total_cves": len(self.matched_cves),
            "extraction_date": datetime.now().isoformat(),
            "statistics": {
                "direct_match": self.stats["direct_match"],
                "extended_candidates": self.stats["extended_candidates"],
                "extended_verified": self.stats["extended_verified"],
                "extended_rejected": self.stats["extended_rejected"],
                "by_keyword": self.stats["by_keyword"]
            },
            "cve_ids": [
                cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                for cve in self.matched_cves
            ],
            "direct_match_ids": list(self.direct_match_ids),
            "extended_verified_ids": [
                cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                for cve in self.verified_extended_cves
            ],
            "files_processed": list(self.matched_files)
        }
        
        summary_file = self.output_dir / "summary.json"
        with open(summary_file, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=4, ensure_ascii=False)
        print(f"Summary saved to: {summary_file}")
        
        # Generate human-readable report
        report_file = self.output_dir / "report.txt"
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write("RISC-V CVE Extraction Report\n")
            f.write("=" * 70 + "\n\n")
            f.write(f"Extraction Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total RISC-V related CVEs found: {len(self.matched_cves)}\n\n")
            
            f.write("Statistics:\n")
            f.write("-" * 70 + "\n")
            f.write(f"  Direct RISC-V matches: {self.stats['direct_match']}\n")
            if self.enable_extended:
                f.write(f"  Extended keyword candidates: {self.stats['extended_candidates']}\n")
                f.write(f"  LLM verified: {self.stats['extended_verified']}\n")
                f.write(f"  LLM rejected: {self.stats['extended_rejected']}\n")
                if self.stats["by_keyword"]:
                    f.write(f"  By keyword:\n")
                    for kw, count in sorted(self.stats["by_keyword"].items()):
                        f.write(f"    {kw}: {count}\n")
            
            f.write("\nCVE IDs:\n")
            f.write("-" * 70 + "\n")
            for cve in self.matched_cves:
                cve_id = cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                state = cve.get('cveMetadata', {}).get('state', 'UNKNOWN')
                source = "direct" if cve_id in self.direct_match_ids else "extended"
                
                # Try to get description
                description = self._get_cve_description(cve)
                if not description:
                    description = "No description available"
                # Truncate long descriptions
                if len(description) > 200:
                    description = description[:200] + "..."
                
                f.write(f"\n{cve_id} [{state}] ({source})\n")
                f.write(f"  {description}\n")
        
        print(f"Detailed report saved to: {report_file}")
        print("-" * 70)
        
        # Print CVE IDs to console
        if self.matched_cves:
            print("\nFound CVE IDs:")
            for cve in self.matched_cves:
                cve_id = cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                source = "direct" if cve_id in self.direct_match_ids else "extended"
                print(f"  - {cve_id} ({source})")


def main():
    """Main entry point."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="Extract RISC-V related CVEs from CVE database"
    )
    parser.add_argument(
        '--cves-dir',
        default='cves',
        help='Path to the CVEs directory (default: cves)'
    )
    parser.add_argument(
        '--output-dir',
        default='riscv_cves',
        help='Path to save extracted RISC-V CVEs (default: riscv_cves)'
    )
    parser.add_argument(
        '--config',
        default='llm_config.json',
        help='Path to LLM configuration file (default: llm_config.json)'
    )
    parser.add_argument(
        '--no-extended',
        action='store_true',
        help='Disable extended keyword matching (BOOM, rocket, XiangShan, etc.)'
    )
    parser.add_argument(
        '--extended-only',
        action='store_true',
        help='Only process extended keywords (skip direct RISC-V matching for testing)'
    )
    
    args = parser.parse_args()
    
    # Create extractor and run
    extractor = RISCVCVEExtractor(
        args.cves_dir, 
        args.output_dir,
        config_file=args.config,
        enable_extended=not args.no_extended
    )
    extractor.scan_directory()
    extractor.generate_summary()


if __name__ == "__main__":
    main()
