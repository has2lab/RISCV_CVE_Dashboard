#!/usr/bin/env python3
"""
Extract RISC-V related CVEs from the cves directory.
This script searches for various RISC-V keyword patterns and saves matching CVEs.
"""

import json
import os
import re
from pathlib import Path
from typing import Dict, List, Set
import sys


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
    
    def __init__(self, cves_dir: str = "cves", output_dir: str = "riscv_cves"):
        """
        Initialize the extractor.
        
        Args:
            cves_dir: Path to the CVEs directory
            output_dir: Path to save extracted RISC-V CVEs
        """
        self.cves_dir = Path(cves_dir)
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(exist_ok=True)
        
        # Compile regex patterns for efficiency
        self.compiled_patterns = [
            re.compile(pattern, re.IGNORECASE) for pattern in self.RISCV_PATTERNS
        ]
        
        self.matched_cves: List[Dict] = []
        self.matched_files: Set[str] = set()
        
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
    
    def extract_cve_from_file(self, file_path: Path) -> None:
        """
        Extract CVE data from a JSON file if it's RISC-V related.
        
        Args:
            file_path: Path to the CVE JSON file
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            # Quick check before parsing JSON
            if not self.is_riscv_related(content):
                return
            
            # Parse JSON
            cve_data = json.loads(content)
            
            # Store matched CVE
            cve_id = cve_data.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
            self.matched_cves.append(cve_data)
            self.matched_files.add(str(file_path))
            
            print(f"✓ Found RISC-V CVE: {cve_id}")
            
            # Save individual CVE file
            output_file = self.output_dir / f"{cve_id}.json"
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(cve_data, f, indent=4, ensure_ascii=False)
                
        except json.JSONDecodeError as e:
            print(f"✗ Error parsing JSON in {file_path}: {e}", file=sys.stderr)
        except Exception as e:
            print(f"✗ Error processing {file_path}: {e}", file=sys.stderr)
    
    def scan_directory(self) -> None:
        """Recursively scan the CVEs directory for RISC-V related CVEs."""
        print(f"Scanning {self.cves_dir} for RISC-V related CVEs...")
        print(f"Output directory: {self.output_dir}")
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
    
    def generate_summary(self) -> None:
        """Generate a summary report of extracted CVEs."""
        print("-" * 70)
        print(f"Extraction complete!")
        print(f"Total RISC-V related CVEs found: {len(self.matched_cves)}")
        
        # Save all CVEs in a single file
        all_cves_file = self.output_dir / "all_riscv_cves.json"
        with open(all_cves_file, 'w', encoding='utf-8') as f:
            json.dump(self.matched_cves, f, indent=4, ensure_ascii=False)
        print(f"All CVEs saved to: {all_cves_file}")
        
        # Generate summary report
        summary = {
            "total_cves": len(self.matched_cves),
            "extraction_date": None,  # Will be set when run
            "cve_ids": [
                cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                for cve in self.matched_cves
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
            f.write(f"Total RISC-V related CVEs found: {len(self.matched_cves)}\n\n")
            f.write("CVE IDs:\n")
            f.write("-" * 70 + "\n")
            for cve in self.matched_cves:
                cve_id = cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                state = cve.get('cveMetadata', {}).get('state', 'UNKNOWN')
                
                # Try to get description
                description = "No description available"
                containers = cve.get('containers', {})
                cna = containers.get('cna', {})
                descriptions = cna.get('descriptions', [])
                if descriptions:
                    description = descriptions[0].get('value', 'No description available')
                    # Truncate long descriptions
                    if len(description) > 200:
                        description = description[:200] + "..."
                
                f.write(f"\n{cve_id} [{state}]\n")
                f.write(f"  {description}\n")
        
        print(f"Detailed report saved to: {report_file}")
        print("-" * 70)
        
        # Print CVE IDs to console
        if self.matched_cves:
            print("\nFound CVE IDs:")
            for cve in self.matched_cves:
                cve_id = cve.get('cveMetadata', {}).get('cveId', 'UNKNOWN')
                print(f"  - {cve_id}")


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
    
    args = parser.parse_args()
    
    # Create extractor and run
    extractor = RISCVCVEExtractor(args.cves_dir, args.output_dir)
    extractor.scan_directory()
    extractor.generate_summary()


if __name__ == "__main__":
    main()
