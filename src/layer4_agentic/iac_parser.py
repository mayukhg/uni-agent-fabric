"""Infrastructure as Code (IaC) Parser for detecting security risks"""

import re
import os
import shutil
import tempfile
import subprocess
from typing import List, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

class IaCParser:
    """Parser for Infrastructure as Code files to detect security risks"""
    
    def __init__(self):
        self.logger = logger
        # Simple regex-based rules for demonstration
        # In a real system, this would use a proper HCL parser (like python-hcl2)
        self.rules = [
            {
                "id": "IAC-001",
                "name": "S3 Bucket Public Access Block Missing",
                "pattern": r'resource\s+"aws_s3_bucket"\s+"[^"]+"\s+\{',
                "check": "look_around", # simplified logic type
                "risk_score": 8,
                "description": "S3 bucket defined without explicit public access block"
            },
            {
                "id": "IAC-002",
                "name": "Security Group Open to World",
                "pattern": r'cidr_blocks\s*=\s*\["0.0.0.0/0"\]',
                "risk_score": 9,
                "description": "Security group allows ingress from 0.0.0.0/0"
            },
            {
                "id": "IAC-003",
                "name": "Unencrypted EBS Volume",
                "pattern": r'encrypted\s*=\s*false',
                "risk_score": 7,
                "description": "EBS volume is not encrypted"
            }
        ]

    def scan_repository(self, repo_url: str, branch: str = "main") -> List[Dict[str, Any]]:
        """
        Clone and scan a remote Git repository
        """
        temp_dir = tempfile.mkdtemp()
        try:
            self.logger.info("Cloning repository", repo=repo_url, branch=branch)
            subprocess.check_call(
                ["git", "clone", "--depth", "1", "--branch", branch, repo_url, temp_dir],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL
            )
            return self.parse_directory(temp_dir)
        except subprocess.CalledProcessError as e:
            self.logger.error("Failed to clone repository", repo=repo_url, error=str(e))
            return []
        except Exception as e:
            self.logger.error("Scan error", error=str(e))
            return []
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)

    def parse_directory(self, directory_path: str) -> List[Dict[str, Any]]:
        """
        Parse all supported IaC files in a directory
        
        Args:
            directory_path: Path to directory containing IaC files
            
        Returns:
            List of detected risks
        """
        risks = []
        if not os.path.exists(directory_path):
            self.logger.error("Directory not found", path=directory_path)
            return risks
            
        for root, _, files in os.walk(directory_path):
            for file in files:
                if file.endswith('.tf'):
                    file_path = os.path.join(root, file)
                    file_risks = self.parse_file(file_path)
                    risks.extend(file_risks)
                    
        self.logger.info("IaC scan completed", files_scanned=len(files), risks_found=len(risks))
        return risks

    def parse_file(self, file_path: str) -> List[Dict[str, Any]]:
        """
        Parse a single IaC file
        
        Args:
            file_path: Path to the file
            
        Returns:
            List of detected risks
        """
        risks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for rule in self.rules:
                if re.search(rule["pattern"], content):
                     # Very basic check - if pattern exists, trigger risk.
                     # Real implementation needs precise context (which resource block?)
                     risks.append({
                         "rule_id": rule["id"],
                         "name": rule["name"],
                         "file": os.path.basename(file_path),
                         "path": file_path,
                         "risk_score": rule["risk_score"],
                         "description": rule["description"],
                         "source": "iac_scanner"
                     })
                     
        except Exception as e:
            self.logger.error("Failed to parse file", file=file_path, error=str(e))
            
        return risks
