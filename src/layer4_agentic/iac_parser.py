"""Infrastructure as Code (IaC) Parser for detecting security risks"""

import re
import os
import shutil
import tempfile
import subprocess
from typing import List, Dict, Any
import structlog
import yaml
import json
from pathlib import Path

logger = structlog.get_logger(__name__)

class IaCParser:
    """
    Scanner for detecting security risks in Infrastructure as Code (IaC) files.
    
    Supports:
    - Terraform (.tf): Detected via regex patterns (fallback mode).
    - CloudFormation (.yaml/.json): Parsed as objects with rule-based checks.
    
    Can scan local directories or clone remote Git repositories.
    """
    
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
            },
            {
                "id": "IAC-003",
                "name": "Unencrypted EBS Volume",
                "pattern": r'encrypted\s*=\s*false',
                "risk_score": 7,
                "description": "EBS volume is not encrypted"
            }
        ]
        
        # CloudFormation Rules (Path-based or simple dict check)
        self.cfn_rules = [
             {
                "id": "IAC-CFN-001",
                "name": "Security Group Open to World",
                "resource_type": "AWS::EC2::SecurityGroup",
                "check": lambda r: any(
                    ingress.get("CidrIp") == "0.0.0.0/0" 
                    for ingress in r.get("Properties", {}).get("SecurityGroupIngress", [])
                    if isinstance(ingress, dict)
                ),
                "risk_score": 9,
                "description": "Security group allows ingress from 0.0.0.0/0"
             },
             {
                "id": "IAC-CFN-002",
                "name": "Unencrypted S3 Bucket",
                "resource_type": "AWS::S3::Bucket",
                "check": lambda r: not r.get("Properties", {}).get("BucketEncryption"),
                "risk_score": 6,
                "description": "S3 bucket encryption not enabled"
             }
        ]

    def scan_repository(self, repo_url: str, branch: str = "main") -> List[Dict[str, Any]]:
        """
        Clone a remote Git repository to a temporary directory and scan it.
        
        Args:
            repo_url: HTTPS URL of the git repository.
            branch: Branch to clone (default: 'main').
            
        Returns:
            List of detected risks found in the repo.
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
                file_path = os.path.join(root, file)
                if file.endswith('.tf'):
                     risks.extend(self.parse_terraform_file(file_path))
                elif file.endswith(('.yaml', '.yml', '.json')) and "cloudformation" in file.lower():
                     # Simple heuristic: treat yaml/json as CFN if name implies or we could just try
                     risks.extend(self.parse_cloudformation_file(file_path))
                elif file.endswith(('.yaml', '.yml', '.json')):
                     # Try CFN parsing anyway
                     risks.extend(self.parse_cloudformation_file(file_path))
                    
        self.logger.info("IaC scan completed", files_scanned=len(files), risks_found=len(risks))
        return risks

    def parse_terraform_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse Terraform file using Regex (Fallback detection)"""
        risks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            for rule in self.rules:
                if re.search(rule["pattern"], content):
                     risks.append({
                         "rule_id": rule["id"],
                         "name": rule["name"],
                         "file": os.path.basename(file_path),
                         "path": file_path,
                         "risk_score": rule["risk_score"],
                         "description": rule["description"],
                         "source": "iac_scanner_tf"
                     })
        except Exception as e:
            self.logger.error("Failed to parse Terraform file", file=file_path, error=str(e))
        return risks

    def parse_cloudformation_file(self, file_path: str) -> List[Dict[str, Any]]:
        """Parse CloudFormation file (YAML/JSON)"""
        risks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                if file_path.endswith('.json'):
                    data = json.load(f)
                else:
                    data = yaml.safe_load(f)
            
            resources = data.get("Resources", {})
            if not resources: 
                return []
                
            for r_name, r_def in resources.items():
                r_type = r_def.get("Type")
                for rule in self.cfn_rules:
                    if rule["resource_type"] == r_type:
                        try:
                            if rule["check"](r_def):
                                risks.append({
                                     "rule_id": rule["id"],
                                     "name": rule["name"],
                                     "file": os.path.basename(file_path),
                                     "path": file_path,
                                     "risk_score": rule["risk_score"],
                                     "description": f"{rule['description']} (Resource: {r_name})",
                                     "source": "iac_scanner_cfn"
                                 })
                        except Exception:
                            continue
        except Exception as e:
            self.logger.debug("Failed to parse CloudFormation file", file=file_path, error=str(e))
            
        return risks
