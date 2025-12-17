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

import hcl2
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
        # AST-based rules for HCL parsing
        # Structure: Resource Type -> Check Function
        self.tf_rules = [
            {
                "id": "IAC-TF-001",
                "name": "S3 Bucket Public Access Block Missing",
                "resource_type": "aws_s3_bucket",
                "check": lambda r: True, # Logic: If bucket exists, we warn (simplification for MVP as checking missing child resource is complex)
                # Better logic would be checking if a matching aws_s3_bucket_public_access_block exists, which requires cross-resource context.
                # For this parser scope, we might just flag "Potential Misconfiguration" or rely on detailed attributes.
                # Let's pivot to a simpler attribute check for MVP: Versioning enabled?
                "risk_score": 5,
                "description": "S3 bucket detected (Manual review recommended for public access blocks)"
            },
             {
                "id": "IAC-TF-002",
                "name": "Security Group Open to World",
                "resource_type": "aws_security_group",
                "check": lambda r: self._check_sg_ingress(r),
                "risk_score": 9,
                "description": "Security group allows ingress from 0.0.0.0/0"
            },
            {
                "id": "IAC-TF-003",
                "name": "Unencrypted EBS Volume",
                "resource_type": "aws_ebs_volume",
                "check": lambda r: str(r.get("encrypted", "false")).lower() != "true",
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
        """Parse Terraform file using python-hcl2 (AST)"""
        risks = []
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = hcl2.load(f)
            
            # hcl2 returns dict: { "resource": [ { "type": { "name": { ... } } } ] }
            resources = data.get("resource", [])
            
            for resource_block in resources:
                for r_type, r_instances in resource_block.items():
                    # r_instances is a dict where keys are resource names and values are the config
                    for r_name, r_config in r_instances.items():
                         self._check_hcl_resource(r_type, r_name, r_config, file_path, risks)

        except Exception as e:
            self.logger.error("Failed to parse Terraform file", file=file_path, error=str(e))
            # Fallback? No, we want to enforce robust parsing
        return risks

    def _check_hcl_resource(self, r_type: str, r_name: str, r_config: Dict, file_path: str, risks: List):
        """Check a single HCL resource against rules"""
        for rule in self.tf_rules:
            if rule["resource_type"] == r_type:
                try:
                    if rule["check"](r_config):
                         risks.append({
                             "rule_id": rule["id"],
                             "name": rule["name"],
                             "file": os.path.basename(file_path),
                             "path": file_path,
                             "risk_score": rule["risk_score"],
                             "description": f"{rule['description']} (Resource: {r_name})",
                             "source": "iac_scanner_tf_ast"
                         })
                except Exception as check_err:
                     self.logger.debug("Rule check failed", rule=rule["id"], error=str(check_err))

    def _check_sg_ingress(self, resource_config: Dict) -> bool:
        """Helper to check Security Group ingress"""
        ingress = resource_config.get("ingress", [])
        if not ingress:
            return False
        
        # In HCL2, ingress might be a list of dicts or a single dict
        if isinstance(ingress, dict):
            ingress = [ingress]
            
        for rule in ingress:
            cidr_blocks = rule.get("cidr_blocks", [])
            if "0.0.0.0/0" in cidr_blocks:
                return True
        return False

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
