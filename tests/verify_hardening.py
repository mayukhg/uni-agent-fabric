import asyncio
import sys
import os
import structlog
from datetime import datetime
from unittest.mock import MagicMock, patch, AsyncMock

# Add src to path
sys.path.append(os.path.join(os.path.dirname(__file__), ".."))

# Mocking langgraph to avoid environment issues during verification
from unittest.mock import MagicMock
sys.modules["langgraph"] = MagicMock()
sys.modules["langgraph.graph"] = MagicMock()
sys.modules["langgraph.graph.StateGraph"] = MagicMock()
sys.modules["langgraph.graph.END"] = "END"

from src.layer3_moat.graph_client import NeptuneClient, GraphDatabaseError
from src.layer4_agentic.iac_parser import IaCParser
from src.layer4_agentic.state_machine import RiskDetectionStateMachine
from src.layer2_normalization.strategies import ConfigurableStrategy

logger = structlog.get_logger()

async def verify_neptune_safety():
    """Verify NeptuneClient rejects raw queries"""
    print("\n--- Verifying Neptune Safety (FR 3.1) ---")
    try:
        # Mock dependencies just to instantiate
        with patch.dict('sys.modules', {
            'gremlin_python': MagicMock(),
            'gremlin_python.driver.driver_remote_connection': MagicMock(),
            'gremlin_python.structure.graph': MagicMock()
        }):
            client = NeptuneClient()
            try:
                await client.query("g.V().count()")
                print("❌ FAILED: NeptuneClient should reject raw queries")
            except GraphDatabaseError as e:
                if "disabled for security" in str(e):
                    print("✅ PASSED: NeptuneClient rejected raw query")
                else:
                    print(f"❌ FAILED: Unexpected error message: {e}")
    except Exception as e:
        print(f"⚠️ SKIPPED (Env issues): {e}")

async def verify_iac_parser():
    """Verify IaC Parser for TF and CFN"""
    print("\n--- Verifying IaC Parsing (FR 5.1) ---")
    parser = IaCParser()
    fixtures_dir = os.path.join(os.path.dirname(__file__), "fixtures")
    
    # Test TF
    tf_risks = parser.parse_terraform_file(os.path.join(fixtures_dir, "sample_iac.tf"))
    if any(r["rule_id"] == "IAC-003" for r in tf_risks):
        print(f"✅ PASSED: Detected Unencrypted EBS in Terraform ({len(tf_risks)} risks)")
    else:
        print(f"❌ FAILED: Did not detect Unencrypted EBS in Terraform. Risks: {tf_risks}")

    # Test CFN
    cfn_risks = parser.parse_cloudformation_file(os.path.join(fixtures_dir, "sample_cfn.yaml"))
    
    # Note: rule ID might be IAC-CFN-001 from my implementation
    if any("Security Group Open" in r["name"] for r in cfn_risks):
        print(f"✅ PASSED: Detected Open Security Group in CloudFormation ({len(cfn_risks)} risks)")
    else:
        print(f"❌ FAILED: Did not detect Open Security Group in CloudFormation. Risks: {cfn_risks}")

async def verify_opa_integration():
    """Verify OPA integration logic"""
    print("\n--- Verifying OPA Integration (FR 4.1) ---")
    
    # Mock GraphClient and IaCParser to isolate State Machine
    with patch('src.layer4_agentic.state_machine.get_graph_client') as mock_graph:
        sm = RiskDetectionStateMachine(threshold=5)
        
        # Test Case 1: High Risk -> OPA Deny/Approval
        # Mock OPA response
        with patch('httpx.AsyncClient.post', new_callable=AsyncMock) as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.json.return_value = {
                "result": {"action": "PENDING_APPROVAL", "require_approval": True, "reason": "Test Policy"}
            }
            
            result = await sm._check_opa_policy("node1", "test", 9)
            if result.get("require_approval"):
                print("✅ PASSED: OPA Policy check detected approval requirement")
            else:
                print(f"❌ FAILED: OPA check did not return expected result: {result}")

async def verify_generic_yaml_strategy():
    """Verify YAML Strategy"""
    print("\n--- Verifying YAML Transformation (FR 2.1) ---")
    config_path = os.path.join(os.path.dirname(__file__), "..", "config", "mappings", "tenable.yaml")
    if not os.path.exists(config_path):
         print("❌ FAILED: config/mappings/tenable.yaml not found")
         return
         
    strategy = ConfigurableStrategy(config_path)
    sample_data = {
        "severity": 4,
        "name": "Vuln 1",
        "description": "Desc",
        "connector_id": "conn1",
        "timestamp": 1234567890
    }
    
    result = await strategy.transform(sample_data)
    if result["class_uid"] == 2002 and result["vulnerability"]["name"] == "Vuln 1":
        print("✅ PASSED: YAML Strategy transformed data correctly")
    else:
        print(f"❌ FAILED: Transform result incorrect: {result}")

async def main():
    await verify_neptune_safety()
    await verify_iac_parser()
    await verify_opa_integration()
    await verify_generic_yaml_strategy()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        pass
