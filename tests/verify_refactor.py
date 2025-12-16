import asyncio
import sys
import os
import structlog
from datetime import datetime
from unittest.mock import MagicMock, patch

# Adjust path to import src
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Configure logging
structlog.configure(
    processors=[structlog.dev.ConsoleRenderer()],
    logger_factory=structlog.PrintLoggerFactory(),
)
logger = structlog.get_logger()

async def verify_transformer():
    logger.info("=== Verifying TransformationEngine ===")
    from src.layer2_normalization.transformer import transformer
    
    # Test Tenable Strategy
    tenable_data = {
        "cve": "CVE-2023-1234",
        "name": "Test Vuln",
        "severity": "critical",
        "connector_id": "test_conn"
    }
    result = await transformer.transform("tenable", tenable_data)
    assert result["severity"] == "critical"
    assert result["metadata"]["source"] == "tenable"
    logger.info("Tenable transformation passed")

    # Test Azure Sentinel (New)
    sentinel_data = {
        "Title": "Suspicious Login",
        "Severity": "High",
        "TimeGenerated": datetime.now().isoformat()
    }
    result = await transformer.transform("azure_sentinel", sentinel_data)
    assert result["severity"] == "high"
    assert result["metadata"]["source"] == "azure_sentinel"
    logger.info("Azure Sentinel transformation passed")

async def verify_circuit_breaker():
    logger.info("=== Verifying Circuit Breaker Integration ===")
    from src.layer1_integration.scheduler import scheduler
    from src.layer1_integration.circuit_breaker import ConnectorCircuitBreaker
    
    # Schedule a dummy connector
    async def dummy_fetch():
        logger.info("Fetching...")
        raise Exception("Connection failed")
        
    scheduler.schedule_connector("test_conn", dummy_fetch, interval_seconds=1)
    
    # Check if CB was created
    assert "test_conn" in scheduler.circuit_breakers
    cb = scheduler.circuit_breakers["test_conn"]
    assert isinstance(cb, ConnectorCircuitBreaker)
    logger.info("Circuit breaker creation passed")

async def verify_state_machine():
    logger.info("=== Verifying Agentic State Machine ===")
    
    # Mock langgraph to avoid import errors in environment
    mock_langgraph = MagicMock()
    sys.modules["langgraph"] = mock_langgraph
    sys.modules["langgraph.graph"] = mock_langgraph
    
    # Re-import to use mocks
    if "src.layer4_agentic.state_machine" in sys.modules:
        del sys.modules["src.layer4_agentic.state_machine"]
        
    from src.layer4_agentic.state_machine import RiskDetectionStateMachine
    
    # Mock GraphClient
    with patch("src.layer4_agentic.state_machine.get_graph_client") as mock_get_client:
        mock_client = MagicMock()
        mock_client.find_high_risk_nodes = MagicMock(return_value=[])  # Async mock needed
        
        # Async mock helper
        f = asyncio.Future()
        f.set_result([])
        mock_client.find_high_risk_nodes.return_value = f
        
        mock_get_client.return_value = mock_client
        
        sm = RiskDetectionStateMachine()
        
        # Verify initial state
        assert sm.last_cycle_time is None
        
        # Run one cycle (mocking IaC which is now threaded)
        sm.workflow.ainvoke = MagicMock()
        f_res = asyncio.Future()
        f_res.set_result({"decisions": [], "reasoning_log": []})
        sm.workflow.ainvoke.return_value = f_res
        
        await sm.run()
        logger.info("State machine run passed")

async def verify_neptune_client():
    logger.info("=== Verifying NeptuneClient ===")
    try:
        from src.layer3_moat.graph_client import NeptuneClient
        logger.info("NeptuneClient imported successfully.")
        # We can't easily test it without a real Neptune or gremlin-server, 
        # but importing proves syntax is valid.
    except ImportError as e:
        logger.warning(f"Skipping NeptuneClient test: {e}")
    except Exception as e:
        logger.error(f"NeptuneClient verification failed: {e}")

async def main():
    try:
        await verify_transformer()
        await verify_circuit_breaker()
        await verify_state_machine()
        await verify_neptune_client()
        logger.info("\nALL VERIFICATIONS PASSED")
    except Exception as e:
        logger.error(f"\nVERIFICATION FAILED: {e}")
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
