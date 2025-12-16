"""Main orchestration service for the Universal Agentic Fabric"""

import asyncio
from typing import Dict, Any
import structlog
from .common.logging import configure_logging, get_logger
from .common.config import settings
from .layer1_integration.connector_registry import registry
from .layer1_integration.scheduler import scheduler
from .layer1_integration.circuit_breaker import ConnectorCircuitBreaker, RuleBasedFallback
from .layer2_normalization.transformer import transformer
from .layer3_moat.contextualizer import contextualizer
from .layer4_agentic.state_machine import RiskDetectionStateMachine
from .adapters.slack_adapter import SlackAdapter
from .adapters.teams_adapter import TeamsAdapter

configure_logging(debug=settings.debug)
logger = get_logger(__name__)


class UniversalAgenticFabric:
    """Main orchestration class for the Universal Agentic Fabric"""
    
    def __init__(self):
        self.logger = logger
        self.circuit_breakers: Dict[str, ConnectorCircuitBreaker] = {}
        self.fallback = RuleBasedFallback()
        self.output_adapters: Dict[str, Any] = {}
        self.state_machine = RiskDetectionStateMachine(threshold=7)
    
    async def initialize(self):
        """Initialize the fabric"""
        self.logger.info("Initializing Universal Agentic Fabric")
        
        # Load connectors
        try:
            registry.load_connectors_from_module("connectors.tenable_connector")
            registry.load_connectors_from_module("connectors.splunk_connector")
        except Exception as e:
            self.logger.warning("Some connectors failed to load", error=str(e))
        
        # Start scheduler
        scheduler.start()
        
        self.logger.info("Fabric initialized", connectors=len(registry.list_connectors()))
    
    async def process_alert(self, connector_id: str, alert_data: Dict[str, Any]):
        """
        Process a single alert through the entire pipeline
        
        Args:
            connector_id: ID of the connector that fetched the alert
            alert_data: Raw alert data from connector
        """
        try:
            # Step 1: Get connector to identify source
            connector = registry.get_instance(connector_id)
            source = connector.connector_name if connector else "unknown"
            alert_data["source"] = source
            alert_data["connector_id"] = connector_id
            
            # Step 2: Normalize to OCSF
            self.logger.info("Normalizing alert", source=source, alert_id=alert_data.get("id"))
            ocsf_data = await transformer.transform(source, alert_data)
            
            # Step 3: Contextualize and store in graph
            self.logger.info("Contextualizing alert", class_uid=ocsf_data.get("class_uid"))
            node_id = await contextualizer.ingest_ocsf_data(ocsf_data)
            
            # Step 4: Risk scoring (already done in contextualizer, but can be enhanced)
            self.logger.info("Alert processed", node_id=node_id, source=source)
            
        except Exception as e:
            self.logger.error("Failed to process alert", error=str(e), connector_id=connector_id)
            raise
    
    async def run_agentic_cycle(self):
        """Run the agentic state machine to detect and respond to high-risk objects"""
        self.logger.info("Starting agentic cycle")
        
        try:
            state = await self.state_machine.run()
            
            # Process decisions
            for decision in state.get("decisions", []):
                await self._handle_decision(decision, state.get("reasoning_log", []))
            
            self.logger.info("Agentic cycle completed", decisions=len(state.get("decisions", [])))
            
        except Exception as e:
            self.logger.error("Agentic cycle failed", error=str(e))
    
    async def _handle_decision(self, decision: Dict[str, Any], reasoning_log: list):
        """Handle a decision from the state machine"""
        message = {
            "decision": decision,
            "reasoning_log": reasoning_log
        }
        
        # Send to all configured output adapters
        for adapter_name, adapter in self.output_adapters.items():
            try:
                success = await adapter.send(message)
                if success:
                    self.logger.info("Decision sent", adapter=adapter_name, decision_id=decision.get("node_id"))
            except Exception as e:
                self.logger.error("Failed to send decision", adapter=adapter_name, error=str(e))
    
    def register_output_adapter(self, name: str, adapter: Any):
        """Register an output adapter"""
        self.output_adapters[name] = adapter
        self.logger.info("Output adapter registered", adapter=name)
    
    async def shutdown(self):
        """Shutdown the fabric"""
        self.logger.info("Shutting down Universal Agentic Fabric")
        scheduler.stop()
        await asyncio.sleep(1)  # Allow pending operations to complete


async def main():
    """Main entry point"""
    fabric = UniversalAgenticFabric()
    
    try:
        await fabric.initialize()
        
        # Example: Register output adapters (in production, these would come from config)
        # slack_adapter = SlackAdapter({"webhook_url": "https://hooks.slack.com/..."})
        # fabric.register_output_adapter("slack", slack_adapter)
        
        # Run agentic cycle periodically
        while True:
            await fabric.run_agentic_cycle()
            await asyncio.sleep(60)  # Run every minute
            
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    finally:
        await fabric.shutdown()


if __name__ == "__main__":
    asyncio.run(main())
