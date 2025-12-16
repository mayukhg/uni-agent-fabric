"""Main orchestration service for the Universal Agentic Fabric"""

import asyncio
from typing import Dict, Any
import structlog
import json
from aiohttp import web
from aiokafka import AIOKafkaConsumer
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
    """
    Main orchestration class for the Universal Agentic Fabric.
    
    Responsibilities:
    1. Integration: Initialize connectors, scheduler, and message queues.
    2. Normalization: Route incoming alerts through the Transformation Engine.
    3. Contextualization: Store normalized data in the Graph DB.
    4. Agency: periodic risk analysis and autonomous decision making via the State Machine.
    """
    
    def __init__(self):
        self.logger = logger
        self.circuit_breakers: Dict[str, ConnectorCircuitBreaker] = {}
        self.fallback = RuleBasedFallback()
        self.output_adapters: Dict[str, Any] = {}
        self.state_machine = RiskDetectionStateMachine(threshold=7)
        self.consumer = None
        self.consumer_running = False
    
    async def initialize(self):
        """
        Initialize all fabric components.
        
        - Loads connectors from the registry.
        - Starts the job scheduler.
        - Initializes Kafka Consumer and Producer (DLQ) if configured.
        """
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

        # Initialize Kafka Consumer if configured
        self.producer = None  # Kafka producer for DLQ
        
        if settings.message_queue_type == "kafka" and settings.kafka_bootstrap_servers:
            try:
                self.consumer = AIOKafkaConsumer(
                    settings.kafka_topic,
                    bootstrap_servers=settings.kafka_bootstrap_servers,
                    group_id="agentic_fabric_v1",
                    enable_auto_commit=False,  # Manual commit for at-least-once delivery
                    auto_offset_reset="earliest"
                )
                # Initialize producer for DLQ
                from aiokafka import AIOKafkaProducer
                self.producer = AIOKafkaProducer(
                    bootstrap_servers=settings.kafka_bootstrap_servers
                )
                self.logger.info("Kafka consumer/producer initialized", topic=settings.kafka_topic, dlq=settings.kafka_dlq_topic)
            except Exception as e:
                self.logger.error("Failed to initialize Kafka client", error=str(e))
    
    async def process_alert(self, connector_id: str, alert_data: Dict[str, Any]):
        """
        Process a single alert through the intake pipeline.
        
        Pipeline Steps:
        1. Identify source connector.
        2. Transform (Normalize) to OCSF format.
        3. Contextualize (Ingest) into Graph Nodes.
        
        Args:
            connector_id: ID of the connector that fetched the alert.
            alert_data: Raw alert dictionary from the vendor.
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
    
    async def consume_messages(self):
        """
        Continuous loop to consume messages from Kafka.
        
        Handles:
        - Message decoding.
        - Routing to `process_alert`.
        - Error handling and forwarding to Dead Letter Queue (DLQ).
        - Manual offset committing to ensure at-least-once processing.
        """
        if not self.consumer:
            self.logger.warning("Consumer not initialized, skipping consumption loop")
            return

        self.consumer_running = True
        self.logger.info("Starting message consumption loop")
        
        try:
            await self.consumer.start()
            async for msg in self.consumer:
                if not self.consumer_running:
                    break
                
                try:
                    payload = json.loads(msg.value.decode('utf-8'))
                    self.logger.info("Received message", partition=msg.partition, offset=msg.offset)
                    
                    # Extract connector_id and data from payload
                    # Expected format: {"connector_id": "...", "data": {...}}
                    connector_id = payload.get("connector_id", "unknown")
                    data = payload.get("data", payload)
                    
                    await self.process_alert(connector_id, data)
                    
                    # Manual commit after successful processing
                    await self.consumer.commit()
                    
                except json.JSONDecodeError:
                    self.logger.error("Failed to decode message", offset=msg.offset)
                    # Commit offset for malformed messages to avoid getting stuck
                    await self.consumer.commit()
                except Exception as e:
                    self.logger.error("Error processing message", error=str(e), offset=msg.offset)
                    # Send to DLQ
                    if self.producer and settings.kafka_dlq_topic:
                        try:
                            dlq_payload = {
                                "original_message": msg.value.decode('utf-8', errors='ignore'),
                                "error": str(e),
                                "timestamp": datetime.now().isoformat(),
                                "topic": msg.topic,
                                "partition": msg.partition,
                                "offset": msg.offset
                            }
                            await self.producer.send_and_wait(
                                settings.kafka_dlq_topic, 
                                json.dumps(dlq_payload).encode('utf-8')
                            )
                            self.logger.info("Message sent to DLQ", dlq_topic=settings.kafka_dlq_topic, offset=msg.offset)
                            # Commit offset so we don't get stuck on this message forever
                            await self.consumer.commit()
                        except Exception as dlq_error:
                            self.logger.critical("Failed to send to DLQ", error=str(dlq_error), original_offset=msg.offset)
                            # If DLQ fails, we still commit the original message to avoid reprocessing indefinitely
                            await self.consumer.commit()
                    else:
                        # If no DLQ, logic depends on policy. Here we log and commit to avoid block loop.
                        self.logger.warning("DLQ not configured or producer not available, committing offset for failed message to avoid reprocessing.", offset=msg.offset)
                        await self.consumer.commit()
                    
        except Exception as e:
            self.logger.error("Consumer loop failed", error=str(e))
        finally:
            if self.consumer:
                await self.consumer.stop()
            self.logger.info("Consumer stopped")

    async def shutdown(self):
        """Shutdown the fabric"""
        self.logger.info("Shutting down Universal Agentic Fabric")
        self.consumer_running = False
        scheduler.stop()
        if self.consumer:
            await self.consumer.stop()
        if self.producer:
            await self.producer.stop()
        await asyncio.sleep(1)  # Allow pending operations to complete


async def health_check(request):
    """Health check endpoint"""
    return web.json_response({"status": "healthy", "service": "agentic-fabric"})


async def start_background_tasks(app):
    """Start background agentic cycle"""
    fabric = app['fabric']
    await fabric.initialize()
    
    async def run_cycle():
        while True:
            try:
                await fabric.run_agentic_cycle()
                await asyncio.sleep(60)  # Run every minute
            except Exception as e:
                logger.error("Agentic cycle error", error=str(e))
                await asyncio.sleep(60)
    
    app['cycle_task'] = asyncio.create_task(run_cycle())
    
    # Start consumer task
    app['consumer_task'] = asyncio.create_task(fabric.consume_messages())


async def cleanup_background_tasks(app):
    """Cleanup background tasks"""
    fabric = app['fabric']
    if 'cycle_task' in app:
        app['cycle_task'].cancel()
        try:
            await app['cycle_task']
        except asyncio.CancelledError:
            pass
            
    if 'consumer_task' in app:
        app['consumer_task'].cancel()
        try:
            await app['consumer_task']
        except asyncio.CancelledError:
            pass
            
    await fabric.shutdown()


async def create_app():
    """Create the web application"""
    app = web.Application()
    app['fabric'] = UniversalAgenticFabric()
    
    # Add routes
    app.router.add_get('/health', health_check)
    app.router.add_get('/', health_check)
    
    # Setup background tasks
    app.on_startup.append(start_background_tasks)
    app.on_cleanup.append(cleanup_background_tasks)
    
    return app


async def main():
    """Main entry point"""
    app = await create_app()
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, '0.0.0.0', 8000)
    await site.start()
    logger.info("Agentic Fabric HTTP server started on port 8000")
    
    # Keep running
    try:
        await asyncio.Event().wait()
    except KeyboardInterrupt:
        logger.info("Shutdown requested")
    finally:
        await runner.cleanup()


if __name__ == "__main__":
    asyncio.run(main())
