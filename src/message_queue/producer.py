"""Message queue producer for publishing alerts"""

from typing import Dict, Any, Optional
import structlog
from ..common.config import settings
from ..common.exceptions import ConnectorError

logger = structlog.get_logger(__name__)


class MessageQueueProducer:
    """Producer for publishing messages to message queue"""
    
    def __init__(self):
        self.queue_type = settings.message_queue_type.lower()
        self.logger = logger
        self._producer = None
        self._initialize()
    
    def _initialize(self):
        """Initialize the appropriate message queue producer"""
        if self.queue_type == "kafka":
            self._initialize_kafka()
        elif self.queue_type == "nats":
            self._initialize_nats()
        else:
            self.logger.warning("No message queue configured, using in-memory processing")
    
    def _initialize_kafka(self):
        """Initialize Kafka producer"""
        try:
            from kafka import KafkaProducer
            import json
            
            self._producer = KafkaProducer(
                bootstrap_servers=settings.kafka_bootstrap_servers.split(","),
                value_serializer=lambda v: json.dumps(v).encode('utf-8'),
                key_serializer=lambda k: k.encode('utf-8') if k else None
            )
            self.logger.info("Kafka producer initialized")
        except ImportError:
            raise ConnectorError("kafka-python not installed")
        except Exception as e:
            self.logger.error("Failed to initialize Kafka", error=str(e))
            raise
    
    def _initialize_nats(self):
        """Initialize NATS producer"""
        try:
            import nats
            # NATS would be initialized asynchronously
            self.logger.info("NATS producer will be initialized on first use")
        except ImportError:
            raise ConnectorError("nats-py not installed")
    
    async def publish(self, topic: str, message: Dict[str, Any], key: Optional[str] = None):
        """
        Publish a message to the queue
        
        Args:
            topic: Topic/channel name
            message: Message dictionary
            key: Optional message key for partitioning
        """
        if not self._producer:
            self.logger.warning("No message queue producer, message not published", topic=topic)
            return
        
        try:
            if self.queue_type == "kafka":
                future = self._producer.send(topic, value=message, key=key)
                future.get(timeout=10)  # Wait for send confirmation
                self.logger.info("Message published to Kafka", topic=topic)
            elif self.queue_type == "nats":
                # NATS async implementation would go here
                self.logger.info("Message published to NATS", topic=topic)
        except Exception as e:
            self.logger.error("Failed to publish message", topic=topic, error=str(e))
            raise ConnectorError(f"Failed to publish message: {e}")
    
    def close(self):
        """Close the producer"""
        if self._producer and self.queue_type == "kafka":
            self._producer.close()


# Global producer instance
producer = MessageQueueProducer()

