"""Configuration management using Pydantic Settings"""

from pydantic_settings import BaseSettings
from pydantic import Field
from typing import Optional


class Settings(BaseSettings):
    """
    Application settings loaded from environment variables.
    
    Uses Pydantic BaseSettings to automatically read from .env files or system environment.
    All fields are case-insensitive when reading from env (e.g., APP_NAME overrides app_name).
    """
    
    # Application Metadata
    app_name: str = "Universal Agentic Fabric"
    app_version: str = "2.0.0"
    debug: bool = False  # Enable verbose logging if True
    
    # Graph Database
    graph_db_type: str = Field(default="neo4j", description="Graph database type: neo4j or neptune")
    neo4j_uri: Optional[str] = Field(default=None, description="Neo4j connection URI")
    neo4j_user: Optional[str] = Field(default=None, description="Neo4j username")
    neo4j_password: Optional[str] = Field(default=None, description="Neo4j password")
    
    # OPA
    opa_url: str = Field(default="http://localhost:8181/v1/data/fabric/policy", description="Open Policy Agent URL")
    
    neptune_endpoint: Optional[str] = Field(default=None, description="Neptune endpoint")
    neptune_port: int = Field(default=8182, description="Neptune port")
    
    # Message Queue
    message_queue_type: str = Field(default="kafka", description="Message queue type: kafka or nats")
    kafka_bootstrap_servers: Optional[str] = Field(default=None, description="Kafka bootstrap servers")
    kafka_topic: str = Field(default="security_events", description="Kafka topic for ingestion")
    kafka_dlq_topic: str = Field(default="fabric_dlq", description="Kafka Dead Letter Queue topic")
    nats_url: Optional[str] = Field(default="nats://localhost:4222", description="NATS server URL")
    
    # Secrets Management
    vault_type: str = Field(default="vault", description="Vault type: vault, aws, or azure")
    vault_addr: Optional[str] = Field(default="http://localhost:8200", description="Vault address")
    vault_token: Optional[str] = Field(default=None, description="Vault token")
    aws_region: Optional[str] = Field(default=None, description="AWS region for Secrets Manager")
    azure_keyvault_url: Optional[str] = Field(default=None, description="Azure Key Vault URL")
    
    # Performance
    default_polling_interval: int = Field(default=300, description="Default polling interval in seconds (5 minutes)")
    max_retries: int = Field(default=3, description="Maximum retry attempts")
    retry_backoff_factor: float = Field(default=2.0, description="Exponential backoff factor")
    
    # SLA
    triage_sla_seconds: int = Field(default=300, description="Triage SLA in seconds (5 minutes)")
    
    # Circuit Breaker
    circuit_breaker_failure_threshold: int = Field(default=5, description="Circuit breaker failure threshold")
    circuit_breaker_timeout: int = Field(default=60, description="Circuit breaker timeout in seconds")
    
    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False


# Global settings instance
settings = Settings()

