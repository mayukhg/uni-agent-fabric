"""Onboarding wizard REST API"""

from fastapi import FastAPI, HTTPException, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Dict, Any, Optional, List
import structlog
from ..layer1_integration.connector_registry import registry
from ..layer1_integration.secrets_manager import get_secrets_manager
from ..layer1_integration.scheduler import scheduler
from ..common.logging import configure_logging, get_logger
from ..layer1_integration.webhooks import router as webhook_router
from ..layer4_agentic.approval_api import router as approval_router

configure_logging()
logger = get_logger(__name__)

app = FastAPI(title="Universal Agentic Fabric - Onboarding API", version="2.0.0")

app.include_router(webhook_router)
app.include_router(approval_router)


@app.on_event("startup")
async def startup_event():
    """Load connectors on startup"""
    try:
        logger.info("Loading connectors...")
        
        # Import connector classes
        from connectors.splunk_connector import SplunkConnector
        from connectors.tenable_connector import TenableConnector
        from connectors.aws_connector import AwsSecurityHubConnector
        from connectors.crowdstrike_connector import CrowdStrikeConnector
        
        # Register with explicit names matching frontend IDs
        registry.register("splunk", SplunkConnector)
        registry.register("tenable", TenableConnector)
        registry.register("aws_security_hub", AwsSecurityHubConnector)
        registry.register("crowdstrike", CrowdStrikeConnector)
        
        logger.info(f"Loaded connectors: {registry.list_connectors()}")
    except Exception as e:
        logger.error(f"Failed to load connectors: {e}")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class ConnectorConfig(BaseModel):
    """Connector configuration model"""
    connector_name: str
    config: Dict[str, Any]


class OutputConfig(BaseModel):
    """Output adapter configuration model"""
    adapter_type: str  # slack, teams, etc.
    config: Dict[str, Any]


class OnboardingRequest(BaseModel):
    """Onboarding wizard request"""
    step: int
    connector_config: Optional[ConnectorConfig] = None
    output_config: Optional[OutputConfig] = None
    connector_id: Optional[str] = None


class ConnectorInfo(BaseModel):
    """Connector information"""
    name: str
    description: str
    required_config: List[str]


@app.get("/")
async def root():
    """Root endpoint"""
    return {"message": "Universal Agentic Fabric Onboarding API", "version": "2.0.0"}


@app.get("/health")
async def health():
    """Health check endpoint"""
    return {"status": "healthy"}


@app.get("/connectors", response_model=List[ConnectorInfo])
async def list_connectors():
    """List available connectors"""
    connectors = registry.list_connectors()
    # In a real implementation, you'd fetch descriptions from metadata
    return [
        ConnectorInfo(
            name=name,
            description=f"Connector for {name}",
            required_config=["api_key", "base_url"]
        )
        for name in connectors
    ]


@app.post("/onboarding/step1")
async def step1_select_connector(request: OnboardingRequest):
    """Step 1: Select data source connector"""
    if not request.connector_config:
        raise HTTPException(status_code=400, detail="connector_config required")
    
    connector_name = request.connector_config.connector_name
    if connector_name not in registry.list_connectors():
        raise HTTPException(status_code=404, detail=f"Connector not found: {connector_name}")
    
    return {
        "status": "success",
        "connector_name": connector_name,
        "message": f"Connector {connector_name} selected"
    }


@app.post("/onboarding/step2")
async def step2_input_credentials(request: OnboardingRequest):
    """Step 2: Input credentials and test connection"""
    if not request.connector_config:
        raise HTTPException(status_code=400, detail="connector_config required")
    
    connector_name = request.connector_config.connector_name
    config = request.connector_config.config
    
    # Store credentials in secrets manager
    secrets_manager = get_secrets_manager()
    connector_id = f"{connector_name}_{hash(str(config))}"
    
    # Store API keys securely
    for key in ["api_key", "secret_key", "password", "token"]:
        if key in config:
            await secrets_manager.store_secret(
                f"{connector_id}/{key}",
                config[key]
            )
            # Remove from config for security
            config[key] = "***REDACTED***"
    
    # Create connector instance and test
    try:
        connector = registry.create_instance(connector_id, connector_name, config)
        test_result = await connector.test_connection()
        
        if test_result:
            return {
                "status": "success",
                "connector_id": connector_id,
                "message": "Connection test successful"
            }
        else:
            raise HTTPException(status_code=400, detail="Connection test failed")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Connection test error: {str(e)}")


@app.post("/onboarding/step3")
async def step3_select_output(request: OnboardingRequest):
    """Step 3: Select output adapter"""
    if not request.output_config:
        raise HTTPException(status_code=400, detail="output_config required")
    
    adapter_type = request.output_config.adapter_type
    supported_adapters = ["slack", "teams", "email"]
    
    if adapter_type not in supported_adapters:
        raise HTTPException(
            status_code=400, 
            detail=f"Unsupported adapter type. Supported: {supported_adapters}"
        )
    
    return {
        "status": "success",
        "adapter_type": adapter_type,
        "message": f"Output adapter {adapter_type} selected"
    }


@app.post("/onboarding/step4")
async def step4_finalize(request: OnboardingRequest):
    """Step 4: Finalize connection and start scheduling"""
    if not request.connector_id:
        raise HTTPException(status_code=400, detail="connector_id required")
    
    connector = registry.get_instance(request.connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector instance not found")
    
    # Schedule the connector
    async def fetch_wrapper():
        try:
            alerts = await connector.fetch()
            logger.info("Fetched alerts", connector_id=request.connector_id, count=len(alerts))
            # In a real implementation, alerts would be sent to message queue
        except Exception as e:
            logger.error("Fetch error", connector_id=request.connector_id, error=str(e))
    
    scheduler.schedule_connector(request.connector_id, fetch_wrapper)
    
    next_run = scheduler.get_next_run_time(request.connector_id)
    return {
        "status": "success",
        "connector_id": request.connector_id,
        "message": "Connection finalized and scheduled",
        "next_run": next_run.isoformat() if next_run else None
    }


@app.get("/connectors/{connector_id}/status")
async def get_connector_status(connector_id: str):
    """Get connector status"""
    connector = registry.get_instance(connector_id)
    if not connector:
        raise HTTPException(status_code=404, detail="Connector not found")
    
    next_run = scheduler.get_next_run_time(connector_id)
    return {
        "connector_id": connector_id,
        "status": "active" if connector.is_authenticated else "inactive",
        "metadata": connector.get_metadata(),
        "next_run": next_run.isoformat() if next_run else None
    }
