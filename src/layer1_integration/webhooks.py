from fastapi import APIRouter, HTTPException, Request, BackgroundTasks
from pydantic import BaseModel
from typing import Dict, Any, Optional
import structlog
from datetime import datetime

# Initialize router
router = APIRouter(prefix="/webhooks", tags=["webhooks"])
logger = structlog.get_logger(__name__)

class WebhookEvent(BaseModel):
    source: str
    event_type: str
    payload: Dict[str, Any]
    timestamp: Optional[datetime] = None

async def process_event(event: WebhookEvent):
    """
    Background task to process the incoming event.
    In a real system, this would push to a Kafka topic.
    For this MVP, we will process it directly or push to an internal queue.
    """
    logger.info("Processing webhook event", source=event.source, type=event.event_type)
    
    # Simulating normalization and ingestion
    # Here we would call the TransformationEngine
    # and then the RiskDetectionStateMachine
    
    # TODO: Connect to State Machine
    pass

@router.post("/ingest")
async def ingest_webhook(event: WebhookEvent, background_tasks: BackgroundTasks):
    """
    Generic webhook ingestion endpoint.
    Expects a standardized JSON payload.
    """
    logger.info("Received webhook", source=event.source)
    background_tasks.add_task(process_event, event)
    return {"status": "accepted", "message": "Event queued for processing"}

@router.post("/splunk")
async def splunk_webhook(request: Request, background_tasks: BackgroundTasks):
    """
    Specific endpoint for Splunk alerts (compatible with Splunk Webhook Actions).
    """
    try:
        payload = await request.json()
        # Splunk payloads vary, but typically have 'result' or 'search_name'
        event = WebhookEvent(
            source="splunk",
            event_type="alert",
            payload=payload,
            timestamp=datetime.now()
        )
        background_tasks.add_task(process_event, event)
        return {"status": "accepted"}
    except Exception as e:
        logger.error("Failed to process Splunk webhook", error=str(e))
        raise HTTPException(status_code=400, detail="Invalid payload")
