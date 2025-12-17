from typing import Dict, List, Optional, Any
from pydantic import BaseModel
from datetime import datetime
import uuid
import structlog
import json
import redis
from ..common.config import settings
from ..common.exceptions import ConfigurationError
logger = structlog.get_logger(__name__)

class PendingOperation(BaseModel):
    """
    Data model for an operation requiring human approval.
    
    Attributes:
        id: Unique UUID for the operation.
        risk_score: The calculated risk score that triggered the approval.
        description: Human-readable context about the risk.
        action_type: The proposed automated action (e.g., 'remediate', 'isolate').
        target: The ID of the asset or resource being targeted.
        status: Current state ('PENDING', 'APPROVED', 'REJECTED').
        metadata: Additional context like source system, policy results, etc.
    """
    id: str
    risk_score: float
    description: str
    action_type: str
    target: str
    created_at: datetime
    status: str = "PENDING"  # PENDING, APPROVED, REJECTED
    metadata: Dict[str, Any] = {}

class ApprovalsManager:
    """
    Manager for Human-in-the-Loop (HITL) approval workflows.
    
    Stores pending operations that were flagged by the `RiskDetectionStateMachine`.
    Provides APIs to list, approve, or reject these operations.
    
    Note: Currently uses in-memory storage. For production, this must be backed by a persistent DB (Postgres/Redis).
    """
    def __init__(self):
        self._pending: Dict[str, PendingOperation] = {}
        self.redis_client = None
        
        if settings.approval_db_type == "redis":
            try:
                self.redis_client = redis.from_url(settings.redis_url, decode_responses=True)
                self._load_state()
                logger.info("ApprovalsManager initialized with Redis backend")
            except Exception as e:
                logger.error("Failed to connect to Redis", error=str(e))
                # Fallback or raise depends on criticality. For now, we log error.
                
    def _load_state(self):
        """Recover state from Redis on startup"""
        if not self.redis_client:
            return
            
        pattern = f"{settings.approval_redis_key_prefix}*"
        keys = self.redis_client.keys(pattern)
        
        for key in keys:
            try:
                data = self.redis_client.get(key)
                if data:
                    op_dict = json.loads(data)
                    op = PendingOperation(**op_dict)
                    # Only load into memory if it's PENDING
                    if op.status == "PENDING":
                        self._pending[op.id] = op
            except Exception as e:
                logger.error("Failed to load operation from Redis", key=key, error=str(e))

    def _save_operation(self, operation: PendingOperation):
        """Save operation to Redis"""
        if self.redis_client:
            key = f"{settings.approval_redis_key_prefix}{operation.id}"
            try:
                # Serialize datetime manually or use pydantic json mode
                self.redis_client.set(key, operation.json())
            except Exception as e:
                logger.error("Failed to save to Redis", op_id=operation.id, error=str(e))

    def request_approval(self, risk_score: float, description: str, action_type: str, target: str, metadata: Dict = {}) -> str:
        """Create a new pending operation"""
        op_id = str(uuid.uuid4())
        operation = PendingOperation(
            id=op_id,
            risk_score=risk_score,
            description=description,
            action_type=action_type,
            target=target,
            created_at=datetime.now(),
            metadata=metadata
        )
        self._pending[op_id] = operation
        self._save_operation(operation)
        
        logger.info("Approval requested", op_id=op_id, risk=risk_score, action=action_type)
        return op_id

    def list_pending(self) -> List[PendingOperation]:
        return [op for op in self._pending.values() if op.status == "PENDING"]

    def approve(self, op_id: str) -> Optional[PendingOperation]:
        if op_id in self._pending:
            op = self._pending[op_id]
            op.status = "APPROVED"
            self._save_operation(op)
            
            # Remove from pending memory cache (or keep recent history?)
            # PRD requirement: "stores data in memory... refactor... to persist"
            # We'll keep it in memory for now but status is updated for list_pending filter
            
            logger.info("Operation approved", op_id=op_id)
            return op
        return None

    def reject(self, op_id: str) -> Optional[PendingOperation]:
        if op_id in self._pending:
            op = self._pending[op_id]
            op.status = "REJECTED"
            self._save_operation(op)
            logger.info("Operation rejected", op_id=op_id)
            return op
        return None

    def get_operation(self, op_id: str) -> Optional[PendingOperation]:
        return self._pending.get(op_id)

# Global singleton
approval_manager = ApprovalsManager()
