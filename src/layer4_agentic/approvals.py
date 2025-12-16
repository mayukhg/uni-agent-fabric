from typing import Dict, List, Optional, Any
from pydantic import BaseModel
from datetime import datetime
import uuid
import structlog

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
        logger.info("Approval requested", op_id=op_id, risk=risk_score, action=action_type)
        return op_id

    def list_pending(self) -> List[PendingOperation]:
        return [op for op in self._pending.values() if op.status == "PENDING"]

    def approve(self, op_id: str) -> Optional[PendingOperation]:
        if op_id in self._pending:
            self._pending[op_id].status = "APPROVED"
            logger.info("Operation approved", op_id=op_id)
            return self._pending[op_id]
        return None

    def reject(self, op_id: str) -> Optional[PendingOperation]:
        if op_id in self._pending:
            self._pending[op_id].status = "REJECTED"
            logger.info("Operation rejected", op_id=op_id)
            return self._pending[op_id]
        return None

    def get_operation(self, op_id: str) -> Optional[PendingOperation]:
        return self._pending.get(op_id)

# Global singleton
approval_manager = ApprovalsManager()
