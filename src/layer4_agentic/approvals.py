from typing import Dict, List, Optional, Any
from pydantic import BaseModel
from datetime import datetime
import uuid
import structlog

logger = structlog.get_logger(__name__)

class PendingOperation(BaseModel):
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
    Manages operations requiring human approval.
    For MVP, uses in-memory storage. In production, use a database.
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
