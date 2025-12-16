from fastapi import APIRouter, HTTPException
from typing import List, Dict
from pydantic import BaseModel
from .approvals import approval_manager, PendingOperation

router = APIRouter(prefix="/approvals", tags=["approvals"])

class ApprovalDecision(BaseModel):
    decision: str  # approve / reject
    comment: str = ""

@router.get("/", response_model=List[PendingOperation])
async def list_pending_approvals():
    """List all operations waiting for approval"""
    return approval_manager.list_pending()

@router.post("/{op_id}/approve")
async def approve_operation(op_id: str):
    """Approve a pending operation"""
    op = approval_manager.approve(op_id)
    if not op:
        raise HTTPException(status_code=404, detail="Operation not found or already processed")
    
    # In a real system, this would trigger the 'Execute' phase of the dormant workflow
    # For MVP, we effectively just mark it as approved.
    return {"status": "success", "operation": op}

@router.post("/{op_id}/reject")
async def reject_operation(op_id: str):
    """Reject a pending operation"""
    op = approval_manager.reject(op_id)
    if not op:
        raise HTTPException(status_code=404, detail="Operation not found or already processed")
    
    return {"status": "success", "operation": op}
