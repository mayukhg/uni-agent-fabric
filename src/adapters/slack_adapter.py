"""Slack output adapter"""

import httpx
from typing import Dict, Any
from .base_adapter import BaseOutputAdapter
import structlog

logger = structlog.get_logger(__name__)


class SlackAdapter(BaseOutputAdapter):
    """Slack webhook adapter"""
    
    def __init__(self, config: Dict[str, Any]):
        super().__init__(config)
        self.webhook_url = config.get("webhook_url")
        self.channel = config.get("channel", "#security-alerts")
        self.client = httpx.AsyncClient(timeout=10.0)
    
    async def format_message(self, decision: Dict[str, Any], reasoning_log: list) -> str:
        """Format message for Slack"""
        risk_score = decision.get("risk_score", 0)
        action = decision.get("action", "unknown")
        source = decision.get("source", "unknown")
        node_id = decision.get("node_id", "unknown")
        
        # Determine emoji based on risk
        emoji = "🔴" if risk_score >= 9 else "🟠" if risk_score >= 7 else "🟡"
        
        message = f"{emoji} *Security Alert*\n\n"
        message += f"*Risk Score:* {risk_score}/10\n"
        message += f"*Action:* {action.upper()}\n"
        message += f"*Source:* {source}\n"
        message += f"*Node ID:* {node_id}\n\n"
        message += "*Reasoning:*\n"
        for entry in reasoning_log[-3:]:  # Last 3 reasoning entries
            message += f"• {entry}\n"
        
        return message
    
    async def send(self, message: Dict[str, Any]) -> bool:
        """Send message to Slack"""
        if not self.webhook_url:
            self.logger.error("Slack webhook URL not configured")
            return False
        
        try:
            formatted = await self.format_message(
                message.get("decision", {}),
                message.get("reasoning_log", [])
            )
            
            payload = {
                "text": formatted,
                "channel": self.channel,
                "username": "Agentic Defense",
                "icon_emoji": ":shield:"
            }
            
            response = await self.client.post(self.webhook_url, json=payload)
            response.raise_for_status()
            
            self.logger.info("Message sent to Slack", channel=self.channel)
            return True
        except Exception as e:
            self.logger.error("Failed to send to Slack", error=str(e))
            return False

