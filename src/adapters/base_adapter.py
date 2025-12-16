"""Base adapter interface for output channels"""

from abc import ABC, abstractmethod
from typing import Dict, Any
import structlog

logger = structlog.get_logger(__name__)


class BaseOutputAdapter(ABC):
    """Base class for output adapters"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logger.bind(adapter=self.__class__.__name__)
    
    @abstractmethod
    async def send(self, message: Dict[str, Any]) -> bool:
        """
        Send a message/notification
        
        Args:
            message: Message dictionary with decision, risk score, etc.
            
        Returns:
            True if sent successfully, False otherwise
        """
        pass
    
    @abstractmethod
    async def format_message(self, decision: Dict[str, Any], reasoning_log: list) -> str:
        """
        Format a decision into a message
        
        Args:
            decision: Decision dictionary
            reasoning_log: List of reasoning log entries
            
        Returns:
            Formatted message string
        """
        pass

