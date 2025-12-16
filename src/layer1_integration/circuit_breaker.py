"""Circuit breaker pattern implementation for connector resilience"""

from typing import Callable, Optional
from datetime import datetime, timedelta
import asyncio
from pybreaker import CircuitBreaker
import structlog
from ..common.exceptions import CircuitBreakerOpenError
from ..common.config import settings

logger = structlog.get_logger(__name__)


class ConnectorCircuitBreaker:
    """Circuit breaker for connector operations"""
    
    def __init__(
        self,
        name: str,
        failure_threshold: Optional[int] = None,
        timeout: Optional[int] = None,
        expected_exception: type = Exception
    ):

        """
        Initialize circuit breaker.
        
        Args:
            name: Identifier for logging and metrics.
            failure_threshold: Consecutive failures allowed before tripping (default: 5).
            timeout: Recovery timeout in seconds before attempting partial close (Half-Open).
            expected_exception: Exception type to catch as failure (default: Exception).
        """
        self.name = name
        self.failure_threshold = failure_threshold or settings.circuit_breaker_failure_threshold
        self.timeout = timeout or settings.circuit_breaker_timeout
        self.logger = logger.bind(circuit_breaker=name)
        
        self.breaker = CircuitBreaker(
            fail_max=self.failure_threshold,
            reset_timeout=self.timeout,

            listeners=[self._CircuitBreakerListener(self.logger)]
        )
    
    async def call(self, func: Callable, *args, **kwargs):
        """
        Execute a function with circuit breaker protection.
        
        If the breaker is open, it immediately raises `CircuitBreakerOpenError`.
        If the function fails, the failure counter increments.
        
        Args:
            func: The async or sync function to execute.
            *args: Positional arguments for the function.
            **kwargs: Keyword arguments for the function.
            
        Returns:
            The return value of `func` if successful.
            
        Raises:
            CircuitBreakerOpenError: If the circuit is currently open due to previous failures.
            Exception: Whatever exception `func` raises if it fails (and increments counter).
        """
        try:
            if asyncio.iscoroutinefunction(func):
                return await self.breaker.call_async(func, *args, **kwargs)
            else:
                return self.breaker.call(func, *args, **kwargs)
        except Exception as e:
            self.logger.warning("Circuit breaker caught exception", error=str(e), error_type=type(e).__name__)
            raise
    
    def get_state(self) -> str:
        """Get current circuit breaker state"""
        return self.breaker.current_state
    
    def is_open(self) -> bool:
        """Check if circuit breaker is open"""
        return self.breaker.current_state == "open"
    
    def reset(self) -> None:
        """Manually reset the circuit breaker"""
        self.breaker.reset()
        self.logger.info("Circuit breaker reset")
    
    class _CircuitBreakerListener:
        """Listener for circuit breaker state changes"""
        
        def __init__(self, logger):
            self.logger = logger
        
        def state_change(self, cb, old_state, new_state):
            """Called when circuit breaker state changes"""
            self.logger.warning(
                "Circuit breaker state changed",
                old_state=old_state,
                new_state=new_state,
                failure_count=cb.fail_counter
            )


class RuleBasedFallback:
    """Fallback to rule-based logic when circuit breaker is open"""
    
    def __init__(self):
        self.logger = logger
    
    async def process_alert(self, alert_data: dict) -> dict:
        """
        Process alert using static fallback logic when AI services are unavailable.
        
        Calculates a basic risk score based on severity fields.
        
        Args:
            alert_data: Raw dictionary of alert data.
            
        Returns:
            Alert dictionary enriched with `risk_score` and `processing_method` metadata.
        """
        self.logger.info("Using rule-based fallback", alert_id=alert_data.get("id"))
        
        # Simple rule-based risk scoring
        severity_map = {
            "critical": 10,
            "high": 7,
            "medium": 4,
            "low": 1
        }
        
        severity = alert_data.get("severity", "low").lower()
        base_score = severity_map.get(severity, 1)
        
        # Add time-based decay
        alert_time = alert_data.get("timestamp")
        if alert_time:
            try:
                alert_dt = datetime.fromisoformat(alert_time.replace("Z", "+00:00"))
                age_hours = (datetime.now(alert_dt.tzinfo) - alert_dt).total_seconds() / 3600
                # Reduce score for older alerts
                age_factor = max(0.5, 1 - (age_hours / 24))
                base_score = int(base_score * age_factor)
            except Exception:
                pass
        
        return {
            **alert_data,
            "risk_score": base_score,
            "processing_method": "rule_based_fallback",
            "source": alert_data.get("source", "unknown")
        }

