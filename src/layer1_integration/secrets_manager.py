"""Secrets management for storing and retrieving API credentials"""

from abc import ABC, abstractmethod
from typing import Dict, Optional, Any
import structlog
from ..common.exceptions import SecretsManagementError
from ..common.config import settings

logger = structlog.get_logger(__name__)


class SecretsManager(ABC):
    """Abstract base class for secrets management backends"""
    
    @abstractmethod
    async def store_secret(self, key: str, value: str, metadata: Optional[Dict] = None) -> None:
        """Store a secret"""
        pass
    
    @abstractmethod
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve a secret"""
        pass
    
    @abstractmethod
    async def delete_secret(self, key: str) -> None:
        """Delete a secret"""
        pass
    
    @abstractmethod
    async def list_secrets(self, prefix: str = "") -> List[str]:
        """List all secret keys with optional prefix"""
        pass


class HashiCorpVaultManager(SecretsManager):
    """HashiCorp Vault secrets manager"""
    
    def __init__(self):
        try:
            import hvac
        except ImportError:
            raise SecretsManagementError("hvac library not installed. Install with: pip install hvac")
        
        self.vault_addr = settings.vault_addr
        self.vault_token = settings.vault_token
        self.client = hvac.Client(url=self.vault_addr, token=self.vault_token)
        self.logger = logger.bind(backend="vault")
        
        if not self.client.is_authenticated():
            raise SecretsManagementError("Vault authentication failed")
    
    async def store_secret(self, key: str, value: str, metadata: Optional[Dict] = None) -> None:
        """Store secret in Vault"""
        try:
            secret_path = f"secret/data/{key}"
            self.client.secrets.kv.v2.create_or_update_secret(
                path=key,
                secret={"value": value, "metadata": metadata or {}}
            )
            self.logger.info("Secret stored", key=key)
        except Exception as e:
            self.logger.error("Failed to store secret", key=key, error=str(e))
            raise SecretsManagementError(f"Failed to store secret: {e}")
    
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve secret from Vault"""
        try:
            response = self.client.secrets.kv.v2.read_secret_version(path=key)
            if response and "data" in response and "data" in response["data"]:
                return response["data"]["data"].get("value")
            return None
        except Exception as e:
            self.logger.error("Failed to retrieve secret", key=key, error=str(e))
            return None
    
    async def delete_secret(self, key: str) -> None:
        """Delete secret from Vault"""
        try:
            self.client.secrets.kv.v2.delete_metadata_and_all_versions(path=key)
            self.logger.info("Secret deleted", key=key)
        except Exception as e:
            self.logger.error("Failed to delete secret", key=key, error=str(e))
            raise SecretsManagementError(f"Failed to delete secret: {e}")
    
    async def list_secrets(self, prefix: str = "") -> List[str]:
        """List secrets from Vault"""
        try:
            response = self.client.secrets.kv.v2.list_secrets(path=prefix)
            if response and "data" in response and "keys" in response["data"]:
                return response["data"]["keys"]
            return []
        except Exception as e:
            self.logger.error("Failed to list secrets", prefix=prefix, error=str(e))
            return []


class AWSSecretsManager(SecretsManager):
    """AWS Secrets Manager backend"""
    
    def __init__(self):
        try:
            import boto3
        except ImportError:
            raise SecretsManagementError("boto3 not installed. Install with: pip install boto3")
        
        self.region = settings.aws_region or "us-east-1"
        self.client = boto3.client("secretsmanager", region_name=self.region)
        self.logger = logger.bind(backend="aws", region=self.region)
    
    async def store_secret(self, key: str, value: str, metadata: Optional[Dict] = None) -> None:
        """Store secret in AWS Secrets Manager"""
        try:
            try:
                # Try to update existing secret
                self.client.update_secret(SecretId=key, SecretString=value)
                self.logger.info("Secret updated", key=key)
            except self.client.exceptions.ResourceNotFoundException:
                # Create new secret
                self.client.create_secret(Name=key, SecretString=value)
                self.logger.info("Secret created", key=key)
        except Exception as e:
            self.logger.error("Failed to store secret", key=key, error=str(e))
            raise SecretsManagementError(f"Failed to store secret: {e}")
    
    async def get_secret(self, key: str) -> Optional[str]:
        """Retrieve secret from AWS Secrets Manager"""
        try:
            response = self.client.get_secret_value(SecretId=key)
            return response.get("SecretString")
        except self.client.exceptions.ResourceNotFoundException:
            return None
        except Exception as e:
            self.logger.error("Failed to retrieve secret", key=key, error=str(e))
            return None
    
    async def delete_secret(self, key: str) -> None:
        """Delete secret from AWS Secrets Manager"""
        try:
            self.client.delete_secret(SecretId=key, ForceDeleteWithoutRecovery=True)
            self.logger.info("Secret deleted", key=key)
        except Exception as e:
            self.logger.error("Failed to delete secret", key=key, error=str(e))
            raise SecretsManagementError(f"Failed to delete secret: {e}")
    
    async def list_secrets(self, prefix: str = "") -> List[str]:
        """List secrets from AWS Secrets Manager"""
        try:
            response = self.client.list_secrets()
            secrets = [s["Name"] for s in response.get("SecretList", [])]
            if prefix:
                secrets = [s for s in secrets if s.startswith(prefix)]
            return secrets
        except Exception as e:
            self.logger.error("Failed to list secrets", prefix=prefix, error=str(e))
            return []


def get_secrets_manager() -> SecretsManager:
    """
    Factory function to get the appropriate secrets manager based on configuration
    
    Returns:
        SecretsManager instance
    """
    vault_type = settings.vault_type.lower()
    
    if vault_type == "vault":
        return HashiCorpVaultManager()
    elif vault_type == "aws":
        return AWSSecretsManager()
    elif vault_type == "azure":
        # Azure implementation would go here
        raise SecretsManagementError("Azure Key Vault not yet implemented")
    else:
        raise SecretsManagementError(f"Unknown vault type: {vault_type}")

