"""
AI Model Providers Integration Module
Handles OpenRouter and NVIDIA NIM model selection and API calls
Separate from MCP - models managed via web portal
"""

import os
import json
from typing import Optional, Dict, List, Any
from enum import Enum
from dataclasses import dataclass, asdict
from datetime import datetime


class AIProviderType(Enum):
    """Supported AI providers"""
    OPENROUTER = "openrouter"
    NVIDIA_NIM = "nvidia"


@dataclass
class ModelConfig:
    """Configuration for an AI model"""
    provider: AIProviderType
    model_id: str
    api_key: str
    base_url: str
    headers: Dict[str, str] = None
    temperature: float = 0.2
    max_tokens: int = 1024
    timeout: int = 30


class OpenRouterProvider:
    """OpenRouter API provider integration"""
    
    BASE_URL = "https://openrouter.ai/api/v1"
    
    def __init__(self, api_key: str):
        """Initialize OpenRouter provider"""
        if not api_key:
            raise ValueError("OpenRouter API key is required")
        self.api_key = api_key
        self.base_url = self.BASE_URL
        
    def get_headers(self, site_url: Optional[str] = None, site_name: Optional[str] = None) -> Dict[str, str]:
        """Build headers for OpenRouter API calls"""
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
        if site_url:
            headers["HTTP-Referer"] = site_url
        if site_name:
            headers["X-OpenRouter-Title"] = site_name
        return headers
    
    async def call_model(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tools: Optional[List[Dict]] = None
    ) -> Dict[str, Any]:
        """Call OpenRouter model"""
        try:
            import httpx
            
            payload = {
                "model": model_id,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"
            
            headers = self.get_headers()
            
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                
                result = response.json()
                return {
                    "provider": "openrouter",
                    "model": model_id,
                    "content": result.get("choices", [{}])[0].get("message", {}).get("content", ""),
                    "usage": result.get("usage", {}),
                    "timestamp": datetime.utcnow().isoformat()
                }
        except Exception as e:
            return {
                "error": f"OpenRouter API error: {str(e)}",
                "provider": "openrouter",
                "model": model_id
            }
    
    async def list_models(self) -> Dict[str, Any]:
        """List available models on OpenRouter"""
        try:
            import httpx
            
            headers = self.get_headers()
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers=headers
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            return {"error": f"Failed to list models: {str(e)}"}


class NVIDIANIMProvider:
    """NVIDIA NIM API provider integration"""
    
    BASE_URL = "https://integrate.api.nvidia.com/v1"
    
    def __init__(self, api_key: str):
        """Initialize NVIDIA NIM provider"""
        if not api_key:
            raise ValueError("NVIDIA API key is required")
        self.api_key = api_key
        self.base_url = self.BASE_URL
    
    def get_headers(self) -> Dict[str, str]:
        """Build headers for NVIDIA API calls"""
        return {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json"
        }
    
    async def call_model(
        self,
        model_id: str,
        messages: List[Dict[str, str]],
        temperature: float = 0.2,
        max_tokens: int = 1024,
        tools: Optional[List[Dict]] = None,
        enable_reasoning: bool = False
    ) -> Dict[str, Any]:
        """Call NVIDIA NIM model"""
        try:
            import httpx
            
            payload = {
                "model": model_id,
                "messages": messages,
                "temperature": temperature,
                "max_tokens": max_tokens
            }
            
            if tools:
                payload["tools"] = tools
                payload["tool_choice"] = "auto"
            
            if enable_reasoning:
                payload["extra_body"] = {
                    "chat_template_kwargs": {"enable_thinking": True}
                }
            
            headers = self.get_headers()
            
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(
                    f"{self.base_url}/chat/completions",
                    json=payload,
                    headers=headers
                )
                response.raise_for_status()
                
                result = response.json()
                
                # Handle streaming responses if needed
                content = result.get("choices", [{}])[0].get("message", {}).get("content", "")
                reasoning = result.get("choices", [{}])[0].get("message", {}).get("reasoning", "")
                
                return {
                    "provider": "nvidia",
                    "model": model_id,
                    "content": content,
                    "reasoning": reasoning if reasoning else None,
                    "usage": result.get("usage", {}),
                    "timestamp": datetime.utcnow().isoformat()
                }
        except Exception as e:
            return {
                "error": f"NVIDIA NIM API error: {str(e)}",
                "provider": "nvidia",
                "model": model_id
            }
    
    async def list_models(self) -> Dict[str, Any]:
        """List available models on NVIDIA NIM"""
        try:
            import httpx
            
            headers = self.get_headers()
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.get(
                    f"{self.base_url}/models",
                    headers=headers
                )
                response.raise_for_status()
                return response.json()
        except Exception as e:
            return {"error": f"Failed to list models: {str(e)}"}


class AIProviderManager:
    """Manager for AI providers - selects and routes to appropriate provider"""
    
    def __init__(self):
        """Initialize provider manager"""
        self.providers = {}
        self.active_provider = None
        self.active_model = None
        self._load_from_env()
    
    def _load_from_env(self):
        """Load API keys from environment variables"""
        openrouter_key = os.getenv("OPENROUTER_API_KEY")
        nvidia_key = os.getenv("NVIDIA_API_KEY")
        
        if openrouter_key:
            self.providers[AIProviderType.OPENROUTER.value] = OpenRouterProvider(openrouter_key)
        
        if nvidia_key:
            self.providers[AIProviderType.NVIDIA_NIM.value] = NVIDIANIMProvider(nvidia_key)
    
    def register_provider(self, provider_type: AIProviderType, api_key: str):
        """Register a provider with API key"""
        if provider_type == AIProviderType.OPENROUTER:
            self.providers[AIProviderType.OPENROUTER.value] = OpenRouterProvider(api_key)
        elif provider_type == AIProviderType.NVIDIA_NIM:
            self.providers[AIProviderType.NVIDIA_NIM.value] = NVIDIANIMProvider(api_key)
        else:
            raise ValueError(f"Unknown provider type: {provider_type}")
    
    def set_active_model(self, provider: str, model_id: str):
        """Set the active model to use"""
        if provider not in self.providers:
            raise ValueError(f"Provider '{provider}' not registered")
        self.active_provider = provider
        self.active_model = model_id
    
    async def call_model(
        self,
        messages: List[Dict[str, str]],
        provider: Optional[str] = None,
        model_id: Optional[str] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """Call AI model with optional override"""
        provider = provider or self.active_provider
        model_id = model_id or self.active_model
        
        if not provider or not model_id:
            return {"error": "No active model configured. Set provider and model_id."}
        
        if provider not in self.providers:
            return {"error": f"Provider '{provider}' not registered"}
        
        p = self.providers[provider]
        return await p.call_model(model_id, messages, **kwargs)
    
    async def get_available_models(self, provider: Optional[str] = None) -> Dict[str, Any]:
        """Get available models from provider"""
        if provider:
            if provider not in self.providers:
                return {"error": f"Provider '{provider}' not registered"}
            p = self.providers[provider]
            return await p.list_models()
        
        # Return models from all registered providers
        all_models = {}
        for prov_name, prov in self.providers.items():
            models = await prov.list_models()
            all_models[prov_name] = models
        return all_models
    
    def get_status(self) -> Dict[str, Any]:
        """Get status of registered providers"""
        return {
            "providers": list(self.providers.keys()),
            "active_provider": self.active_provider,
            "active_model": self.active_model,
            "timestamp": datetime.utcnow().isoformat()
        }


# Global instance
_manager = None


def get_provider_manager() -> AIProviderManager:
    """Get or create global provider manager"""
    global _manager
    if _manager is None:
        _manager = AIProviderManager()
    return _manager


async def init_providers(openrouter_key: Optional[str] = None, nvidia_key: Optional[str] = None):
    """Initialize AI providers"""
    manager = get_provider_manager()
    
    if openrouter_key:
        manager.register_provider(AIProviderType.OPENROUTER, openrouter_key)
    
    if nvidia_key:
        manager.register_provider(AIProviderType.NVIDIA_NIM, nvidia_key)
    
    return manager
