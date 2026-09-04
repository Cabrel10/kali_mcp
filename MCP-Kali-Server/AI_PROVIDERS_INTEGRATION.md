# AI Providers Integration - OpenRouter & NVIDIA NIM

## Overview

This module provides seamless integration with two major AI model providers:
- **OpenRouter**: Access to 400+ models from multiple providers
- **NVIDIA NIM**: Access to 190+ optimized models via NVIDIA's inference platform

The integration is **completely separate from the MCP** - models are managed via the web portal and exposed through a unified Python SDK.

## Architecture

### Separation of Concerns
```
┌─────────────────────┐
│   MCP Kali Server   │ (Security tools, reconnaissance)
└──────────┬──────────┘
           │
           ├─► Tool Execution Layer
           │
           └─► Reporting Engine

┌─────────────────────┐
│  AI Providers SDK   │ (OpenRouter + NVIDIA)
└──────────┬──────────┘
           │
           ├─► Model Selection
           ├─► API Routing
           └─► Response Parsing
```

**Key Principle**: The MCP Kali server is independent. AI provider selection happens at the web portal level, not in the tool infrastructure.

## Setup

### 1. Environment Variables

```bash
# OpenRouter API Key (get from https://openrouter.ai/keys)
export OPENROUTER_API_KEY="sk-or-..."

# NVIDIA API Key (get from https://build.nvidia.com/)
export NVIDIA_API_KEY="nvapi-..."
```

### 2. Installation

```bash
pip install httpx  # For async HTTP calls
```

### 3. Configuration Files

Create `.env` file in project root:
```
OPENROUTER_API_KEY=sk-or-...
NVIDIA_API_KEY=nvapi-...
```

## Usage

### Basic Usage

```python
import asyncio
from ai_providers import init_providers, get_provider_manager

async def main():
    # Initialize providers
    manager = await init_providers(
        openrouter_key="sk-or-...",
        nvidia_key="nvapi-..."
    )
    
    # Set active model
    manager.set_active_model("openrouter", "openai/gpt-4o")
    
    # Call model
    response = await manager.call_model(
        messages=[
            {"role": "system", "content": "You are a security expert"},
            {"role": "user", "content": "Analyze this finding..."}
        ]
    )
    
    print(response)

asyncio.run(main())
```

### Provider-Specific Calls

#### OpenRouter

```python
from ai_providers import OpenRouterProvider

provider = OpenRouterProvider("sk-or-...")

response = await provider.call_model(
    model_id="openai/gpt-4o",
    messages=[{"role": "user", "content": "Hello"}],
    temperature=0.2,
    max_tokens=1024
)
```

#### NVIDIA NIM

```python
from ai_providers import NVIDIANIMProvider

provider = NVIDIANIMProvider("nvapi-...")

response = await provider.call_model(
    model_id="nvidia/nemotron-3-ultra-550b-a55b",
    messages=[{"role": "user", "content": "Hello"}],
    enable_reasoning=True  # Enable extended reasoning
)
```

### List Available Models

```python
manager = get_provider_manager()

# Get models from specific provider
openrouter_models = await manager.get_available_models("openrouter")

# Get models from all providers
all_models = await manager.get_available_models()
```

## Available Models

### OpenRouter Highlights

**Large Models** (Best for reasoning):
- `openai/gpt-4o` - GPT-4 Omni (multimodal)
- `anthropic/claude-3.5-sonnet` - Claude 3.5 Sonnet
- `deepseek-ai/deepseek-v4-pro` - DeepSeek V4 Pro (1M context)

**Code Models** (Optimized for programming):
- `qwen/qwen3-coder-480b-a35b-instruct` - Qwen3 Coder (480B)
- `mistralai/mistral-large-3-675b-instruct-2512` - Mistral Large

**Fast & Efficient** (Low cost, good quality):
- `meta/llama-3.1-405b-instruct` - Llama 3.1 405B
- `openai/gpt-4-turbo` - GPT-4 Turbo

### NVIDIA NIM Highlights

**Ultra-Advanced Reasoning**:
- `nvidia/nemotron-3-ultra-550b-a55b` - Extended thinking (8K reasoning tokens)
- `nvidia/nemotron-3.5-lightning-30b-a3b` - Fast reasoning model

**Open Source (Optimized)**:
- `meta/llama-3.1-405b-instruct` - Llama 3.1 optimized
- `mistralai/mistral-large-3-675b-instruct-2512` - Mistral optimized

**Specialized**:
- `qwen/qwen3-coder-480b-a35b-instruct` - Programming tasks
- `deepseek-ai/deepseek-v4-pro` - Long context (1M tokens)

## Model Selection Strategy

### For Security Analysis
```python
# Option 1: OpenRouter GPT-4o (multimodal, latest)
manager.set_active_model("openrouter", "openai/gpt-4o")

# Option 2: NVIDIA Nemotron (extended reasoning)
manager.set_active_model("nvidia", "nvidia/nemotron-3-ultra-550b-a55b")
```

### For Code Analysis
```python
# Option 1: OpenRouter Qwen Coder
manager.set_active_model("openrouter", "qwen/qwen3-coder-480b-a35b-instruct")

# Option 2: NVIDIA Qwen Coder
manager.set_active_model("nvidia", "qwen/qwen3-coder-480b-a35b-instruct")
```

### For Cost-Optimized Tasks
```python
# Cheapest on OpenRouter
manager.set_active_model("openrouter", "openai/gpt-4:free")

# NVIDIA free tier (40 RPM limit)
manager.set_active_model("nvidia", "meta/llama-3.1-405b-instruct")
```

## Pricing & Limits

### OpenRouter
- **Free Tier**: Limited requests, no credit limit
- **Paid**: Pay-per-token model
- Check current rates: `https://openrouter.ai/models`

### NVIDIA NIM
- **Free Tier**: 40 requests/minute, 1M tokens/month
- **Paid**: Volume discounts available
- Perfect for prototyping

## Integration with MCP Kali

The AI providers module is independent but can integrate with MCP Kali for:

1. **Report Generation**: Use AI to summarize findings
2. **Vulnerability Analysis**: Parse and contextualize scan results
3. **Recommendation Engine**: Suggest next steps based on findings

Example integration (separate from this module):
```python
from kali_mcp_server import KillChainTracker
from ai_providers import get_provider_manager

async def analyze_findings(target, findings):
    manager = get_provider_manager()
    
    prompt = f"""
    Analyze these security findings for {target}:
    {json.dumps(findings, indent=2)}
    
    Provide:
    1. Risk assessment
    2. Recommended remediation
    3. Attack chain prediction
    """
    
    response = await manager.call_model(
        messages=[{"role": "user", "content": prompt}]
    )
    
    return response
```

## Environment File Example

Create `ai_providers.env`:
```ini
# OpenRouter Configuration
OPENROUTER_API_KEY=sk-or-1234567890...
OPENROUTER_MODEL_DEFAULT=openai/gpt-4o

# NVIDIA NIM Configuration
NVIDIA_API_KEY=nvapi-1234567890...
NVIDIA_MODEL_DEFAULT=nvidia/nemotron-3-ultra-550b-a55b

# Model Selection
ACTIVE_PROVIDER=openrouter
ACTIVE_MODEL=openai/gpt-4o
```

## API Response Format

### Standard Response
```json
{
    "provider": "openrouter",
    "model": "openai/gpt-4o",
    "content": "Analysis result...",
    "usage": {
        "prompt_tokens": 150,
        "completion_tokens": 250,
        "total_tokens": 400
    },
    "timestamp": "2026-09-04T13:00:00.000000"
}
```

### Error Response
```json
{
    "error": "OpenRouter API error: Connection timeout",
    "provider": "openrouter",
    "model": "openai/gpt-4o"
}
```

### NVIDIA with Reasoning
```json
{
    "provider": "nvidia",
    "model": "nvidia/nemotron-3-ultra-550b-a55b",
    "content": "Final answer...",
    "reasoning": "Step 1: ... Step 2: ...",
    "usage": {
        "prompt_tokens": 200,
        "completion_tokens": 300,
        "total_tokens": 500
    },
    "timestamp": "2026-09-04T13:00:00.000000"
}
```

## Troubleshooting

### API Key Issues
```bash
# Verify keys are set
echo $OPENROUTER_API_KEY
echo $NVIDIA_API_KEY

# Load from .env file
python -c "from dotenv import load_dotenv; load_dotenv()"
```

### Model Not Found
```python
# List all available models
models = await manager.get_available_models()
print(json.dumps(models, indent=2))
```

### Rate Limiting
OpenRouter and NVIDIA apply rate limits:
- OpenRouter: Depends on payment tier
- NVIDIA: 40 requests/minute on free tier

Implement backoff:
```python
import asyncio

async def call_with_retry(manager, messages, max_retries=3):
    for attempt in range(max_retries):
        response = await manager.call_model(messages)
        if "error" not in response:
            return response
        if attempt < max_retries - 1:
            await asyncio.sleep(2 ** attempt)  # Exponential backoff
    return response
```

## Notes

⚠️ **Important**: 
- This module is **independent from MCP Kali server**
- Models are managed via web portal configuration, not through this SDK
- Use this SDK for direct model calls in custom analysis workflows
- Keep API keys secure - use environment variables, never commit keys

## References

- OpenRouter: https://openrouter.ai/
- NVIDIA NIM: https://build.nvidia.com/
- OpenRouter Models: https://openrouter.ai/models
- NVIDIA NIM Models: https://catalog.ngc.nvidia.com/

---

**Last Updated**: September 4, 2026
**Module Version**: 1.0.0
