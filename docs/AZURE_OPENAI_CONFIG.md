# Azure OpenAI Configuration Guide

This AI Orchestrator API supports both standard OpenAI and Azure OpenAI services. You can switch between them by modifying your environment configuration.

## Configuration Options

### Standard OpenAI (Default)
```bash
# Standard OpenAI Configuration
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_MAX_TOKENS=2000
OPENAI_TEMPERATURE=0.7

# Disable Azure OpenAI
AZURE_OPENAI_ENABLED=false
```

### Azure OpenAI
```bash
# Standard OpenAI Configuration (still required as fallback)
OPENAI_API_KEY=your-openai-api-key-here
OPENAI_MODEL=gpt-4-turbo-preview
OPENAI_MAX_TOKENS=2000
OPENAI_TEMPERATURE=0.7

# Enable Azure OpenAI
AZURE_OPENAI_ENABLED=true
AZURE_OPENAI_ENDPOINT=https://your-resource-name.openai.azure.com/
AZURE_OPENAI_API_KEY=your-azure-openai-api-key
AZURE_OPENAI_DEPLOYMENT_NAME=your-deployment-name
AZURE_OPENAI_API_VERSION=2024-12-01-preview
```

## Environment Variables

| Variable | Required | Description | Example |
|----------|----------|-------------|---------|
| `AZURE_OPENAI_ENABLED` | Yes | Set to `true` to use Azure OpenAI, `false` for standard OpenAI | `true` |
| `AZURE_OPENAI_ENDPOINT` | Yes* | Your Azure OpenAI resource endpoint | `https://oai-cec-de-germany-west-central.openai.azure.com/` |
| `AZURE_OPENAI_API_KEY` | Yes* | Your Azure OpenAI API key | `FSd9gA8V...` |
| `AZURE_OPENAI_DEPLOYMENT_NAME` | Yes* | The name of your model deployment in Azure | `gpt-4o` |
| `AZURE_OPENAI_API_VERSION` | No | Azure OpenAI API version (defaults to `2024-12-01-preview`) | `2024-12-01-preview` |

*Required only when `AZURE_OPENAI_ENABLED=true`

## Current Configuration

Based on your current `.env` file, you have:

- **Azure OpenAI Enabled**: ✅ `true`
- **Endpoint**: `https://oai-cec-de-germany-west-central.openai.azure.com/`
- **Deployment**: `gpt-4o`
- **API Version**: `2024-12-01-preview`

## How It Works

1. **Configuration Loading**: The system loads both standard OpenAI and Azure OpenAI settings from environment variables
2. **Service Selection**: If `AZURE_OPENAI_ENABLED=true`, the AI service uses Azure OpenAI configuration
3. **Client Initialization**: The appropriate OpenAI client is created based on the configuration
4. **Model/Deployment Name**: When using Azure OpenAI, the `AZURE_OPENAI_DEPLOYMENT_NAME` is used instead of `OPENAI_MODEL`

## Error Handling

The system validates configuration at startup:

- **Azure OpenAI Enabled**: Requires `AZURE_OPENAI_API_KEY`, `AZURE_OPENAI_ENDPOINT`, and `AZURE_OPENAI_DEPLOYMENT_NAME`
- **Standard OpenAI**: Requires `OPENAI_API_KEY`

If required configuration is missing, the service will fail to start with a descriptive error message.

## Switching Between Configurations

To switch from Azure OpenAI to standard OpenAI:
1. Set `AZURE_OPENAI_ENABLED=false` in your `.env` file
2. Ensure `OPENAI_API_KEY` is properly set
3. Restart the application

To switch from standard OpenAI to Azure OpenAI:
1. Set all required Azure OpenAI environment variables
2. Set `AZURE_OPENAI_ENABLED=true` in your `.env` file
3. Restart the application

## Testing Configuration

You can verify your configuration is working by checking the service logs at startup. The system will indicate whether it's using Azure OpenAI or standard OpenAI.

## Supported Features

Both Azure OpenAI and standard OpenAI support the same API features used in this application:
- Chat completions
- Conversation summaries
- Workflow parameter validation
- Intent detection and processing

The API interface remains the same regardless of which service you choose.