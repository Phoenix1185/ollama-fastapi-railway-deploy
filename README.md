# Ollama/Azure OpenAI FastAPI Server (v3.0 - Fly.io Ready)

Self-hosted LLM API with API key authentication, supporting both Ollama and Azure OpenAI.

## Deploy to Fly.io

### 1. Install flyctl and login
```bash
curl -L https://fly.io/install.sh | sh
fly auth login
```

### 2. Launch app
```bash
fly launch --name ollama-fastapi-railway --region iad --no-deploy
```

### 3. Set secrets
```bash
fly secrets set MASTER_KEY=your-strong-master-key-here
```

### 4. Deploy
```bash
fly deploy
```

## Configuration

This application supports both Ollama and Azure OpenAI. By default, it uses Ollama. To enable Azure OpenAI, you need to set the following environment variables:

| Variable                       | Description                                      | Default Value              |
|--------------------------------|--------------------------------------------------|----------------------------|
| `AZURE_OPENAI_ENDPOINT`        | Your Azure OpenAI endpoint URL                   | None                       |
| `AZURE_OPENAI_KEY`             | Your Azure OpenAI API Key                        | None                       |
| `AZURE_OPENAI_DEPLOYMENT_NAME` | The name of your Azure OpenAI model deployment   | None                       |
| `AZURE_OPENAI_API_VERSION`     | The API version for Azure OpenAI                 | `2024-02-15-preview`       |

If `AZURE_OPENAI_ENDPOINT` and `AZURE_OPENAI_KEY` are provided, the application will attempt to use Azure OpenAI for chat completions. If a specific model is requested that matches `AZURE_OPENAI_DEPLOYMENT_NAME`, or if no model is specified and Azure is configured, it will route the request to Azure OpenAI. Otherwise, it will fall back to Ollama.

### Example Azure OpenAI Secret Setup (Fly.io)
```bash
fly secrets set \
  AZURE_OPENAI_ENDPOINT="https://YOUR_RESOURCE_NAME.openai.azure.com/" \
  AZURE_OPENAI_KEY="YOUR_AZURE_OPENAI_KEY" \
  AZURE_OPENAI_DEPLOYMENT_NAME="YOUR_DEPLOYMENT_NAME" \
  AZURE_OPENAI_API_VERSION="2024-02-15-preview"
```

## Fly.io Free Tier Limits
- **Memory**: 2GB max (this config is optimized for it)
- **CPU**: 2 shared cores
- **Model**: Use qwen2.5:0.5b (~300MB) or tinyllama (~600MB) for Ollama
- **Storage**: Ephemeral (models re-download on restart)

## For Bigger Models
Upgrade to paid plan or use:
```bash
fly scale memory 4096  # 4GB - requires paid plan
```

## Authentication

### Create API Key (needs MASTER_KEY)
```bash
curl -X POST https://your-app.fly.dev/admin/keys \
  -H "X-Master-Key: your-master-key" \
  -H "Content-Type: application/json" \
  -d '{"name": "my-app"}'
```

### Use API Key

#### With Ollama
```python
import requests

url = "https://your-app.fly.dev/v1/chat/completions"
headers = {
    "Authorization": "Bearer ollama_xxxxxxxx",
    "Content-Type": "application/json"
}
data = {
    "model": "qwen2.5:0.5b",
    "messages": [{"role": "user", "content": "Hello!"}]
}
res = requests.post(url, json=data, headers=headers)
print(res.json())
```

#### With Azure OpenAI
If you have configured Azure OpenAI, you can use it by specifying the `AZURE_OPENAI_DEPLOYMENT_NAME` as the model. If no model is specified and Azure is configured, it will be used by default.

```python
import requests

url = "https://your-app.fly.dev/v1/chat/completions"
headers = {
    "Authorization": "Bearer ollama_xxxxxxxx", # Use your generated API key
    "Content-Type": "application/json"
}
data = {
    "model": "YOUR_AZURE_OPENAI_DEPLOYMENT_NAME", # Or omit for default Azure usage
    "messages": [{"role": "user", "content": "Hello from Azure!"}]
}
res = requests.post(url, json=data, headers=headers)
print(res.json())
```

## Pages
- /ui - Dashboard
- /api-docs - API reference
- /docs - Swagger UI
- /redoc - ReDoc
- /health - Status (no auth)

## Models That Fit in 2GB (for Ollama)
| Model | Size | Works? |
|-------|------|--------|
| qwen2.5:0.5b | ~300MB | Yes |
| tinyllama | ~600MB | Yes |
| phi3:mini | ~2GB | Maybe (tight) |
| llama3.2:1b | ~1.3GB | Maybe |
