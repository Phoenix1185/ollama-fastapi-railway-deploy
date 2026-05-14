#!/bin/bash
set -e

# Configure Ollama for low memory
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_MAX_LOADED_MODELS=1

# Start Ollama server in background
echo "Starting Ollama server..."
ollama serve &

# Start a background process to pull the model once Ollama is ready
(
    echo "Waiting for Ollama to be ready for model pull..."
    for i in {1..90}; do
        if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
            DEFAULT_MODEL=${DEFAULT_MODEL:-qwen2.5:0.5b}
            echo "Ollama ready, pulling model: $DEFAULT_MODEL"
            ollama pull $DEFAULT_MODEL || echo "Model pull failed, will retry on first request"
            break
        fi
        sleep 2
    done
) &

# Start FastAPI immediately so health checks pass
echo "Starting FastAPI on port 8000..."
# Use python -m uvicorn to ensure it uses the correct environment
exec python3 -m uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
