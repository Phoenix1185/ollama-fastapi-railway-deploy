#!/bin/bash
set -e
export OLLAMA_NUM_PARALLEL=1
export OLLAMA_MAX_LOADED_MODELS=1
echo "Starting Ollama server..."
ollama serve &
for i in {1..90}; do
  if curl -s http://localhost:11434/api/tags > /dev/null 2>&1; then
    echo "Ollama ready"
    break
  fi
  sleep 1
done
DEFAULT_MODEL=${DEFAULT_MODEL:-qwen2.5:0.5b}
echo "Pulling model: $DEFAULT_MODEL"
ollama pull $DEFAULT_MODEL || true
echo "Starting FastAPI on port 8000..."
exec uvicorn main:app --host 0.0.0.0 --port 8000 --workers 1
