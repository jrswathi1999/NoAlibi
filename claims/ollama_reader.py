"""Ask the local Ollama model to extract one claim per claim type as JSON."""

# S1 timing (warm, one claim prompt): qwen2.5:7b 6.0 s, llama3.2:3b 3.9 s. Both under 15 s;
# qwen2.5:7b chosen for quality. Fallback if too slow: llama3.2:3b. Override with OLLAMA_MODEL.
DEFAULT_MODEL = "qwen2.5:7b"
FALLBACK_MODEL = "llama3.2:3b"
