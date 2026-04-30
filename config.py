import os

AI_MODE = os.getenv("AI_MODE", "off")  # off / local

OLLAMA_URL = os.getenv(
    "OLLAMA_URL",
    "http://172.30.176.1:11434/api/generate"
)

OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "qwen2.5:3b")