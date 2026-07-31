"""
Backend Configuration Settings
==============================
Reads environment variables for FastAPI backend server and guardian integration.
"""
from __future__ import annotations

import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    API_V1_STR: str = "/api/v1"
    PROJECT_NAME: str = "AI Code Guardian API"
    VERSION: str = "2.1.0"
    CORS_ORIGINS: List[str] = ["*"]
    DATABASE_URL: str = os.getenv("DATABASE_URL", "postgresql+asyncpg://guardian:guardian_pass@localhost:5432/guardian_db")
    
    # NVIDIA Nemotron Settings
    NVIDIA_API_KEY: str = ""
    NVIDIA_BASE_URL: str = "https://integrate.api.nvidia.com/v1"
    NVIDIA_MODEL: str = "meta/llama-3.1-8b-instruct"
    LLM_TEMPERATURE: float = 0.1
    LLM_MAX_TOKENS: int = 2048

    model_config = SettingsConfigDict(env_file=".env", extra="ignore")


settings = Settings()
