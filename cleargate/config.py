from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _load_dotenv() -> None:
    env = ROOT / ".env"
    if not env.exists():
        return
    for line in env.read_text().splitlines():
        key, sep, value = line.strip().partition("=")
        if sep and key and not key.startswith("#"):
            os.environ.setdefault(key.strip(), value.strip())


_load_dotenv()


def _env(name: str, default: str = "") -> str:
    return os.environ.get(name, default).strip() or default


@dataclass(frozen=True)
class Settings:
    github: str = field(default_factory=lambda: _env("CLEARGATE_GITHUB", "stub"))
    postgres: str = field(default_factory=lambda: _env("CLEARGATE_POSTGRES", "stub"))
    slack: str = field(default_factory=lambda: _env("CLEARGATE_SLACK", "stub"))
    enforcer: str = field(default_factory=lambda: _env("CLEARGATE_ENFORCER", "local"))
    llm: str = field(default_factory=lambda: _env("CLEARGATE_LLM", "scripted"))
    openai_base_url: str = field(default_factory=lambda: _env("OPENAI_BASE_URL"))
    openai_api_key: str = field(default_factory=lambda: _env("OPENAI_API_KEY"))
    model: str = field(default_factory=lambda: _env("CLEARGATE_MODEL", "gpt-4o-mini"))
    aws_region: str = field(default_factory=lambda: _env("AWS_REGION", "ap-south-1"))
    bedrock_model_id: str = field(default_factory=lambda: _env("BEDROCK_MODEL_ID", "global.anthropic.claude-sonnet-5-5"))
    bedrock_fallback_model_id: str = field(
        default_factory=lambda: _env("BEDROCK_FALLBACK_MODEL_ID", "global.anthropic.claude-haiku-5-5"))
    anthropic_api_key: str = field(default_factory=lambda: _env("ANTHROPIC_API_KEY"))
    anthropic_model: str = field(default_factory=lambda: _env("ANTHROPIC_MODEL", "claude-sonnet-5-5"))
    llm_fallback_models: str = field(default_factory=lambda: _env("CLEARGATE_LLM_FALLBACK_MODELS"))
    llm_timeout: float = field(default_factory=lambda: float(_env("CLEARGATE_LLM_TIMEOUT", "45")))
    llm_max_tokens: int = field(default_factory=lambda: int(_env("CLEARGATE_LLM_MAX_TOKENS", "1024")))
    github_token: str = field(default_factory=lambda: _env("GITHUB_TOKEN"))
    github_repo: str = field(default_factory=lambda: _env("GITHUB_REPO"))
    issue: int = field(default_factory=lambda: int(_env("CLEARGATE_ISSUE", "1")))
    database_url: str = field(default_factory=lambda: _env("DATABASE_URL"))
    slack_bot_token: str = field(default_factory=lambda: _env("SLACK_BOT_TOKEN"))
    slack_webhook_url: str = field(default_factory=lambda: _env("SLACK_WEBHOOK_URL"))
    slack_approval_channel: str = field(default_factory=lambda: _env("SLACK_APPROVAL_CHANNEL", "#inc-4471"))
    slack_signing_secret: str = field(default_factory=lambda: _env("SLACK_SIGNING_SECRET"))
    policy_path: Path = field(default_factory=lambda: Path(_env("CLEARGATE_POLICY", str(ROOT / "policy.yaml"))))
    records_dir: Path = field(default_factory=lambda: Path(_env("CLEARGATE_RECORDS_DIR", str(ROOT / "records"))))
    state_dir: Path = field(default_factory=lambda: Path(_env("CLEARGATE_STATE_DIR", str(ROOT / ".cleargate"))))
