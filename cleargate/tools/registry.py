from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cleargate.config import Settings
from cleargate.tools.base import CompositeToolClient
from cleargate.tools.github import GitHubRest, GitHubStub
from cleargate.tools.postgres import PostgresLive, PostgresStub
from cleargate.tools.slack import SlackLive, SlackStub


@dataclass
class ToolBackends:
    client: CompositeToolClient
    github: GitHubStub | GitHubRest
    postgres: PostgresStub | PostgresLive
    slack: SlackStub | SlackLive
    labels: dict[str, str]


def build_tools(settings: Settings, workdir: Path, force_stub: bool = False) -> ToolBackends:
    workdir.mkdir(parents=True, exist_ok=True)
    live = not force_stub
    github = (GitHubRest(settings.github_token, settings.github_repo)
              if live and settings.github == "live" else GitHubStub(workdir))
    postgres = (PostgresLive(settings.database_url)
                if live and settings.postgres == "live" else PostgresStub(workdir))
    slack = (SlackLive(settings.slack_bot_token, settings.slack_webhook_url)
             if live and settings.slack == "live" else SlackStub(workdir))
    labels = {
        "github": "GitHub REST" if isinstance(github, GitHubRest) else "local git repo (stub)",
        "postgres": "Postgres" if isinstance(postgres, PostgresLive) else "SQLite (stub)",
        "slack": "Slack" if isinstance(slack, SlackLive) else "JSONL outbox (stub)",
    }
    return ToolBackends(CompositeToolClient(github, postgres, slack), github, postgres, slack, labels)
