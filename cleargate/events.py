from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from enum import StrEnum
from typing import Any


class Verb(StrEnum):
    ALLOW = "ALLOW"
    NARROW = "NARROW"
    BLOCK = "BLOCK"
    ESCALATE = "ESCALATE"
    UNGUARDED = "UNGUARDED"


class Kind(StrEnum):
    TASK_OPEN = "task_open"
    DELEGATION = "delegation"
    CALL = "call"
    APPROVAL = "approval"
    TASK_CLOSE = "task_close"
    NOTICE = "notice"
    KILL = "kill"


@dataclass
class Decision:
    kind: Kind
    verb: Verb
    source: str
    run_id: str
    mode: str
    task_id: str
    agent: str
    delegation_chain: list[str]
    tool: str | None = None
    args: dict[str, Any] = field(default_factory=dict)
    rule: str = ""
    reason: str = ""
    approver: str | None = None
    executed: bool = False
    outside_task: bool = False
    result_preview: str = ""
    # Who decided and on what grounds. `rule` is the deciding rule id (local) or the runtime's
    # policy name; `real_world_reason` is the real-world control behind it (policy.yaml `reason:`).
    policy_name: str = ""
    policy_version: str = ""
    real_world_reason: str = ""
    intent_mismatch: str = ""
    denial_step: str = ""
    args_digest: str = ""
    meta: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["kind"] = str(self.kind)
        data["verb"] = str(self.verb)
        return data
