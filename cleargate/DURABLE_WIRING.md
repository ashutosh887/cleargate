# Durable approval: wiring for cleargate/web/app.py

`cleargate serve --durable` passes `durable=True` to `create_app`. The web lane owns `app.py`, so
the change is listed here. Each step is an exact before/after replacement; nothing else in the app
changes. With `durable=False` (the default) every path is the same as today.

What it does: a gated escalation hibernates to a receipt in `.cleargate/durable.db` and the run
thread ends. The existing approve endpoints (button, voice, Slack) then record the decision on the
receipt and resume the run on a new thread, like a webhook. After a server restart, pending
receipts are announced again so the UI and the voice endpoint still see them.

1. Import the durable helpers.

Before:
```python
from cleargate.scenario import Run
```
After:
```python
from cleargate.durable import ReceiptError, announce_pending, approve_and_resume
from cleargate.scenario import Run
```

2. Accept the flag.

Before:
```python
def create_app(approvals: str = "web", force_stub: bool = False) -> FastAPI:
```
After:
```python
def create_app(approvals: str = "web", force_stub: bool = False, durable: bool = False) -> FastAPI:
```

3. Re-announce receipts left pending by an earlier server process.

Before:
```python
    bus.listen(track)
```
After:
```python
    bus.listen(track)
    if durable:
        announce_pending(settings, bus)
```

4. Runs hibernate instead of blocking a thread.

Before:
```python
        return Run(settings, bus, approvals=approvals, force_stub=force_stub, prompt=prompt or None)
```
After:
```python
        return Run(settings, bus, approvals=approvals, force_stub=force_stub, prompt=prompt or None, durable=durable)
```

5. Voice approval works with no live run (the code is checked against each pending receipt's verifier).

Before:
```python
        if run is None:
            raise HTTPException(404, "no run in progress")
        if not re.fullmatch(r"[0-9a-f]{4,}", heard):
```
After:
```python
        if run is None and not durable:
            raise HTTPException(404, "no run in progress")
        if not re.fullmatch(r"[0-9a-f]{4,}", heard):
```

Before:
```python
        if run.broker.resolve_by_code(heard, VOICE_APPROVER, "voice"):
```
After:
```python
        if durable:
            try:
                return approve_and_resume(settings, bus, VOICE_APPROVER, "voice", code=heard)
            except ReceiptError as exc:
                raise HTTPException(403, str(exc))
        if run.broker.resolve_by_code(heard, VOICE_APPROVER, "voice"):
```

6. The approve/reject button: the approval id is the receipt id.

Before:
```python
        if run is None or not run.broker.resolve(approval_id, bool(body.get("approved")), WEB_APPROVER, "web"):
```
After:
```python
        if durable:
            try:
                approve_and_resume(settings, bus, WEB_APPROVER, "web", receipt_id=approval_id,
                                   approved=bool(body.get("approved")))
            except ReceiptError as exc:
                raise HTTPException(404, str(exc))
            return {"ok": True}
        if run is None or not run.broker.resolve(approval_id, bool(body.get("approved")), WEB_APPROVER, "web"):
```

7. Slack buttons carry the receipt id the same way.

Before:
```python
        if run is not None:
            run.broker.resolve(action["value"], action["action_id"] == "cleargate_approve", approver, "slack")
```
After:
```python
        if durable:
            try:
                approve_and_resume(settings, bus, approver, "slack", receipt_id=action["value"],
                                   approved=action["action_id"] == "cleargate_approve")
            except ReceiptError as exc:
                return {"text": f"Not recorded: {exc}"}
        elif run is not None:
            run.broker.resolve(action["value"], action["action_id"] == "cleargate_approve", approver, "slack")
```

Notes for the UI: in durable mode an `approval_pending` event has `durable: true`, an `expires`
time, and an `id` that is the receipt id. Re-announced receipts carry `code: null` (only a verifier
is stored). A resumed run publishes `mode_start` with `resumed_from`, then the usual decision and
`mode_done` events for the same run id.
