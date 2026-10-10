from __future__ import annotations

import asyncio
import json
import os
import re
import socket
import threading
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from fastapi import FastAPI, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, Response, StreamingResponse

from cleargate.approval import verify_slack_signature
from cleargate.bus import EventBus
from cleargate.config import Settings
from cleargate.scenario import Run
from cleargate.voice import SarvamVoice, VoiceUnavailable

STATIC = Path(__file__).parent / "static"
# Set server-side: the browser never names who approved.
VOICE_APPROVER = "on-call engineer (voice)"
WEB_APPROVER = "on-call engineer (web)"

_SPOKEN = {
    "zero": "0", "oh": "0", "one": "1", "won": "1", "two": "2", "to": "2", "too": "2", "three": "3", "four": "4",
    "for": "4", "five": "5", "six": "6", "seven": "7", "eight": "8", "ate": "8", "nine": "9",
    "a": "a", "ay": "a", "eh": "a", "alpha": "a", "b": "b", "be": "b", "bee": "b", "bravo": "b",
    "c": "c", "see": "c", "sea": "c", "charlie": "c", "d": "d", "dee": "d", "delta": "d",
    "e": "e", "ee": "e", "echo": "e", "f": "f", "ef": "f", "eff": "f", "foxtrot": "f",
}


def spoken_code(transcript: str) -> str:
    """Pull the hex code out of e.g. 'approve 3 f a 9', 'approve 3fa9' or 'approve three foxtrot alpha nine'."""
    text = transcript.lower()
    match = re.search(r"approv\w*\s+(.*)", text)
    tail = match.group(1) if match else text
    out = ""
    for word in re.findall(r"[a-z0-9]+", tail):
        if word in _SPOKEN:
            out += _SPOKEN[word]
        elif re.fullmatch(r"[0-9a-f]+", word):
            out += word
        elif out:
            break
    return out


def _decision_event(entry: dict[str, Any]) -> dict[str, Any] | None:
    payload = entry.get("payload", {})
    if payload.get("kind") in (None, "header", "seal"):
        return None
    return {"type": "decision", **payload, "args_digest": entry.get("args_digest"), "seq": entry.get("seq")}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def create_app(approvals: str = "web", force_stub: bool = False) -> FastAPI:
    settings = Settings()
    bus = EventBus()
    app = FastAPI(title="ClearGate")
    state: dict[str, Any] = {"run": None, "thread": None, "pending": {}}

    def track(event: dict[str, Any]) -> None:
        if event.get("type") == "approval_pending":
            state["pending"][event["id"]] = event
        elif event.get("type") == "approval_resolved":
            state["pending"].pop(event.get("id"), None)

    bus.listen(track)

    def busy() -> bool:
        thread = state["thread"]
        return thread is not None and thread.is_alive()

    def make_run(prompt: str | None) -> Run:
        return Run(settings, bus, approvals=approvals, force_stub=force_stub, prompt=prompt or None)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/config")
    def config() -> dict[str, Any]:
        return {"enforcer": settings.enforcer, "llm": settings.llm, "approvals": approvals,
                "tools": {"github": settings.github, "postgres": settings.postgres, "slack": settings.slack},
                "stub": force_stub}

    @app.post("/api/run")
    async def start_run(request: Request) -> dict[str, Any]:
        if busy():
            raise HTTPException(409, "a run is already in progress")
        prompt = ""
        try:
            body = await request.json()
            prompt = str((body or {}).get("prompt") or "").strip()
        except Exception:
            pass
        bus.reset()
        state["pending"].clear()
        run = make_run(prompt or None)
        bus.publish({"type": "run_start", "run_id": run.run_id, "enforcer": settings.enforcer, "prompt": prompt,
                     "replay": False})
        state["run"] = run
        state["thread"] = threading.Thread(target=run.run_both, daemon=True, name="cleargate-run")
        state["thread"].start()
        # Run hands the prompt to open_task (runtime narrowing and intent); the team's steps stay scripted.
        return {"run_id": run.run_id, "prompt": prompt, "prompt_used": run.prompt is not None,
                "prompt_scope": "task intent for narrowing; team steps unchanged" if run.prompt else ""}

    @app.post("/api/approvals/voice")
    async def voice_approval(request: Request) -> dict[str, Any]:
        body = await request.json()
        transcript = str(body.get("transcript") or "")
        heard = spoken_code(transcript) or str(body.get("code") or "").lower()
        run = state["run"]
        if run is None:
            raise HTTPException(404, "no run in progress")
        if not re.fullmatch(r"[0-9a-f]{4,}", heard):
            raise HTTPException(400, f"no digest code heard in {transcript!r}")
        if "reject" in transcript.lower():
            raise HTTPException(400, "say 'approve <code>'; use the Reject button to reject")
        if run.broker.resolve_by_code(heard, VOICE_APPROVER, "voice"):
            return {"ok": True, "code": heard, "via": "voice"}
        raise HTTPException(403, f"spoken code {heard!r} does not match exactly one pending approval digest")

    @app.post("/api/approvals/{approval_id}")
    async def decide(approval_id: str, request: Request) -> dict[str, bool]:
        run = state["run"]
        body = await request.json()
        if run is None or not run.broker.resolve(approval_id, bool(body.get("approved")), WEB_APPROVER, "web"):
            raise HTTPException(404, "no pending approval with that id")
        return {"ok": True}

    def replay_worker(stock: Path | None, gated: Path, pace: float) -> None:
        run_id = gated.name.removesuffix("-gated.jsonl")
        bus.publish({"type": "run_start", "run_id": run_id, "replay": True, "record": str(gated)})
        events: list[tuple[float, int, dict[str, Any]]] = []
        sources: dict[str, str] = {}
        for order, (mode, path) in enumerate((("stock", stock), ("gated", gated))):
            if path is None:
                continue
            for entry in _read_jsonl(path):
                event = _decision_event(entry)
                if event is None:
                    continue
                sources.setdefault(mode, str(event.get("source") or ""))
                events.append((float(event.get("timestamp") or 0), order, event))
        events.sort(key=lambda item: (item[2].get("seq") or 0, item[1]))
        for mode, source in sources.items():
            bus.publish({"type": "mode_start", "mode": mode, "run_id": run_id, "source": source, "replay": True})
        for _, _, event in events:
            bus.publish(event)
            time.sleep(pace)
        for mode, path in (("stock", stock), ("gated", gated)):
            if path is None:
                continue
            bus.publish(replay_summary(mode, path, sources.get(mode, "")))
        bus.publish({"type": "run_done", "run_id": run_id, "replay": True})

    def replay_summary(mode: str, path: Path, source: str) -> dict[str, Any]:
        done: dict[str, Any] = {"type": "mode_done", "mode": mode, "record": str(path), "source": source,
                                "replay": True, "counts": {}, "verdict": "", "reasons": [], "verified": ""}
        try:
            from cleargate.scenario import ModeResult, count, go_no_go, verify_record

            result = ModeResult(mode, source, path)
            result.counts = count(bus.history, mode)
            result.verified = verify_record(path)
            merged = result.counts.get("merged_by")
            go_no_go(result, bool(merged), False)
            done.update(counts=result.counts, verdict=result.verdict, verified=result.verified,
                        reasons=[r.replace("bug fixed on main", "fix merged (replayed from the signed record)")
                                 for r in result.reasons])
        except Exception as exc:
            done["reasons"] = [f"summary unavailable in replay: {type(exc).__name__}: {exc}"]
        return done

    @app.post("/api/replay")
    def start_replay(pace: float = 0.7, run_id: str = "") -> dict[str, Any]:
        if busy():
            raise HTTPException(409, "a run is already in progress")
        records = settings.records_dir
        gated_all = sorted(records.glob(f"{run_id}*-gated.jsonl" if run_id else "*-gated.jsonl"))
        if not gated_all:
            raise HTTPException(404, f"no gated record in {records}")
        gated = gated_all[-1]
        stock = gated.with_name(gated.name.replace("-gated.jsonl", "-stock.jsonl"))
        bus.reset()
        state["pending"].clear()
        state["run"] = None
        pace = max(0.05, min(pace, 5.0))
        state["thread"] = threading.Thread(target=replay_worker, args=(stock if stock.exists() else None, gated, pace),
                                           daemon=True, name="cleargate-replay")
        state["thread"].start()
        return {"replaying": gated.name, "stock": stock.name if stock.exists() else None, "pace": pace}

    @app.post("/slack/interactions")
    async def slack_interactions(request: Request) -> dict[str, str]:
        raw = await request.body()
        if not settings.slack_signing_secret:
            raise HTTPException(403, "Slack interactions are disabled: SLACK_SIGNING_SECRET is not set")
        if not verify_slack_signature(
                settings.slack_signing_secret, request.headers.get("X-Slack-Request-Timestamp", ""), raw,
                request.headers.get("X-Slack-Signature", "")):
            raise HTTPException(401, "bad Slack signature")
        payload = json.loads(parse_qs(raw.decode())["payload"][0])
        action = payload["actions"][0]
        user = payload.get("user", {})
        approver = f"slack:{user.get('username') or user.get('name') or user.get('id', 'unknown')}"
        run = state["run"]
        if run is not None:
            run.broker.resolve(action["value"], action["action_id"] == "cleargate_approve", approver, "slack")
        return {"text": f"Recorded: {'approved' if action['action_id'] == 'cleargate_approve' else 'rejected'} by {approver}"}

    @app.get("/events")
    async def events(request: Request) -> StreamingResponse:
        queue = bus.subscribe()
        backlog = list(bus.history)

        async def stream() -> Any:
            try:
                for event in backlog:
                    yield f"data: {json.dumps(event, default=str)}\n\n"
                while not await request.is_disconnected():
                    try:
                        event = await asyncio.wait_for(queue.get(), timeout=15)
                        yield f"data: {json.dumps(event, default=str)}\n\n"
                    except asyncio.TimeoutError:
                        yield ": keep-alive\n\n"
            finally:
                bus.unsubscribe(queue)

        return StreamingResponse(stream(), media_type="text/event-stream",
                                 headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})

    voice = SarvamVoice()
    seen_public: dict[str, str] = {}

    @app.get("/oncall")
    def oncall() -> FileResponse:
        return FileResponse(STATIC / "oncall.html")

    @app.get("/api/voice/status")
    def voice_status(request: Request) -> dict[str, Any]:
        port = request.url.port or 8700
        public = os.environ.get("CLEARGATE_PUBLIC_URL", "").rstrip("/")
        host = request.headers.get("host", "")
        if not public and host and host.split(":")[0] not in ("localhost", "127.0.0.1", "0.0.0.0") \
                and not re.match(r"^\d+\.\d+\.\d+\.\d+", host):
            public = f"{request.headers.get('x-forwarded-proto', request.url.scheme)}://{host}"
            seen_public["url"] = public
        public = public or seen_public.get("url", "")
        urls = ([f"{public}/oncall"] if public else []) + [f"http://{ip}:{port}/oncall" for ip in _lan_ips()]
        return {"sarvam": voice.enabled, "oncall_urls": urls}

    @app.get("/api/voice/escalations")
    def voice_escalations() -> dict[str, Any]:
        """Polling twin of /events for the on-call page (quick tunnels can buffer SSE)."""
        history = list(bus.history)
        run_id = next((e.get("run_id") for e in reversed(history) if e.get("type") == "run_start"), None)
        resolved = [e for e in history if e.get("type") == "approval_resolved"]
        done = {e.get("id") for e in resolved}
        pending = [e for e in history if e.get("type") == "approval_pending" and e.get("id") not in done]
        return {"run_id": run_id, "pending": pending, "resolved": resolved}

    @app.post("/api/voice/tts")
    async def voice_tts(request: Request) -> Response:
        body = await request.json()
        text = str((body or {}).get("text") or "").strip()
        if not text:
            raise HTTPException(400, "text is required")
        try:
            audio = await run_in_threadpool(voice.tts, text[:2000], str(body.get("language") or "en-IN"))
        except VoiceUnavailable as exc:
            raise HTTPException(503, str(exc))
        return Response(audio, media_type="audio/wav", headers={"Cache-Control": "no-store"})

    @app.post("/api/voice/stt")
    async def voice_stt(request: Request) -> dict[str, Any]:
        content_type = request.headers.get("content-type", "")
        if content_type.startswith("multipart/"):
            form = await request.form()
            upload = form.get("file")
            if upload is None or isinstance(upload, str):
                raise HTTPException(400, "multipart field 'file' is required")
            audio, name, kind = await upload.read(), upload.filename or "reply.webm", upload.content_type or ""
        else:
            audio, name, kind = await request.body(), "reply", content_type.split(";")[0] or "audio/webm"
            name += {"audio/wav": ".wav", "audio/x-wav": ".wav", "audio/mp4": ".m4a", "audio/ogg": ".ogg",
                     "audio/mpeg": ".mp3"}.get(kind, ".webm")
        if not audio:
            raise HTTPException(400, "empty audio")
        if len(audio) > 5_000_000:
            raise HTTPException(413, "clip too long; keep it under 30 seconds")
        try:
            result = await run_in_threadpool(voice.stt, audio, name, kind)
        except VoiceUnavailable as exc:
            raise HTTPException(503, str(exc))
        return {**result, "code": spoken_code(result["transcript"])}

    return app


def _lan_ips() -> list[str]:
    ips: list[str] = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("10.255.255.255", 1))
            ips.append(s.getsockname()[0])
    except OSError:
        pass
    return [ip for ip in ips if not ip.startswith("127.")]
