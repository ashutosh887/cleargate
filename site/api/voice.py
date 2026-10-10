"""POST /api/voice (raw audio body, ?phone=...): a spoken caller turn.

Sarvam speech-to-text, then the same stub bank turn as /api/call (stock and gated), then Sarvam
text-to-speech of both replies. The key stays server side (SARVAM_API_KEY) and is never returned.
"""
from __future__ import annotations

import base64
import io
import os
import sys
import threading
import time
import wave
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(Path(__file__).resolve().parent / "_lib"))

from call import PHONES, turn  # noqa: E402  (same bank turn as /api/call)
from cleargate.bank.call import DEFAULT_PHONE  # noqa: E402
from cleargate.voice.sarvam import SarvamVoice, VoiceUnavailable  # noqa: E402

MAX_BYTES = 2 * 1024 * 1024
MAX_SECONDS = 20
WINDOW, LIMIT = 600, 10
DAILY_CAP = int(os.environ.get("VOICE_DAILY_CAP", "300"))  # per serverless instance
TYPES = {"audio/webm", "audio/ogg", "audio/wav", "audio/x-wav", "audio/wave", "audio/mp4", "audio/mpeg"}

_hits: dict[str, list[float]] = {}
_day = {"date": "", "count": 0}
_lock = threading.Lock()


def admit(ip: str) -> str | None:
    """Return an error message if this call is over a limit, else None (and count it)."""
    now = time.time()
    today = time.strftime("%Y-%m-%d", time.gmtime(now))
    with _lock:
        if _day["date"] != today:
            _day.update(date=today, count=0)
        if _day["count"] >= DAILY_CAP:
            return "Voice calls are at today's limit. Type the caller line instead."
        recent = [t for t in _hits.get(ip, []) if now - t < WINDOW]
        if len(recent) >= LIMIT:
            _hits[ip] = recent
            return "Too many voice calls from this address. Try again in a few minutes, or type instead."
        _hits[ip] = [*recent, now]
        _day["count"] += 1
    return None


def wav_seconds(audio: bytes) -> float | None:
    try:
        with wave.open(io.BytesIO(audio)) as w:
            return w.getnframes() / float(w.getframerate())
    except (wave.Error, EOFError, ZeroDivisionError):
        return None


def speak(voice: SarvamVoice, text: str, language: str) -> str | None:
    if not text:
        return None
    try:
        return base64.b64encode(voice.tts(text[:900], language=language)).decode()
    except VoiceUnavailable:
        return None


def spoken_turn(audio: bytes, content_type: str, phone: str, voice: SarvamVoice) -> dict:
    ext = {"audio/webm": "webm", "audio/ogg": "ogg", "audio/mp4": "m4a", "audio/mpeg": "mp3"}.get(content_type, "wav")
    heard = voice.stt(audio, filename=f"caller.{ext}", content_type=content_type, language="unknown")
    text = heard["transcript"].strip()
    if not text:
        raise VoiceUnavailable("No speech heard. Hold the button and speak, then let go.")
    result = turn(text[:400], phone)
    language = result.get("language") or heard.get("language_code") or "en-IN"
    if language not in ("hi-IN", "en-IN"):
        language = "en-IN"
    result["heard_language"] = heard.get("language_code")
    result["audio"] = {mode: speak(voice, pane.get("reply") or "", language)
                       for mode, pane in result["panes"].items()}
    result["audio_type"] = "audio/wav"
    return result


class handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: dict) -> None:
        import json
        data = json.dumps(body, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        voice = SarvamVoice(timeout=12.0)
        if not voice.enabled:
            return self._send(503, {"error": "Voice is off on this deployment. Type the caller line instead."})
        try:
            size = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            size = 0
        if size <= 0:
            return self._send(400, {"error": "Send the recorded audio as the request body."})
        if size > MAX_BYTES:
            return self._send(413, {"error": f"Keep it under {MAX_SECONDS} seconds."})
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type not in TYPES:
            return self._send(415, {"error": "Send audio/webm, audio/ogg, audio/mp4 or audio/wav."})
        ip = (self.headers.get("x-forwarded-for") or self.client_address[0]).split(",")[0].strip()
        refused = admit(ip)
        if refused:
            return self._send(429, {"error": refused})
        audio = self.rfile.read(size)
        seconds = wav_seconds(audio) if "wav" in content_type else None
        if seconds is not None and seconds > MAX_SECONDS + 0.5:
            return self._send(413, {"error": f"Keep it under {MAX_SECONDS} seconds."})
        phone = (parse_qs(urlparse(self.path).query).get("phone") or [DEFAULT_PHONE])[0]
        phone = phone if phone in PHONES else DEFAULT_PHONE
        try:
            return self._send(200, spoken_turn(audio, content_type, phone, voice))
        except VoiceUnavailable as exc:
            msg = str(exc)
            print(f"voice: {msg[:300]}", file=sys.stderr)
            if not msg.startswith("No speech heard"):  # never echo upstream errors or response bodies
                msg = "The speech service didn't answer. Type the caller line instead."
            return self._send(502, {"error": msg})
        except Exception as exc:  # the page shows the error instead of a blank pane
            print(f"voice: {type(exc).__name__}: {str(exc)[:300]}", file=sys.stderr)
            return self._send(500, {"error": "The call failed on the server. Try again."})

    def do_GET(self) -> None:
        self._send(405, {"error": "POST recorded caller audio to this endpoint."})
