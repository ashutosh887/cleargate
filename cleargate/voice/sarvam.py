"""Sarvam AI voice (Indian-English TTS and STT) for the on-call escalation call.

Every failure raises VoiceUnavailable so callers can fall back to the browser's Web Speech API."""
from __future__ import annotations

import base64
import io
import json
import os
import re
import wave
from concurrent.futures import ThreadPoolExecutor

import httpx

TTS_URL = "https://api.sarvam.ai/text-to-speech"
STT_URL = "https://api.sarvam.ai/speech-to-text"
TTS_CHUNK = 450
KEYTERMS = ["approve", "reject", "alpha", "bravo", "charlie", "delta", "echo", "foxtrot",
            "zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine"]


class VoiceUnavailable(RuntimeError):
    pass


def normalize_transcript(text: str) -> str:
    """Join words STT sometimes splits ("fox trot") so the spoken-code parser sees NATO letters."""
    text = re.sub(r"\bfox\s*-?\s*trot\b", "foxtrot", text, flags=re.I)
    text = re.sub(r"\bal\s+fa\b|\balfa\b", "alpha", text, flags=re.I)
    text = re.sub(r"\bcharley\b", "charlie", text, flags=re.I)
    text = re.sub(r"\beco\b", "echo", text, flags=re.I)
    return text.strip()


def _chunks(text: str, limit: int = TTS_CHUNK) -> list[str]:
    parts, current = [], ""
    for sentence in re.split(r"(?<=[.!?])\s+", text.strip()):
        if current and len(current) + len(sentence) + 1 > limit:
            parts.append(current)
            current = sentence
        else:
            current = f"{current} {sentence}".strip()
    if current:
        parts.append(current)
    return [p[:limit] for p in parts] or [""]


def _join_wavs(blobs: list[bytes]) -> bytes:
    if len(blobs) == 1:
        return blobs[0]
    out = io.BytesIO()
    with wave.open(io.BytesIO(blobs[0])) as first:
        params = first.getparams()
    with wave.open(out, "wb") as writer:
        writer.setparams(params)
        for blob in blobs:
            with wave.open(io.BytesIO(blob)) as reader:
                writer.writeframes(reader.readframes(reader.getnframes()))
    return out.getvalue()


class SarvamVoice:
    def __init__(self, api_key: str | None = None, timeout: float = 15.0):
        self.api_key = api_key if api_key is not None else os.environ.get("SARVAM_API_KEY", "")
        self.speaker = os.environ.get("SARVAM_TTS_SPEAKER", "")
        self.timeout = timeout

    @property
    def enabled(self) -> bool:
        return bool(self.api_key)

    def _headers(self) -> dict[str, str]:
        if not self.api_key:
            raise VoiceUnavailable("SARVAM_API_KEY is not set")
        return {"api-subscription-key": self.api_key}

    def tts(self, text: str, language: str = "en-IN") -> bytes:
        """Return WAV bytes for `text`."""
        headers = self._headers()

        def one(chunk: str) -> bytes:
            body: dict[str, str] = {"text": chunk, "target_language_code": language}
            if self.speaker:
                body["speaker"] = self.speaker
            try:
                resp = httpx.post(TTS_URL, headers=headers, json=body, timeout=self.timeout)
                resp.raise_for_status()
                return base64.b64decode(resp.json()["audios"][0])
            except (httpx.HTTPError, KeyError, IndexError, ValueError) as exc:
                raise VoiceUnavailable(f"Sarvam TTS failed: {type(exc).__name__}: {exc}") from exc

        chunks = _chunks(text)
        with ThreadPoolExecutor(max_workers=min(4, len(chunks))) as pool:
            blobs = list(pool.map(one, chunks))
        return _join_wavs(blobs)

    def stt(self, audio: bytes, filename: str = "reply.webm", content_type: str = "audio/webm",
            language: str = "en-IN") -> dict[str, str]:
        """Transcribe a short clip (< 30 s). Returns {"transcript", "raw", "language_code"}."""
        headers = self._headers()
        data = {"model": "saaras:v4", "language_code": language, "keyterms": json.dumps(KEYTERMS)}
        try:
            resp = httpx.post(STT_URL, headers=headers, data=data, timeout=self.timeout,
                              files={"file": (filename, audio, content_type or "application/octet-stream")})
            resp.raise_for_status()
            body = resp.json()
        except (httpx.HTTPError, ValueError) as exc:
            detail = getattr(getattr(exc, "response", None), "text", "")[:200]
            raise VoiceUnavailable(f"Sarvam STT failed: {type(exc).__name__}: {exc} {detail}".strip()) from exc
        raw = str(body.get("transcript") or "")
        return {"transcript": normalize_transcript(raw), "raw": raw,
                "language_code": str(body.get("language_code") or language)}
