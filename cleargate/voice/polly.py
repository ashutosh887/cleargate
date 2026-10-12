"""Amazon Polly voice for the agent's spoken reply (Kajal, the neural voice that speaks Hindi and Indian English).

Auth is the normal AWS credential chain. Every failure raises VoiceUnavailable, like SarvamVoice."""
from __future__ import annotations

import io
import os
import wave

from cleargate.voice.sarvam import VoiceUnavailable, _chunks

SAMPLE_RATE = 16000
POLLY_CHUNK = 2800


class PollyVoice:
    def __init__(self, region: str | None = None, voice_id: str | None = None):
        self.region = region or os.environ.get("POLLY_REGION") or os.environ.get("AWS_REGION") or "ap-south-1"
        self.voice_id = voice_id or os.environ.get("POLLY_VOICE", "Kajal")
        self._client = None

    @property
    def enabled(self) -> bool:
        try:
            import boto3

            return boto3.Session().get_credentials() is not None
        except Exception:
            return False

    def _polly(self):
        if self._client is None:
            import boto3

            self._client = boto3.client("polly", region_name=self.region)
        return self._client

    def tts(self, text: str, language: str = "en-IN") -> bytes:
        """Return WAV bytes for `text`."""
        from botocore.exceptions import BotoCoreError, ClientError

        pcm = bytearray()
        for chunk in _chunks(text, POLLY_CHUNK):
            try:
                resp = self._polly().synthesize_speech(
                    Text=chunk, VoiceId=self.voice_id, Engine="neural", OutputFormat="pcm",
                    SampleRate=str(SAMPLE_RATE), LanguageCode=language if language in ("hi-IN", "en-IN") else "en-IN")
                pcm += resp["AudioStream"].read()
            except (BotoCoreError, ClientError) as exc:
                raise VoiceUnavailable(f"Amazon Polly failed: {type(exc).__name__}: {exc}") from exc
        out = io.BytesIO()
        with wave.open(out, "wb") as writer:
            writer.setnchannels(1)
            writer.setsampwidth(2)
            writer.setframerate(SAMPLE_RATE)
            writer.writeframes(bytes(pcm))
        return out.getvalue()


def reply_voice():
    """CLEARGATE_TTS=polly speaks replies with Amazon Polly; anything else keeps Sarvam."""
    if os.environ.get("CLEARGATE_TTS", "").lower() == "polly":
        return PollyVoice()
    from cleargate.voice.sarvam import SarvamVoice

    return SarvamVoice()
