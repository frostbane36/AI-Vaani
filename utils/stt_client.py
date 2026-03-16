"""
utils/stt_client.py
Speech-to-Text using Groq Whisper API.
Audio is resampled to 16kHz mono WAV before sending to minimize payload size.
"""

import os
import io
import wave
import struct
from groq import Groq

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

LANG_CODE_MAP = {
    "mr-IN": "mr",
    "hi-IN": "hi",
    "en-IN": "en",
}


def _to_16k_mono_wav(audio_bytes: bytes) -> bytes:
    """
    Convert any audio bytes to 16kHz mono WAV using pydub (fast, in-memory).
    Falls back to raw bytes if pydub is unavailable.
    """
    try:
        from pydub import AudioSegment
        audio = AudioSegment.from_file(io.BytesIO(audio_bytes))
        audio = audio.set_frame_rate(16000).set_channels(1).set_sample_width(2)
        buf = io.BytesIO()
        audio.export(buf, format="wav")
        return buf.getvalue()
    except Exception:
        # fallback: send as-is
        return audio_bytes


def transcribe_audio_chunk(audio_bytes: bytes, language_code: str = "mr-IN") -> str:
    """
    Transcribe audio using Groq whisper-large-v3-turbo.
    Resamples to 16kHz mono WAV first to keep payload small and fast.
    """
    lang = LANG_CODE_MAP.get(language_code, "hi")

    # Downsample for speed — smaller file = faster upload + faster inference
    wav_bytes = _to_16k_mono_wav(audio_bytes)

    try:
        transcription = client.audio.transcriptions.create(
            file=("audio.wav", io.BytesIO(wav_bytes)),
            model="whisper-large-v3-turbo",
            language=lang,
            response_format="text",
        )
        result = transcription if isinstance(transcription, str) else transcription.text
        return result.strip()
    except Exception as e:
        return f"[ERROR] Transcription failed: {str(e)}"


def transcribe_audio_file(file_path: str, language_code: str = "mr-IN") -> str:
    with open(file_path, "rb") as f:
        return transcribe_audio_chunk(f.read(), language_code)
