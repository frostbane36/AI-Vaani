"""
utils/stt_client.py
Speechmatics real-time Speech-to-Text client.
Supports Marathi (mr-IN) and Hindi (hi-IN) with dialect awareness.

Docs: https://docs.speechmatics.com/introduction/batch-guide
"""

import os
import time
import io
import requests

SPEECHMATICS_API_KEY = os.environ.get("SPEECHMATICS_API_KEY", "")
SPEECHMATICS_BATCH_URL = "https://asr.api.speechmatics.com/v2/jobs/"

# Language code mapping (Speechmatics uses different codes)
LANG_CODE_MAP = {
    "mr-IN": "mr",   # Marathi
    "hi-IN": "hi",   # Hindi
    "en-IN": "en",   # English (Indian accent)
}


def transcribe_audio_chunk(audio_bytes: bytes, language_code: str = "mr-IN") -> str:
    """
    Send audio bytes to Speechmatics Batch API and return transcript.
    For a hackathon, batch API is simpler than real-time WebSocket.

    Args:
        audio_bytes: Raw audio data (WAV format preferred)
        language_code: BCP-47 code like 'mr-IN', 'hi-IN'

    Returns:
        Transcribed text string
    """
    if not SPEECHMATICS_API_KEY:
        return "[ERROR] SPEECHMATICS_API_KEY not set in environment."

    lang = LANG_CODE_MAP.get(language_code, "hi")

    headers = {"Authorization": f"Bearer {SPEECHMATICS_API_KEY}"}

    # 1. Submit the job
    files = {
        "data_file": ("audio.wav", io.BytesIO(audio_bytes), "audio/wav"),
        "config": (
            None,
            f'{{"type":"transcription","transcription_config":{{"language":"{lang}","diarization":"speaker"}}}}',
            "application/json",
        ),
    }

    try:
        resp = requests.post(SPEECHMATICS_BATCH_URL, headers=headers, files=files, timeout=30)
        resp.raise_for_status()
        job_id = resp.json()["id"]

        # 2. Poll for completion (max 30s for a hackathon demo)
        for _ in range(30):
            time.sleep(1)
            status_resp = requests.get(
                f"{SPEECHMATICS_BATCH_URL}{job_id}", headers=headers, timeout=10
            )
            status = status_resp.json().get("job", {}).get("status")
            if status == "done":
                break
            elif status == "rejected":
                return "[ERROR] Speechmatics rejected the audio."

        # 3. Fetch transcript
        transcript_resp = requests.get(
            f"{SPEECHMATICS_BATCH_URL}{job_id}/transcript",
            headers={**headers, "Accept": "text/plain"},
            timeout=10,
        )
        return transcript_resp.text.strip()

    except requests.RequestException as e:
        return f"[ERROR] STT request failed: {str(e)}"


def transcribe_audio_file(file_path: str, language_code: str = "mr-IN") -> str:
    """Convenience wrapper to transcribe from a file path."""
    with open(file_path, "rb") as f:
        return transcribe_audio_chunk(f.read(), language_code)


# ── Alternative: Google Cloud STT (60 min free/month) ──────────────────────────
def transcribe_with_google(audio_bytes: bytes, language_code: str = "mr-IN") -> str:
    """
    Google Cloud Speech-to-Text alternative.
    Uncomment and use if you prefer GCP over Speechmatics.

    Setup:
        pip install google-cloud-speech
        export GOOGLE_APPLICATION_CREDENTIALS=path/to/service_account.json
    """
    # from google.cloud import speech
    # client = speech.SpeechClient()
    # audio = speech.RecognitionAudio(content=audio_bytes)
    # config = speech.RecognitionConfig(
    #     encoding=speech.RecognitionConfig.AudioEncoding.LINEAR16,
    #     sample_rate_hertz=16000,
    #     language_code=language_code,
    #     enable_automatic_punctuation=True,
    # )
    # response = client.recognize(config=config, audio=audio)
    # return " ".join(r.alternatives[0].transcript for r in response.results)
    return "[INFO] Google STT not configured. See utils/stt_client.py."
