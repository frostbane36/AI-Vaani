"""
components/audio_stream.py
Browser microphone capture using streamlit-webrtc.
Collects audio frames and returns them for STT processing.
"""

import av
import queue
import threading
import numpy as np
import streamlit as st

try:
    from streamlit_webrtc import webrtc_streamer, WebRtcMode, RTCConfiguration
    WEBRTC_AVAILABLE = True
except ImportError:
    WEBRTC_AVAILABLE = False

# Public STUN servers for WebRTC NAT traversal
RTC_CONFIG = RTCConfiguration(
    iceServers=[{"urls": ["stun:stun.l.google.com:19302"]}]
) if WEBRTC_AVAILABLE else None

# Shared audio queue between WebRTC callback and Streamlit main thread
_audio_queue: queue.Queue = queue.Queue()
_SAMPLE_RATE = 16000
_CHANNELS = 1


class AudioProcessor:
    """
    Processes WebRTC audio frames.
    Accumulates ~1 second of audio before pushing to the queue.
    """

    def __init__(self):
        self._buffer = []
        self._frame_count = 0
        self._frames_per_chunk = 50  # ~1 second at typical frame rates

    def recv(self, frame: av.AudioFrame) -> av.AudioFrame:
        # Convert to float32 mono
        pcm = frame.to_ndarray()
        if pcm.ndim > 1:
            pcm = pcm.mean(axis=0)
        self._buffer.append(pcm.astype(np.float32))
        self._frame_count += 1

        # Every N frames, push the buffered audio to the queue
        if self._frame_count >= self._frames_per_chunk:
            chunk = np.concatenate(self._buffer)
            _audio_queue.put(chunk)
            self._buffer = []
            self._frame_count = 0

        return frame


def render_audio_streamer():
    """
    Renders the WebRTC audio capture widget in Streamlit.
    Returns accumulated audio frames (numpy arrays) if available.
    """
    if not WEBRTC_AVAILABLE:
        st.info(
            "📦 Install `streamlit-webrtc` for live mic capture:\n"
            "```\npip install streamlit-webrtc\n```\n"
            "Until then, use the demo scenarios or paste a transcript manually."
        )
        return []

    st.markdown("**Live Microphone**")

    ctx = webrtc_streamer(
        key="ai-vaani-stream",
        mode=WebRtcMode.SENDONLY,
        audio_receiver_size=512,
        rtc_configuration=RTC_CONFIG,
        media_stream_constraints={"audio": True, "video": False},
        audio_frame_callback=AudioProcessor().recv,
    )

    # Drain the audio queue and return all accumulated frames
    frames = []
    while not _audio_queue.empty():
        try:
            frames.append(_audio_queue.get_nowait())
        except queue.Empty:
            break

    if ctx.state.playing:
        st.caption("🔴 Mic active — speak clearly in Marathi or Hindi")
    else:
        st.caption("Click START above to enable microphone capture")

    return frames


def frames_to_wav_bytes(frames: list) -> bytes:
    """
    Convert list of float32 numpy audio chunks to WAV bytes
    suitable for the Speechmatics API.
    """
    import wave
    import io

    if not frames:
        return b""

    audio_data = np.concatenate(frames)

    # Normalize and convert to int16 PCM
    audio_int16 = (audio_data * 32767).clip(-32768, 32767).astype(np.int16)

    buf = io.BytesIO()
    with wave.open(buf, "wb") as wf:
        wf.setnchannels(_CHANNELS)
        wf.setsampwidth(2)  # int16 = 2 bytes
        wf.setframerate(_SAMPLE_RATE)
        wf.writeframes(audio_int16.tobytes())

    return buf.getvalue()
