"""
components/audio_stream.py
Browser microphone capture using Streamlit's built-in st.audio_input.
Returns WAV bytes ready for STT processing.
"""

import streamlit as st


def render_audio_streamer() -> bytes | None:
    """
    Renders a mic recorder widget using st.audio_input.
    Returns WAV bytes when the user has recorded audio, else None.
    """
    st.markdown("**Live Microphone**")
    audio = st.audio_input("Record your voice", label_visibility="collapsed")
    if audio is not None:
        st.caption("✅ Audio captured — click **Analyze Transcript** to process")
        return audio.read()
    st.caption("Click the mic button above to record")
    return None
