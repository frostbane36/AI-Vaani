"""
AI-Vaani — Real-Time Vernacular Scam Detection
Entry point: streamlit run app.py
"""

from dotenv import load_dotenv
load_dotenv()

import streamlit as st
import time
import json
from utils.groq_analyzer import analyze_transcript
from utils.stt_client import transcribe_audio_chunk
from utils.threat_model import ThreatResult, assess_risk_color

st.set_page_config(
    page_title="AI-Vaani | वाणी",
    page_icon="🎙️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Inject custom CSS ──────────────────────────────────────────────────────────
with open("assets/style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ── Session state init ─────────────────────────────────────────────────────────
defaults = {
    "transcript": "",
    "threat_result": None,
    "recording": False,
    "calls_analyzed": 0,
    "threats_flagged": 0,
    "selected_language": "mr-IN",
    "analysis_latency_ms": None,
    "audio_buffer": [],
}
for k, v in defaults.items():
    if k not in st.session_state:
        st.session_state[k] = v

# ── Header ─────────────────────────────────────────────────────────────────────
col_logo, col_status = st.columns([3, 1])
with col_logo:
    st.markdown("""
    <div class="topbar">
        <div class="logo-block">
            <span class="logo-badge">AV</span>
            <div>
                <div class="logo-title">AI-Vaani</div>
                <div class="logo-sub">वाणी · Voice Threat Detection</div>
            </div>
        </div>
    </div>
    """, unsafe_allow_html=True)

with col_status:
    status_text = "🔴 RECORDING" if st.session_state.recording else "🟢 READY"
    st.markdown(f'<div class="status-pill">{status_text}</div>', unsafe_allow_html=True)

st.divider()

# ── Main Layout ────────────────────────────────────────────────────────────────
left, right = st.columns([3, 2], gap="large")

# ── LEFT PANEL ─────────────────────────────────────────────────────────────────
with left:
    st.markdown("#### 🎙️ Live Audio Input")

    lang_map = {"मराठी (mr-IN)": "mr-IN", "हिंदी (hi-IN)": "hi-IN", "English (en-IN)": "en-IN"}
    lang_label = st.selectbox("Language", list(lang_map.keys()), label_visibility="collapsed")
    st.session_state.selected_language = lang_map[lang_label]

    # WebRTC audio streamer (browser mic capture)
    from components.audio_stream import render_audio_streamer
    audio_frames = render_audio_streamer()

    st.markdown("---")
    st.markdown("#### 📝 Transcript")

    transcript_display = st.empty()
    transcript_input = st.text_area(
        "Or paste transcript manually:",
        placeholder="Paste Marathi/Hindi/English call transcript here for analysis...",
        height=140,
        key="manual_transcript",
    )

    col_analyze, col_clear = st.columns([1, 1])
    with col_analyze:
        analyze_clicked = st.button("🔍 Analyze Transcript", use_container_width=True, type="primary")
    with col_clear:
        if st.button("🗑️ Clear", use_container_width=True):
            st.session_state.transcript = ""
            st.session_state.threat_result = None
            st.rerun()

    # Demo scenarios
    st.markdown("#### 🧪 Demo Scenarios")
    dcol1, dcol2, dcol3 = st.columns(3)
    with dcol1:
        if st.button("⚠️ OTP Fraud\n(Marathi)", use_container_width=True):
            st.session_state.transcript = (
                "नमस्कार, मी SBI बँकेतून बोलत आहे. तुमचे खाते 24 तासात बंद होणार आहे. "
                "आपल्या खात्यावर संशयास्पद व्यवहार आढळले आहेत. "
                "कृपया आत्ताच तुमचा OTP सांगा अन्यथा सर्व पैसे गोठवले जातील. "
                "तुमचा ATM पिन आणि खाते क्रमांक द्या."
            )
            st.rerun()
    with dcol2:
        if st.button("⚡ Electricity\nScam", use_container_width=True):
            st.session_state.transcript = (
                "MSEDCL कार्यालयातून बोलत आहे. तुमचे वीज बिल थकीत आहे, "
                "आज रात्री 9 वाजता कनेक्शन तोडले जाईल. "
                "टाळण्यासाठी आत्ताच Paytm वर पैसे पाठवा आणि तुमचा खाते क्रमांक द्या. "
                "हे शेवटचे नोटीस आहे."
            )
            st.rerun()
    with dcol3:
        if st.button("✅ Safe Call\n(Hindi)", use_container_width=True):
            st.session_state.transcript = (
                "नमस्ते, मैं आपके दोस्त रमेश बोल रहा हूँ। "
                "कल शाम को मिलना है क्या? चाय पीते हैं और बात करते हैं। "
                "मौसम बहुत अच्छा है आजकल।"
            )
            st.rerun()

    # Show current transcript
    if st.session_state.transcript:
        transcript_display.markdown(
            f'<div class="transcript-box">{st.session_state.transcript}</div>',
            unsafe_allow_html=True,
        )

# ── RIGHT PANEL ────────────────────────────────────────────────────────────────
with right:
    st.markdown("#### 🛡️ Threat Analysis")

    result: ThreatResult | None = st.session_state.threat_result

    # Risk Score Meter
    risk_score = result.risk_score if result else 0
    risk_color = assess_risk_color(risk_score)
    st.markdown(f"""
    <div class="risk-display">
        <div class="risk-number" style="color:{risk_color}">{risk_score}</div>
        <div class="risk-sublabel">SCAM PROBABILITY SCORE</div>
    </div>
    """, unsafe_allow_html=True)
    st.progress(risk_score / 100)

    if risk_score >= 70:
        st.error("🚨 HIGH RISK DETECTED — This call shows strong scam indicators!")
    elif risk_score >= 40:
        st.warning("⚠️ MODERATE RISK — Suspicious patterns detected. Proceed with caution.")
    else:
        st.success("✅ LOW RISK — No significant threat indicators found.")

    st.markdown("---")

    # Threat Breakdown
    st.markdown("**Threat Indicators**")
    if result:
        indicators = [
            ("Urgency / Fear Tactics", result.urgency_detected, "🔴"),
            ("OTP / PIN Request", result.otp_request, "🔴"),
            ("Bank / Financial Data Request", result.bank_details_request, "🔴"),
            ("Authority Impersonation", result.impersonation_detected, "🟠"),
            ("Cultural Manipulation Tactic", result.cultural_tactic, "🟠"),
        ]
        for label, detected, icon in indicators:
            status = f"{icon} DETECTED" if detected else "🟢 CLEAR"
            col_l, col_r = st.columns([3, 1])
            col_l.caption(label)
            col_r.markdown(f"`{status}`")
    else:
        st.caption("Run analysis to see threat breakdown.")

    st.markdown("---")

    # Analysis Summary
    if result and result.summary:
        st.markdown("**AI Analysis**")
        st.info(result.summary)

    if result and result.detected_language:
        col_l, col_m, col_r = st.columns(3)
        col_l.metric("Language", result.detected_language)
        col_m.metric("Confidence", f"{result.confidence}%")
        if st.session_state.analysis_latency_ms:
            col_r.metric("Latency", f"{st.session_state.analysis_latency_ms}ms")

    st.markdown("---")

    # Session Stats
    st.markdown("**Session Stats**")
    s1, s2 = st.columns(2)
    s1.metric("Calls Analyzed", st.session_state.calls_analyzed)
    s2.metric("Threats Flagged", st.session_state.threats_flagged)

    st.markdown("---")
    st.caption("🤖 Powered by **Llama-3-70B @ Groq** · 500+ tok/sec")
    st.caption("🎙️ STT: **Speechmatics API** · mr-IN / hi-IN")


# ── Analysis trigger ───────────────────────────────────────────────────────────
active_transcript = transcript_input or st.session_state.transcript

if analyze_clicked and active_transcript.strip():
    with st.spinner("Analyzing with Groq Llama-3..."):
        t0 = time.time()
        result = analyze_transcript(
            transcript=active_transcript,
            language=st.session_state.selected_language,
        )
        latency = int((time.time() - t0) * 1000)

    st.session_state.threat_result = result
    st.session_state.transcript = active_transcript
    st.session_state.calls_analyzed += 1
    st.session_state.analysis_latency_ms = latency
    if result.risk_score >= 40:
        st.session_state.threats_flagged += 1
    st.rerun()

elif analyze_clicked:
    st.warning("Please enter or paste a transcript first.")
