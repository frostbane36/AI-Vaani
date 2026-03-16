"""
AI-Vaani — Real-Time Vernacular Scam Detection
Entry point: streamlit run app.py
"""

from dotenv import load_dotenv
load_dotenv()

import streamlit as st
import time
import json
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
from utils.groq_analyzer import analyze_transcript
from utils.threat_model import ThreatResult, assess_risk_color

st.set_page_config(
    page_title="AI-Vaani | वाणी",
    page_icon="🎙️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

with open("assets/style.css") as f:
    st.markdown(f"<style>{f.read()}</style>", unsafe_allow_html=True)

# ── Session state ──────────────────────────────────────────────────────────────
defaults = {
    "transcript": "",
    "threat_result": None,
    "recording": False,
    "calls_analyzed": 0,
    "threats_flagged": 0,
    "selected_language": "mr-IN",
    "analysis_latency_ms": None,
    "audio_buffer": [],
    "batch_results": [],   # list of {filename, transcript, result}
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

# ── Tabs ───────────────────────────────────────────────────────────────────────
tab_live, tab_batch, tab_dashboard = st.tabs(["🎙️ Live Analysis", "📂 Batch Upload", "📊 Dashboard"])

# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — LIVE ANALYSIS
# ══════════════════════════════════════════════════════════════════════════════
with tab_live:
    left, right = st.columns([3, 2], gap="large")

    with left:
        st.markdown("#### 🎙️ Live Audio Input")
        lang_map = {"मराठी (mr-IN)": "mr-IN", "हिंदी (hi-IN)": "hi-IN", "English (en-IN)": "en-IN"}
        lang_label = st.selectbox("Language", list(lang_map.keys()), label_visibility="collapsed")
        st.session_state.selected_language = lang_map[lang_label]

        from components.audio_stream import render_audio_streamer
        audio_bytes = render_audio_streamer()

        if audio_bytes and audio_bytes != st.session_state.get("last_audio_bytes"):
            st.session_state["last_audio_bytes"] = audio_bytes
            with st.spinner("Transcribing & analyzing..."):
                from utils.stt_client import transcribe_audio_chunk
                transcript = transcribe_audio_chunk(audio_bytes, st.session_state.selected_language)
                if transcript and not transcript.startswith("[ERROR]"):
                    t0 = time.time()
                    result = analyze_transcript(transcript, st.session_state.selected_language)
                    latency = int((time.time() - t0) * 1000)
                    st.session_state.transcript = transcript
                    st.session_state.threat_result = result
                    st.session_state.calls_analyzed += 1
                    st.session_state.analysis_latency_ms = latency
                    if result.risk_score >= 40:
                        st.session_state.threats_flagged += 1
                    st.rerun()
                else:
                    st.warning(transcript or "Transcription returned empty result.")

        st.markdown("---")
        st.markdown("#### 📝 Transcript")

        transcript_input = st.text_area(
            "Or paste transcript manually:",
            placeholder="Paste Marathi/Hindi/English call transcript here...",
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

        # Highlighted transcript
        if st.session_state.transcript and st.session_state.threat_result:
            st.markdown("#### 🔍 Highlighted Transcript")
            _r = st.session_state.threat_result
            _text = st.session_state.transcript
            for phrase in _r.key_phrases:
                if phrase and phrase in _text:
                    _text = _text.replace(
                        phrase,
                        f'<mark style="background:#FF4B4B33;border-radius:3px;padding:1px 3px;'
                        f'border-bottom:2px solid #FF4B4B;font-weight:600">{phrase}</mark>'
                    )
            st.markdown(f'<div class="transcript-box">{_text}</div>', unsafe_allow_html=True)
        elif st.session_state.transcript:
            st.markdown(f'<div class="transcript-box">{st.session_state.transcript}</div>', unsafe_allow_html=True)

    with right:
        st.markdown("#### 🛡️ Threat Analysis")
        result: ThreatResult | None = st.session_state.threat_result
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
            st.error("🚨 HIGH RISK — Strong scam indicators detected!")
        elif risk_score >= 40:
            st.warning("⚠️ MODERATE RISK — Suspicious patterns detected.")
        else:
            st.success("✅ LOW RISK — No significant threats found.")

        st.markdown("---")

        # Radar chart for threat indicators
        if result:
            indicators_vals = [
                int(result.urgency_detected),
                int(result.otp_request),
                int(result.bank_details_request),
                int(result.impersonation_detected),
                int(result.cultural_tactic),
            ]
            indicator_labels = ["Urgency", "OTP Request", "Bank Details", "Impersonation", "Cultural Tactic"]
            fig_radar = go.Figure(go.Scatterpolar(
                r=indicators_vals + [indicators_vals[0]],
                theta=indicator_labels + [indicator_labels[0]],
                fill='toself',
                fillcolor='rgba(255,75,75,0.2)',
                line=dict(color='#FF4B4B', width=2),
            ))
            fig_radar.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 1], tickvals=[0, 1], ticktext=["", ""])),
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=20),
                height=220,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
            )
            st.plotly_chart(fig_radar, use_container_width=True)

            # Threat indicator rows
            for label, detected, icon in [
                ("Urgency / Fear Tactics", result.urgency_detected, "🔴"),
                ("OTP / PIN Request", result.otp_request, "🔴"),
                ("Bank / Financial Data Request", result.bank_details_request, "🔴"),
                ("Authority Impersonation", result.impersonation_detected, "🟠"),
                ("Cultural Manipulation", result.cultural_tactic, "🟠"),
            ]:
                status = f"{icon} DETECTED" if detected else "🟢 CLEAR"
                c1, c2 = st.columns([3, 1])
                c1.caption(label)
                c2.markdown(f"`{status}`")
        else:
            st.caption("Run analysis to see threat breakdown.")

        st.markdown("---")
        if result and result.summary:
            st.markdown("**AI Analysis**")
            st.info(result.summary)

        if result and result.key_phrases:
            st.markdown("**Flagged Phrases**")
            st.markdown(" ".join([f'`{p}`' for p in result.key_phrases]))

        if result and result.detected_language:
            c1, c2, c3 = st.columns(3)
            c1.metric("Language", result.detected_language)
            c2.metric("Confidence", f"{result.confidence}%")
            if st.session_state.analysis_latency_ms:
                c3.metric("Latency", f"{st.session_state.analysis_latency_ms}ms")

        st.markdown("---")
        s1, s2 = st.columns(2)
        s1.metric("Calls Analyzed", st.session_state.calls_analyzed)
        s2.metric("Threats Flagged", st.session_state.threats_flagged)
        st.caption("🤖 Groq · Llama-3.3-70B + Whisper")

# ── Manual analyze trigger ─────────────────────────────────────────────────────
with tab_live:
    active_transcript = transcript_input or st.session_state.transcript
    if analyze_clicked and active_transcript.strip():
        with st.spinner("Analyzing with Groq Llama-3..."):
            t0 = time.time()
            result = analyze_transcript(active_transcript, st.session_state.selected_language)
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

# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — BATCH UPLOAD
# ══════════════════════════════════════════════════════════════════════════════
with tab_batch:
    st.markdown("#### 📂 Upload Multiple Audio Files")
    st.caption("Upload up to 10 audio files at once. Each will be transcribed and analyzed.")

    batch_lang_map = {"मराठी (mr-IN)": "mr-IN", "हिंदी (hi-IN)": "hi-IN", "English (en-IN)": "en-IN"}
    batch_lang = batch_lang_map[st.selectbox("Language for all files", list(batch_lang_map.keys()), key="batch_lang")]

    uploaded_files = st.file_uploader(
        "Drop audio files here",
        type=["wav", "mp3", "ogg", "m4a", "webm", "flac"],
        accept_multiple_files=True,
        label_visibility="collapsed",
    )

    if uploaded_files:
        st.markdown(f"**{len(uploaded_files)} file(s) selected**")
        if st.button("🚀 Analyze All Files", type="primary", use_container_width=True):
            from utils.stt_client import transcribe_audio_chunk
            batch_results = []
            progress = st.progress(0)
            status_box = st.empty()

            for i, f in enumerate(uploaded_files):
                status_box.info(f"Processing {i+1}/{len(uploaded_files)}: {f.name}")
                audio_data = f.read()
                transcript = transcribe_audio_chunk(audio_data, batch_lang)
                if transcript.startswith("[ERROR]"):
                    batch_results.append({"filename": f.name, "transcript": transcript, "result": None, "error": True})
                else:
                    result = analyze_transcript(transcript, batch_lang)
                    st.session_state.calls_analyzed += 1
                    if result.risk_score >= 40:
                        st.session_state.threats_flagged += 1
                    batch_results.append({"filename": f.name, "transcript": transcript, "result": result, "error": False})
                progress.progress((i + 1) / len(uploaded_files))

            st.session_state.batch_results = batch_results
            status_box.success(f"✅ Done! Processed {len(batch_results)} files.")
            st.rerun()

    # Show batch results
    if st.session_state.batch_results:
        st.markdown("---")
        st.markdown("#### Results")

        for item in st.session_state.batch_results:
            r: ThreatResult | None = item["result"]
            risk = r.risk_score if r else 0
            color = assess_risk_color(risk)
            level = r.risk_level if r else "ERROR"

            with st.expander(f"{'🔴' if risk >= 70 else '🟠' if risk >= 40 else '🟢'}  {item['filename']}  —  Score: {risk}  [{level}]"):
                if item["error"]:
                    st.error(item["transcript"])
                else:
                    col_t, col_s = st.columns([3, 2])
                    with col_t:
                        st.markdown("**Transcript**")
                        _text = item["transcript"]
                        if r:
                            for phrase in r.key_phrases:
                                if phrase and phrase in _text:
                                    _text = _text.replace(
                                        phrase,
                                        f'<mark style="background:#FF4B4B33;border-radius:3px;padding:1px 3px;'
                                        f'border-bottom:2px solid #FF4B4B;font-weight:600">{phrase}</mark>'
                                    )
                        st.markdown(f'<div class="transcript-box">{_text}</div>', unsafe_allow_html=True)
                    with col_s:
                        st.markdown("**Threat Indicators**")
                        if r:
                            for label, val in [
                                ("Urgency", r.urgency_detected),
                                ("OTP Request", r.otp_request),
                                ("Bank Details", r.bank_details_request),
                                ("Impersonation", r.impersonation_detected),
                                ("Cultural Tactic", r.cultural_tactic),
                            ]:
                                st.markdown(f"{'🔴' if val else '🟢'} {label}")
                            st.markdown(f"**Summary:** {r.summary}")

        if st.button("🗑️ Clear Batch Results"):
            st.session_state.batch_results = []
            st.rerun()
