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
from utils.groq_analyzer import analyze_transcript, get_backend_label
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
    st.markdown('<div class="status-pill">🟢 READY</div>', unsafe_allow_html=True)

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
        dcol1, dcol2, dcol3, dcol4 = st.columns(4)
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
        with dcol4:
            if st.button("🔗 Link Scam\n(English)", use_container_width=True):
                st.session_state.transcript = (
                    "Hello, your KYC verification is pending. Your account will be blocked. "
                    "Please click this link immediately to update: http://sbi-kyc-update.xyz/verify "
                    "Or visit bit.ly/sbi-kyc-now to complete the process. "
                    "You can also go to sbi-secure dot com slash login to submit your OTP."
                )
                st.rerun()

        # Highlighted transcript
        if st.session_state.transcript and st.session_state.threat_result:
            st.markdown("#### 🔍 Highlighted Transcript")
            _r = st.session_state.threat_result
            _text = st.session_state.transcript
            # Highlight suspicious links first (orange)
            for link in _r.suspicious_links:
                if link.url in _text:
                    _text = _text.replace(
                        link.url,
                        f'<mark style="background:#F5A62333;border-radius:3px;padding:1px 3px;'
                        f'border-bottom:2px solid #F5A623;font-weight:600" title="{link.reason}">{link.url}</mark>'
                    )
            # Highlight key phrases (red)
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

        # Backend degradation warning
        if result:
            backend_warn = get_backend_label(result)
            if backend_warn:
                st.warning(backend_warn)

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
                ("Suspicious Links", bool(result.suspicious_links), "🟠"),
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

        if result and result.suspicious_links:
            st.markdown("**🔗 Suspicious Links Detected**")
            for link in result.suspicious_links:
                badge = "🔴" if link.risk == "HIGH" else "🟠"
                st.error(f"{badge} `{link.url}`  \n_{link.reason}_")

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
        st.caption("🤖 Groq → Ollama → Rules · Whisper STT")

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

# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — DASHBOARD
# ══════════════════════════════════════════════════════════════════════════════
with tab_dashboard:
    # Collect all results: live + batch
    all_results = []
    if st.session_state.threat_result:
        all_results.append({
            "filename": "Live / Manual",
            "result": st.session_state.threat_result,
            "transcript": st.session_state.transcript,
        })
    for item in st.session_state.batch_results:
        if not item["error"] and item["result"]:
            all_results.append(item)

    if not all_results:
        st.info("No analysis data yet. Run a live analysis or process batch files first, then come back here.")
    else:
        # ── KPI row ────────────────────────────────────────────────────────────
        total = len(all_results)
        high_risk = sum(1 for x in all_results if x["result"].risk_score >= 70)
        med_risk  = sum(1 for x in all_results if 40 <= x["result"].risk_score < 70)
        low_risk  = sum(1 for x in all_results if x["result"].risk_score < 40)
        avg_score = int(sum(x["result"].risk_score for x in all_results) / total)

        k1, k2, k3, k4, k5 = st.columns(5)
        k1.metric("Total Analyzed", total)
        k2.metric("🔴 High Risk", high_risk)
        k3.metric("🟠 Medium Risk", med_risk)
        k4.metric("🟢 Low Risk", low_risk)
        k5.metric("Avg Score", avg_score)

        st.markdown("---")

        # ── Row 1: Risk score bar + threat type breakdown ──────────────────────
        row1_l, row1_r = st.columns([3, 2], gap="large")

        with row1_l:
            st.markdown("**Risk Scores per Call**")
            names  = [x["filename"] for x in all_results]
            scores = [x["result"].risk_score for x in all_results]
            colors = [assess_risk_color(s) for s in scores]
            fig_bar = go.Figure(go.Bar(
                x=names, y=scores,
                marker_color=colors,
                text=scores, textposition="outside",
            ))
            fig_bar.update_layout(
                yaxis=dict(range=[0, 110], title="Risk Score"),
                xaxis=dict(title=""),
                margin=dict(l=10, r=10, t=10, b=60),
                height=280,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(size=12),
            )
            fig_bar.add_hline(y=70, line_dash="dot", line_color="#FF4B4B", annotation_text="High Risk")
            fig_bar.add_hline(y=40, line_dash="dot", line_color="#F5A623", annotation_text="Medium Risk")
            st.plotly_chart(fig_bar, use_container_width=True)

        with row1_r:
            st.markdown("**Risk Distribution**")
            fig_pie = go.Figure(go.Pie(
                labels=["High Risk", "Medium Risk", "Low Risk"],
                values=[high_risk, med_risk, low_risk],
                marker_colors=["#FF4B4B", "#F5A623", "#00E5B4"],
                hole=0.5,
                textinfo="label+percent",
            ))
            fig_pie.update_layout(
                showlegend=False,
                margin=dict(l=10, r=10, t=10, b=10),
                height=280,
                paper_bgcolor='rgba(0,0,0,0)',
            )
            st.plotly_chart(fig_pie, use_container_width=True)

        st.markdown("---")

        # ── Row 2: Threat type frequency + radar ──────────────────────────────
        row2_l, row2_r = st.columns([3, 2], gap="large")

        with row2_l:
            st.markdown("**Threat Type Frequency Across All Calls**")
            threat_counts = {
                "Urgency":          sum(1 for x in all_results if x["result"].urgency_detected),
                "OTP Request":      sum(1 for x in all_results if x["result"].otp_request),
                "Bank Details":     sum(1 for x in all_results if x["result"].bank_details_request),
                "Impersonation":    sum(1 for x in all_results if x["result"].impersonation_detected),
                "Cultural Tactic":  sum(1 for x in all_results if x["result"].cultural_tactic),
            }
            fig_hbar = go.Figure(go.Bar(
                x=list(threat_counts.values()),
                y=list(threat_counts.keys()),
                orientation='h',
                marker_color=["#FF4B4B", "#FF4B4B", "#FF4B4B", "#F5A623", "#F5A623"],
                text=list(threat_counts.values()), textposition="outside",
            ))
            fig_hbar.update_layout(
                xaxis=dict(title="Count", range=[0, max(total, 1) + 0.5]),
                margin=dict(l=10, r=30, t=10, b=10),
                height=260,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
            )
            st.plotly_chart(fig_hbar, use_container_width=True)

        with row2_r:
            st.markdown("**Aggregate Threat Radar**")
            t_vals = list(threat_counts.values())
            t_norm = [v / max(total, 1) for v in t_vals]
            t_labels = list(threat_counts.keys())
            fig_radar2 = go.Figure(go.Scatterpolar(
                r=t_norm + [t_norm[0]],
                theta=t_labels + [t_labels[0]],
                fill='toself',
                fillcolor='rgba(255,75,75,0.15)',
                line=dict(color='#FF4B4B', width=2),
            ))
            fig_radar2.update_layout(
                polar=dict(radialaxis=dict(visible=True, range=[0, 1])),
                showlegend=False,
                margin=dict(l=20, r=20, t=20, b=20),
                height=260,
                paper_bgcolor='rgba(0,0,0,0)',
            )
            st.plotly_chart(fig_radar2, use_container_width=True)

        st.markdown("---")

        # ── Row 3: Per-call detail table + alerts ─────────────────────────────
        st.markdown("**Per-Call Summary**")
        rows = []
        for x in all_results:
            r = x["result"]
            rows.append({
                "File": x["filename"],
                "Risk Score": r.risk_score,
                "Level": r.risk_level,
                "Language": r.detected_language,
                "Urgency": "✅" if r.urgency_detected else "—",
                "OTP": "✅" if r.otp_request else "—",
                "Bank": "✅" if r.bank_details_request else "—",
                "Impersonation": "✅" if r.impersonation_detected else "—",
                "Cultural": "✅" if r.cultural_tactic else "—",
                "Threats": r.threat_count,
            })
        df = pd.DataFrame(rows)
        st.dataframe(
            df.style.apply(
                lambda col: [
                    "background-color:#FF4B4B22" if v >= 70
                    else "background-color:#F5A62322" if v >= 40
                    else "" for v in col
                ] if col.name == "Risk Score" else [""] * len(col),
                axis=0,
            ),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("---")

        # ── Alerts for high-risk calls ─────────────────────────────────────────
        high_risk_items = [x for x in all_results if x["result"].risk_score >= 70]
        if high_risk_items:
            st.markdown("**🚨 High Risk Alerts**")
            for x in high_risk_items:
                r = x["result"]
                with st.container():
                    st.error(
                        f"**{x['filename']}** — Score: {r.risk_score}/100  \n"
                        f"{r.summary}  \n"
                        f"Flagged phrases: {', '.join(r.key_phrases) if r.key_phrases else 'none'}"
                    )

        # ── Highlighted transcripts for all calls ─────────────────────────────
        st.markdown("---")
        st.markdown("**Highlighted Transcripts**")
        for x in all_results:
            r = x["result"]
            _text = x["transcript"]
            for phrase in r.key_phrases:
                if phrase and phrase in _text:
                    _text = _text.replace(
                        phrase,
                        f'<mark style="background:#FF4B4B33;border-radius:3px;padding:1px 3px;'
                        f'border-bottom:2px solid #FF4B4B;font-weight:600">{phrase}</mark>'
                    )
            risk_color = assess_risk_color(r.risk_score)
            st.markdown(
                f'<div style="font-size:12px;font-weight:600;color:{risk_color};margin-bottom:4px">'
                f'{x["filename"]} — {r.risk_score}/100 [{r.risk_level}]</div>'
                f'<div class="transcript-box">{_text}</div>',
                unsafe_allow_html=True,
            )
