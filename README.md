# AI-Vaani 🎙️ वाणी
### Real-Time Vernacular Scam Detection for India

AI-Vaani detects phone scams in **Marathi and Hindi** in real time, using:
- **Speechmatics** for high-accuracy vernacular STT
- **Groq + Llama-3-70B** for sub-second threat analysis
- **Streamlit + WebRTC** for a live browser-based dashboard

---

## ⚡ Quickstart (4-hour hackathon)

### 1. Clone & install

```bash
git clone https://github.com/your-username/ai-vaani
cd ai-vaani
pip install -r requirements.txt
```

### 2. Set API keys

```bash
cp .env.example .env
# Edit .env and add your keys:
#   GROQ_API_KEY        → https://console.groq.com  (free)
#   SPEECHMATICS_API_KEY → https://speechmatics.com  (8 free hours/month)
```

Then load them:
```bash
source .env  # Linux/Mac
# OR on Windows: set GROQ_API_KEY=your_key_here
```

### 3. Run

```bash
streamlit run app.py
```

Open http://localhost:8501 — the dashboard appears.

---

## 🏗️ Project Structure

```
ai-vaani/
├── app.py                    # Main Streamlit app (entry point)
├── requirements.txt
├── .env.example              # API key template
├── .gitignore
│
├── components/
│   └── audio_stream.py       # Browser mic capture (streamlit-webrtc)
│
├── utils/
│   ├── groq_analyzer.py      # Groq LLM threat analysis
│   ├── stt_client.py         # Speechmatics STT client
│   └── threat_model.py       # ThreatResult dataclass + helpers
│
├── assets/
│   └── style.css             # Custom dashboard styling
│
└── .streamlit/
    ├── config.toml           # Theme + server config
    └── secrets.toml.example  # Streamlit Cloud secrets template
```

---

## 🎯 How It Works

```
Browser Mic
    │
    ▼
streamlit-webrtc (AudioProcessor)
    │  ~1 second audio chunks
    ▼
Speechmatics API  (mr-IN / hi-IN)
    │  transcript text
    ▼
Groq API — Llama-3-70B
    │  specialized security system prompt
    ▼
ThreatResult (risk_score, threat flags)
    │
    ▼
Streamlit Dashboard
  ├── Risk Score Meter (0–100)
  ├── Threat Indicator Grid
  ├── AI Analysis Summary
  └── 🚨 High-risk alert banner
```

---

## 🛡️ Threat Detection Logic

The Groq system prompt instructs Llama-3 to detect:

| Indicator | Examples |
|-----------|---------|
| **Urgency/Fear** | "खाते बंद होणार", "आज रात्री तोडणे" |
| **OTP Request** | "OTP सांगा", "PIN द्या" |
| **Bank Details** | Account number, IFSC, CVV requests |
| **Impersonation** | Fake SBI, MSEDCL, Income Tax, Police |
| **Cultural Tactics** | Electricity cut threats, KYC expiry, lottery |

Risk score 0–100:
- **0–30**: Benign conversation
- **31–60**: Suspicious, monitor
- **61–80**: High probability scam
- **81–100**: Confirmed scam

---

## 🧪 Demo Scenarios

The dashboard includes three built-in demos (no mic needed):

1. **OTP Fraud (Marathi)** — Fake SBI call requesting OTP + account freeze threat
2. **Electricity Scam (Maharashtra)** — Fake MSEDCL threatening power cutoff
3. **Safe Call (Hindi)** — Benign conversation, should score < 10

---

## 🚀 Deployment (Streamlit Community Cloud)

1. Push your code to GitHub (ensure `.env` is in `.gitignore`)
2. Go to [share.streamlit.io](https://share.streamlit.io) and connect your repo
3. Add secrets in the dashboard:
   - `GROQ_API_KEY`
   - `SPEECHMATICS_API_KEY`
4. Deploy — free hosting included

Update `utils/groq_analyzer.py` and `utils/stt_client.py` to read from `st.secrets`:
```python
import streamlit as st
api_key = st.secrets.get("GROQ_API_KEY") or os.environ.get("GROQ_API_KEY")
```

---

## 🔮 Hackathon Pitch Points

- **Privacy-first**: Llama-3 is open-weight; analysis could move fully on-device (Edge AI pitch)
- **Cultural intelligence**: Understands Maharashtra-specific scam scripts, not just keyword matching
- **Latency**: Groq delivers < 500ms end-to-end analysis — fast enough for live calls
- **Language coverage**: mr-IN, hi-IN, en-IN in a single model

---

## 📦 API Keys & Free Tiers

| Service | Free Tier | Link |
|---------|-----------|------|
| Groq | Unlimited (rate-limited) | [console.groq.com](https://console.groq.com) |
| Speechmatics | 8 hours/month | [speechmatics.com](https://speechmatics.com) |
| Google STT | 60 min/month | [cloud.google.com](https://cloud.google.com/speech-to-text) |
| Streamlit Cloud | Free hosting | [share.streamlit.io](https://share.streamlit.io) |

---

Built for hackathon — AI-Vaani 🇮🇳
# AI-Vaani
# AI-Vaani
