"""
utils/groq_analyzer.py

Three-tier analysis pipeline:
  1. Groq (cloud, 70B)  — tried first, 4s timeout
  2. Ollama (local, 8B) — silent fallback if Groq fails
  3. Keyword rules      — always works, no network needed
"""

import os
import json
import re
import requests
from utils.threat_model import ThreatResult
from utils.link_detector import detect_suspicious_links

GROQ_API_KEY  = os.environ.get("GROQ_API_KEY", "")
GROQ_URL      = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL    = "llama-3.3-70b-versatile"
OLLAMA_URL    = "http://localhost:11434/v1/chat/completions"
OLLAMA_MODEL  = "llama3:8b"

SYSTEM_PROMPT = """You are an expert cybersecurity analyst specializing in telephone fraud detection for Indian users, with deep knowledge of Marathi and Hindi language manipulation tactics.

Your task: Analyze the provided call transcript (may be in Marathi, Hindi, or English) and detect scam/phishing indicators.

Respond ONLY with valid JSON — no extra text, no markdown code fences.

JSON schema:
{
  "risk_score": <integer 0-100>,
  "detected_language": "<language name in English, e.g. Marathi, Hindi, English>",
  "confidence": <integer 0-100 for language detection confidence>,
  "urgency_detected": <true/false>,
  "otp_request": <true/false>,
  "bank_details_request": <true/false>,
  "impersonation_detected": <true/false>,
  "cultural_tactic": <true/false>,
  "summary": "<2-3 sentence explanation of findings in English>",
  "key_phrases": ["<phrase1>", "<phrase2>"]
}

Scoring guide:
- 0-30: Benign conversation
- 31-60: Suspicious, monitor
- 61-80: High probability scam
- 81-100: Confirmed scam — immediate action needed

Threat definitions:
- urgency_detected: Caller creates time pressure ("account will close", "last notice", "immediately")
- otp_request: Any request for OTP, PIN, password, CVV
- bank_details_request: Requests account number, IFSC, card details, Aadhaar linked bank info
- impersonation_detected: Pretends to be bank, MSEDCL, police, IT dept, government, telecom
- cultural_tactic: Uses India-specific manipulation — electricity disconnection threats, income tax raids, KYC expiry, lottery winnings, fake courier holds

Common Indian scam scripts to detect:
- SBI/HDFC/Kotak: "खाते बंद होणार", "KYC अपडेट करा", "OTP सांगा"
- MSEDCL electricity: "वीज तोडणे", "बिल थकीत"
- IT/Police: "arrest warrant", "income tax notice", "cyber crime"
- Courier: "FedEx parcel hold", "customs clearance"
"""

# ── Tier 3: keyword rule engine ────────────────────────────────────────────────
_URGENCY_KW    = ["बंद होणार","account will close","last notice","immediately","तात्काळ","अन्यथा","तोडले जाईल","arrest","blocked"]
_OTP_KW        = ["otp","pin","password","cvv","पिन","ओटीपी","पासवर्ड"]
_BANK_KW       = ["account number","खाते क्रमांक","ifsc","card number","aadhaar","आधार","cvv","bank details"]
_IMPERSON_KW   = ["sbi","hdfc","icici","msedcl","police","income tax","cyber crime","government","बँकेतून","कार्यालयातून"]
_CULTURAL_KW   = ["kyc","वीज","electricity","income tax","courier","parcel","lottery","prize","refund","cashback"]


def _keyword_analysis(transcript: str) -> ThreatResult:
    t = transcript.lower()
    urgency    = any(k.lower() in t for k in _URGENCY_KW)
    otp        = any(k.lower() in t for k in _OTP_KW)
    bank       = any(k.lower() in t for k in _BANK_KW)
    imperson   = any(k.lower() in t for k in _IMPERSON_KW)
    cultural   = any(k.lower() in t for k in _CULTURAL_KW)
    links      = detect_suspicious_links(transcript)

    score = sum([urgency * 25, otp * 30, bank * 25, imperson * 15, cultural * 10])
    score += min(len([l for l in links if l.risk == "HIGH"]) * 10, 20)
    score = min(score, 100)

    flags = [k for k in _OTP_KW + _BANK_KW + _URGENCY_KW if k.lower() in t][:5]

    r = ThreatResult(
        risk_score=score,
        detected_language="Unknown",
        confidence=0,
        urgency_detected=urgency,
        otp_request=otp,
        bank_details_request=bank,
        impersonation_detected=imperson,
        cultural_tactic=cultural,
        summary="Analyzed using offline keyword rules (no LLM available).",
        key_phrases=flags,
        suspicious_links=links,
    )
    r._backend = "keyword-rules"
    return r


# ── Shared LLM call ────────────────────────────────────────────────────────────
def _llm_call(url: str, model: str, api_key: str, user_message: str, timeout: int) -> dict:
    """Raw HTTP POST to any OpenAI-compatible endpoint. Returns parsed JSON data dict."""
    headers = {"Content-Type": "application/json"}
    if api_key:
        headers["Authorization"] = f"Bearer {api_key}"

    payload = {
        "model": model,
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user",   "content": user_message},
        ],
        "temperature": 0.1,
        "max_tokens": 600,
    }

    resp = requests.post(url, headers=headers, json=payload, timeout=timeout)
    resp.raise_for_status()
    raw = resp.json()["choices"][0]["message"]["content"].strip()
    raw = re.sub(r"^```(?:json)?", "", raw).strip()
    raw = re.sub(r"```$", "", raw).strip()
    return json.loads(raw)


def _build_result(data: dict, transcript: str, backend: str) -> ThreatResult:
    links      = detect_suspicious_links(transcript)
    high_links = [l for l in links if l.risk == "HIGH"]
    base_score = int(data.get("risk_score", 0))
    final_score = min(base_score + min(len(high_links) * 10, 20), 100)

    r = ThreatResult(
        risk_score=final_score,
        detected_language=data.get("detected_language", "Unknown"),
        confidence=int(data.get("confidence", 0)),
        urgency_detected=bool(data.get("urgency_detected", False)),
        otp_request=bool(data.get("otp_request", False)),
        bank_details_request=bool(data.get("bank_details_request", False)),
        impersonation_detected=bool(data.get("impersonation_detected", False)),
        cultural_tactic=bool(data.get("cultural_tactic", False)),
        summary=data.get("summary", "Analysis complete."),
        key_phrases=data.get("key_phrases", []),
        suspicious_links=links,
    )
    r._backend = backend
    return r


# ── Public entry point ─────────────────────────────────────────────────────────
def analyze_transcript(transcript: str, language: str = "mr-IN") -> ThreatResult:
    """
    Tier 1 → Groq (4s timeout)
    Tier 2 → Ollama local (5s timeout)
    Tier 3 → Keyword rules (always works)
    """
    user_message = f'Language hint: {language}\n\nTranscript to analyze:\n"""\n{transcript}\n"""\n\nRespond with JSON only.'

    # ── Tier 1: Groq ──────────────────────────────────────────────────────────
    try:
        data = _llm_call(GROQ_URL, GROQ_MODEL, GROQ_API_KEY, user_message, timeout=4)
        return _build_result(data, transcript, "groq")
    except Exception:
        pass  # silent — try Ollama next

    # ── Tier 2: Ollama ────────────────────────────────────────────────────────
    try:
        data = _llm_call(OLLAMA_URL, OLLAMA_MODEL, "ollama", user_message, timeout=5)
        return _build_result(data, transcript, "ollama")
    except Exception:
        pass  # silent — fall through to rules

    # ── Tier 3: Keyword rules ─────────────────────────────────────────────────
    return _keyword_analysis(transcript)


def get_backend_label(result: ThreatResult) -> str | None:
    """Returns a UI warning string if not using Groq, else None."""
    backend = getattr(result, "_backend", "groq")
    if backend == "ollama":
        return "⚠️ Offline mode — using local model (lower accuracy)"
    if backend == "keyword-rules":
        return "⚠️ Offline mode — no LLM available, using keyword rules only"
    return None
