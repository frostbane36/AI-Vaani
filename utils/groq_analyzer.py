"""
utils/groq_analyzer.py
Sends transcript to Groq (Llama-3-70B) for security analysis.
Returns a structured ThreatResult.
"""

import os
import json
import re
from groq import Groq
from utils.threat_model import ThreatResult

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

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
- 0–30: Benign conversation
- 31–60: Suspicious, monitor
- 61–80: High probability scam
- 81–100: Confirmed scam — immediate action needed

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

def analyze_transcript(transcript: str, language: str = "mr-IN") -> ThreatResult:
    """
    Send transcript to Groq Llama-3-70B for analysis.
    Returns a ThreatResult dataclass.
    """
    user_message = f"""Language hint: {language}

Transcript to analyze:
\"\"\"
{transcript}
\"\"\"

Respond with JSON only."""

    try:
        response = client.chat.completions.create(
            model="llama-3.3-70b-versatile",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_message},
            ],
            temperature=0.1,
            max_tokens=600,
        )

        raw = response.choices[0].message.content.strip()

        # Strip markdown fences if model adds them
        raw = re.sub(r"^```(?:json)?", "", raw).strip()
        raw = re.sub(r"```$", "", raw).strip()

        data = json.loads(raw)
        return ThreatResult(
            risk_score=int(data.get("risk_score", 0)),
            detected_language=data.get("detected_language", "Unknown"),
            confidence=int(data.get("confidence", 0)),
            urgency_detected=bool(data.get("urgency_detected", False)),
            otp_request=bool(data.get("otp_request", False)),
            bank_details_request=bool(data.get("bank_details_request", False)),
            impersonation_detected=bool(data.get("impersonation_detected", False)),
            cultural_tactic=bool(data.get("cultural_tactic", False)),
            summary=data.get("summary", "Analysis complete."),
            key_phrases=data.get("key_phrases", []),
        )

    except json.JSONDecodeError as e:
        return ThreatResult(
            risk_score=0,
            detected_language="Unknown",
            confidence=0,
            urgency_detected=False,
            otp_request=False,
            bank_details_request=False,
            impersonation_detected=False,
            cultural_tactic=False,
            summary=f"JSON parse error: {e}. Raw response: {raw[:200]}",
            key_phrases=[],
        )
    except Exception as e:
        return ThreatResult(
            risk_score=0,
            detected_language="Unknown",
            confidence=0,
            urgency_detected=False,
            otp_request=False,
            bank_details_request=False,
            impersonation_detected=False,
            cultural_tactic=False,
            summary=f"Analysis error: {str(e)}",
            key_phrases=[],
        )
