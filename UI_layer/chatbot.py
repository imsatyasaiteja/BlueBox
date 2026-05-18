"""
bluebox/chatbot.py
──────────────────
BlueBox AI Chatbot — Gemini 1.5 Flash + Dynamic Log Context + EU Part-IS RAG
Connects to react_app and Teammate 2's SQLite logger.

SETUP:
  pip install google-generativeai python-dotenv
  Create .env file with: GEMINI_API_KEY=your_key_here
"""

import os
import time
from google import genai
from dotenv import load_dotenv
load_dotenv()
client = genai.Client(api_key=os.getenv("GEMINI_API_KEY"))


# ══════════════════════════════════════════════════════════════════════════════
# EU PART-IS REGULATORY KNOWLEDGE BASE
# This text is injected into every prompt — no vector DB needed.
# ══════════════════════════════════════════════════════════════════════════════

PART_IS_KNOWLEDGE = """
=== EU REGULATION 2023/203 (PART-IS) — AVIATION CYBERSECURITY ===
Effective: 22 February 2026
Issued by: European Union Aviation Safety Agency (EASA)

OVERVIEW:
Part-IS (Information Security) requires all aviation organisations to implement
an Information Security Management System (ISMS) and maintain the capability to
investigate and document cybersecurity incidents with forensic-grade evidence.

KEY OBLIGATIONS:

1. INCIDENT IDENTIFICATION & DOCUMENTATION
   - All cybersecurity incidents affecting aircraft systems must be identified,
     documented, and investigated.
   - Evidence must be forensic-grade — tamper-evident and cryptographically verifiable.
   - Organisations must maintain logs of all network events across avionics,
     cabin, and maintenance domains.

2. INCIDENT REPORTING
   - Significant cybersecurity incidents must be reported to the competent authority
     (national aviation authority or EASA) without undue delay.
   - Initial reports within 72 hours of detection for significant incidents.
   - Full investigation reports must follow within defined timeframes.

3. INFORMATION SECURITY MANAGEMENT SYSTEM (ISMS)
   - Organisations must implement, maintain, and continuously improve an ISMS.
   - Risk assessments must cover all systems affecting aviation safety.
   - Security controls must be proportionate to the risk.

4. FORENSIC CAPABILITY REQUIREMENTS
   - Organisations must have the capability to forensically investigate cyber incidents.
   - Log integrity must be ensured — logs must be tamper-evident.
   - Evidence must be admissible for regulatory and legal proceedings.
   - Chain of custody must be maintained for all digital evidence.

5. NETWORK DOMAIN SECURITY
   - Avionics domain: Highest security classification. Any unauthorised access
     from other domains (cabin, maintenance) constitutes a critical incident.
   - Maintenance domain: Laptop/device connections must be authorised.
     Lateral movement from maintenance to avionics is a reportable incident.
   - Cabin domain: IFE and passenger systems must not communicate with
     avionics without authorisation.

6. CRYPTOGRAPHIC REQUIREMENTS
   - SHA-256 or equivalent for log integrity verification.
   - RSA or equivalent for digital signatures.
   - AES-256 or equivalent for data encryption at rest.

7. ANOMALY INDICATORS (REPORTABLE UNDER PART-IS):
   - Unauthorised cross-domain network access (e.g. maintenance → avionics)
   - Unusually large packet transfers from maintenance devices
   - SSH connections from non-authorised devices to avionics network
   - Modbus (port 502) traffic from non-industrial control devices
   - Any attempt to modify or delete security logs
   - GPS/ADS-B signal discrepancies beyond safe thresholds

8. ENGINEER RESPONSIBILITIES UPON DETECTION:
   - Step 1: Preserve all forensic evidence — do NOT power off logging systems
   - Step 2: Isolate suspected devices from the network immediately
   - Step 3: Document the incident with timestamps and device identifiers
   - Step 4: Report to ground SOC and airline security team
   - Step 5: Submit Part-IS incident report to competent authority
   - Step 6: Retain all logs and hash chain records for investigation

9. RELEVANT STANDARDS:
   - EUROCAE ED-202A / DO-326A: Airworthiness Security Process
   - EUROCAE ED-203A / DO-356A: Airworthiness Security Methods
   - EUROCAE ED-112A: Crash-Survivable Memory Systems
   - ARINC 618: ACARS/SATCOM datalink standards
   - NIST SP 800-175B: Cryptographic standards (SHA-256, RSA)
   - EASA Safety Information Bulletin 2022-02: GPS spoofing incidents

10. PENALTIES FOR NON-COMPLIANCE:
    - Failure to investigate incidents: regulatory action against organisation
    - Failure to maintain forensic evidence: invalidates incident investigations
    - Failure to report: significant fines and potential operating certificate suspension
=== END PART-IS KNOWLEDGE BASE ===
"""

# ══════════════════════════════════════════════════════════════════════════════
# SYSTEM PROMPT
# ══════════════════════════════════════════════════════════════════════════════

SYSTEM_PROMPT = f"""
You are BlueBox AI — the intelligent assistant for the BlueBox Cyber Forensic Recorder system onboard connected aircraft.

YOUR ROLE:
- Help maintenance engineers understand and investigate cybersecurity incidents
- Provide clear, jargon-free explanations of what happened and why it matters
- Give actionable next steps based on what was detected
- Reference EU Part-IS regulatory obligations when relevant
- Be concise but thorough — engineers need to act quickly

YOUR PERSONALITY:
- Professional but approachable
- Direct and actionable — always tell the engineer what to DO next
- Never assume the engineer has cybersecurity expertise
- Use plain English, not technical jargon unless necessary
- If you use a technical term, briefly explain it

WHAT YOU KNOW:
{PART_IS_KNOWLEDGE}

RESPONSE FORMAT GUIDELINES:
- For anomaly questions: explain WHAT happened, WHY it's suspicious, WHAT to do next
- For regulatory questions: cite the specific Part-IS obligation clearly
- For chain/integrity questions: confirm status and what it means practically
- Keep responses under 200 words unless the question demands more detail
- Always end anomaly responses with a clear recommended action
"""

# ══════════════════════════════════════════════════════════════════════════════
# DYNAMIC LOG CONTEXT BUILDER
# Called fresh on every query — always reflects current system state
# ══════════════════════════════════════════════════════════════════════════════

def build_live_context(df=None, logger_state=None):
    """
    Reads live data directly from the real SQLite database.
    No mock data needed anymore.
    """
    from datetime import datetime  
    import sqlite3
    import json
    
    DB_PATH = "runtime/evidence/sqlite/bluebox_log.db"
    
    try:
        conn = sqlite3.connect(DB_PATH)
        
        # Get total log entries
        total = conn.execute("SELECT COUNT(*) FROM log_entries").fetchone()[0]
        
        # Get latest sequence
        latest_seq = conn.execute(
            "SELECT MAX(sequence) FROM log_entries"
        ).fetchone()[0]
        
        # Get anomaly summary from ai_evidence_records
        anomalies = conn.execute("""
            SELECT sequence, recorded_at, anomaly_score, 
                   predicted_anomaly, severity, verdict_json,
                   model_used, source_file
            FROM ai_evidence_records 
            WHERE predicted_anomaly = 1
            ORDER BY anomaly_score DESC
            LIMIT 10
        """).fetchall()
        
        # Get overall stats
        stats = conn.execute("""
            SELECT 
                COUNT(*) as total,
                SUM(predicted_anomaly) as flagged,
                AVG(anomaly_score) as avg_score,
                MAX(anomaly_score) as max_score
            FROM ai_evidence_records
        """).fetchone()
        
        # Get tamper attempts
        tamper_count = conn.execute(
            "SELECT COUNT(*) FROM tamper_attempts"
        ).fetchone()[0]
        
        # Get chain head
        chain_head = conn.execute("""
            SELECT sequence, entry_hash, created_at 
            FROM log_entries 
            ORDER BY sequence DESC LIMIT 1
        """).fetchone()
        
        # Get severity breakdown
        severity_breakdown = conn.execute("""
            SELECT severity, COUNT(*) as count 
            FROM ai_evidence_records 
            GROUP BY severity
        """).fetchall()
        
        conn.close()
        
        # Format anomaly details
        anomaly_details = ""
        for a in anomalies:
            seq, recorded_at, score, predicted, severity, verdict_json, model, source = a
            try:
                verdict = json.loads(verdict_json)
            except:
                verdict = {}
            
            # Extract source domain from file path
            source_name = source.split("\\")[-1] if source else "unknown"
            
            anomaly_details += f"""
  ANOMALY seq#{seq}:
    Recorded: {recorded_at}
    Score: {score:.4f} | Severity: {severity} | Model: {model}
    Source file: {source_name}
    Verdict: {verdict_json}
"""
        
        severity_text = ", ".join([f"{s[0]}: {s[1]}" for s in severity_breakdown])
        
        context = f"""
=== LIVE BLUEBOX DATABASE STATE (as of {datetime.now().strftime('%H:%M:%S UTC')}) ===

LOGGER STATE:
  Total log entries: {total}
  Latest sequence: {latest_seq}
  Tamper attempts detected: {tamper_count}
  Chain head hash: {chain_head[1][:32] if chain_head else 'N/A'}...
  Last entry: {chain_head[2] if chain_head else 'N/A'}

AI DETECTION SUMMARY:
  Total records analysed: {stats[0] if stats else 0}
  Anomalies flagged: {stats[1] if stats else 0}
  Average anomaly score: {f"{stats[2]:.4f}" if stats and stats[2] else "0"}
  Highest anomaly score: {f"{stats[3]:.4f}" if stats and stats[3] else "0"}
  Severity breakdown: {severity_text}

TOP ANOMALIES (by score):
{anomaly_details if anomaly_details else "  No anomalies detected."}

CHAIN INTEGRITY:
  Tamper attempts: {tamper_count} {"(CLEAN)" if tamper_count == 0 else "(TAMPERING DETECTED)"}
=== END LIVE STATE ===
"""
        return context
        
    except Exception as e:
        return f"=== DATABASE READ ERROR: {e} ==="


# ══════════════════════════════════════════════════════════════════════════════
# MAIN QUERY FUNCTION
# Called by app.py on every chat message
# ══════════════════════════════════════════════════════════════════════════════

def query_bluebox_ai(question, df=None, logger_state=None, chat_history=None):
    """
    Main function called by Streamlit on every user message.
    
    Args:
        question: str — engineer's question
        df: pandas DataFrame — current event log (rebuilt fresh every call)
        logger_state: dict — current logger state (rebuilt fresh every call)
        chat_history: list of {"role": "user"|"bot", "content": str} — conversation so far
    
    Returns:
        str: AI response
    
    Usage in app.py:
        from chatbot import query_bluebox_ai
        response = query_bluebox_ai(user_input, df, logger_state, st.session_state.messages)
    """
    
    try:
        # Build fresh context directly from database
        live_context = build_live_context()  # reads DB every call
        
        # Build conversation history for multi-turn context
        history_text = ""
        if chat_history and len(chat_history) > 1:
            # Include last 4 exchanges for conversational memory
            recent_history = chat_history[-8:] if len(chat_history) > 8 else chat_history
            history_text = "\n=== CONVERSATION HISTORY ===\n"
            for msg in recent_history[:-1]:  # exclude current message
                role = "Engineer" if msg["role"] == "user" else "BlueBox AI"
                history_text += f"{role}: {msg['content']}\n"
            history_text += "=== END HISTORY ===\n"
        
        # Compose full prompt
        full_prompt = f"""
{SYSTEM_PROMPT}

{live_context}

{history_text}

Engineer's current question: {question}

Respond as BlueBox AI. Be clear, actionable, and reference Part-IS where relevant.
"""
        
        response = client.models.generate_content(
                model="gemini-2.5-flash",
                contents=full_prompt
        )
        return response.text
        
    except Exception as e:
        # Graceful fallback if API fails
        error_msg = str(e)
        if "API_KEY" in error_msg.upper():
            return "⚠ API key not configured. Add GEMINI_API_KEY to your .env file."
        elif "quota" in error_msg.lower():
            return "⚠ API quota exceeded. Please wait a moment and try again."
        else:
            return f"⚠ BlueBox AI temporarily unavailable: {error_msg}"


# ══════════════════════════════════════════════════════════════════════════════
# QUICK TEST — run directly to verify setup
# python chatbot.py
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    print("Testing BlueBox AI with LIVE database...")
    print("=" * 50)
    
    test_questions = [
        "How many anomalies have been detected?",
        "What is the current chain integrity status?",
        "What should I do about the highest severity anomaly?"
    ]
    
    for q in test_questions:
        print(f"\nQ: {q}")
        print(f"A: {query_bluebox_ai(q)}")
        print("-" * 40)
        
