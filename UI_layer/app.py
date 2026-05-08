import streamlit as st
import pandas as pd
import time
from datetime import datetime, timedelta
import random

# ─── PAGE CONFIG ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="BlueBox | Cyber Forensic Recorder",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── CUSTOM CSS ────────────────────────────────────────────────────────────────
st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

  html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #0a0e1a;
    color: #c9d6e3;
  }
  .stApp { background-color: #0a0e1a; }

  section[data-testid="stSidebar"] {
    background-color: #0d1220;
    border-right: 1px solid #1e3a5f;
  }
  div[data-testid="metric-container"] {
    background: linear-gradient(135deg, #0d1a2e, #0f2340);
    border: 1px solid #1e3a5f;
    border-radius: 8px;
    padding: 16px;
  }
  div[data-testid="metric-container"] label {
    color: #4a9eff !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.75rem !important;
    letter-spacing: 0.1em;
  }
  div[data-testid="metric-container"] div[data-testid="stMetricValue"] {
    color: #e0f0ff !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 1.8rem !important;
  }
  h1, h2, h3 { font-family: 'Rajdhani', sans-serif !important; color: #e0f0ff !important; }

  .bb-header {
    background: linear-gradient(90deg, #050d1a, #0a1f3d, #050d1a);
    border: 1px solid #1e3a5f;
    border-left: 4px solid #4a9eff;
    padding: 20px 28px;
    border-radius: 8px;
    margin-bottom: 24px;
  }
  .bb-header h1 {
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 2rem !important;
    color: #4a9eff !important;
    margin: 0 !important;
    letter-spacing: 0.15em;
  }
  .bb-header p { color: #6b9ac4; margin: 4px 0 0 0; font-size: 0.9rem; letter-spacing: 0.05em; }

  .badge-ok {
    background: #0a2e1a; border: 1px solid #00c853; color: #00e676;
    padding: 3px 12px; border-radius: 20px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.75rem; letter-spacing: 0.1em;
  }
  .badge-warn {
    background: #2e1a00; border: 1px solid #ff6d00; color: #ff9100;
    padding: 3px 12px; border-radius: 20px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.75rem; letter-spacing: 0.1em;
  }
  .badge-crit {
    background: #2e0a0a; border: 1px solid #d50000; color: #ff1744;
    padding: 3px 12px; border-radius: 20px;
    font-family: 'Share Tech Mono', monospace; font-size: 0.75rem; letter-spacing: 0.1em;
  }
  .domain-card {
    border-radius: 8px; padding: 14px 16px; text-align: center;
    font-family: 'Share Tech Mono', monospace; font-size: 0.78rem;
    letter-spacing: 0.08em; margin-bottom: 8px;
  }
  .domain-avionics {
    background: #0a1a0e; border: 1px solid #00c853; color: #00e676;
  }
  .domain-cabin {
    background: #0a1220; border: 1px solid #4a9eff; color: #4a9eff;
  }
  .domain-maintenance {
    background: #2e1a00; border: 1px solid #ff9100; color: #ff9100;
  }
  .panel-title {
    font-family: 'Share Tech Mono', monospace;
    color: #4a9eff; font-size: 0.8rem; letter-spacing: 0.15em;
    text-transform: uppercase; margin-bottom: 12px;
    border-bottom: 1px solid #1e3a5f; padding-bottom: 8px;
  }
  .chain-entry {
    background: #060d1a; border-left: 3px solid #1e3a5f;
    padding: 8px 12px; margin: 4px 0;
    font-family: 'Share Tech Mono', monospace; font-size: 0.72rem;
    color: #6b9ac4; border-radius: 0 4px 4px 0;
  }
  .chain-entry.anomaly { border-left: 3px solid #ff1744; color: #ff6b6b; background: #1a0608; }
  .chain-entry.verified { border-left: 3px solid #00c853; }
  .replay-entry {
    background: #060d1a; border-left: 3px solid #1e3a5f;
    padding: 10px 14px; margin: 6px 0;
    font-family: 'Share Tech Mono', monospace; font-size: 0.75rem;
    color: #6b9ac4; border-radius: 0 6px 6px 0;
    transition: all 0.3s;
  }
  .replay-entry.active { border-left: 3px solid #4a9eff; color: #c9d6e3; background: #0d1a2e; }
  .replay-entry.anomaly-replay { border-left: 3px solid #ff1744; color: #ff6b6b; background: #1a0608; }
  .chat-user {
    background: #0f2340; border: 1px solid #1e3a5f;
    border-radius: 12px 12px 4px 12px; padding: 10px 14px; margin: 8px 0;
    color: #c9d6e3; font-size: 0.9rem;
  }
  .chat-bot {
    background: #060d1a; border: 1px solid #00c853;
    border-radius: 4px 12px 12px 12px; padding: 10px 14px; margin: 8px 0;
    color: #a0d4b0; font-size: 0.88rem;
    font-family: 'Share Tech Mono', monospace;
  }
  .stButton > button {
    background: linear-gradient(135deg, #0a1f3d, #1e3a5f);
    border: 1px solid #4a9eff; color: #4a9eff;
    font-family: 'Share Tech Mono', monospace;
    letter-spacing: 0.1em; border-radius: 4px; transition: all 0.2s;
  }
  .stButton > button:hover { background: #4a9eff; color: #0a0e1a; }
  #MainMenu {visibility: hidden;} footer {visibility: hidden;}
</style>
""", unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# DATA LAYER
# ─────────────────────────────────────────────────────────────────────────────
# 🔌 INTEGRATION POINT A — TEAMMATE 2 (Hash Chain Logger)
# When teammate's SQLite database is ready, replace get_mock_logs() with:
#
#   import sqlite3
#   def load_from_sqlite(db_path="bluebox_logs.db"):
#       conn = sqlite3.connect(db_path)
#       df = pd.read_sql("SELECT * FROM log_entries ORDER BY timestamp", conn)
#       conn.close()
#       return df
#
# Expected columns from teammate's DB:
#   timestamp, source, destination, protocol, port, packet_size,
#   domain, hash, prev_hash, rsa_signature, chain_valid
# ══════════════════════════════════════════════════════════════════════════════

@st.cache_data
def get_mock_logs():
    base_time = datetime(2026, 4, 30, 9, 0, 0)
    domains = {
        "ACARS-01": "Avionics", "CMU-02": "Avionics",
        "IFE-04": "Cabin", "PASS-SRV": "Cabin",
        "MAINT-05": "Maintenance", "EFB-03": "Maintenance"
    }
    sources = list(domains.keys())
    events = []
    for i in range(18):
        src = random.choice(sources)
        events.append({
            "id": i + 1,
            "timestamp": base_time + timedelta(minutes=i * 5),
            "source": src,
            "destination": random.choice(["ROUTER-A", "SWITCH-B", "GW-01", "AVIONICS-NET"]),
            "protocol": random.choice(["ARINC-429", "ARINC-664", "TCP/IP", "UDP"]),
            "port": random.choice([443, 8080, 3000, 5000]),
            "packet_size": random.randint(64, 512),
            "domain": domains[src],
            "anomaly_score": round(random.uniform(0.05, 0.25), 3),
            "anomaly_reason": "NULL",
            "flagged": False,
            "hash": f"{random.randint(0,0xFFFFFFFF):08x}{random.randint(0,0xFFFFFFFF):08x}",
            "prev_hash": f"{random.randint(0,0xFFFFFFFF):08x}" if i > 0 else "0000000000000000",
            "rsa_signature": f"RSA-{random.randint(100000,999999)}",
            "chain_valid": True
        })

    # Inject anomalies
    events.insert(10, {
        "id": 11, "timestamp": base_time + timedelta(minutes=55),
        "source": "MAINT-05", "destination": "AVIONICS-NET",
        "protocol": "TCP/IP", "port": 22, "packet_size": 4821,
        "domain": "Maintenance",
        "anomaly_score": 0.847,
        "anomaly_reason": "Packet size 9.4× above baseline; SSH to avionics domain (lateral movement)",
        "flagged": True,
        "hash": "ff3a9c12de456b78", "prev_hash": "ab12cd34ef56gh78",
        "rsa_signature": "RSA-847291", "chain_valid": True
    })
    events.insert(14, {
        "id": 15, "timestamp": base_time + timedelta(minutes=72),
        "source": "EFB-03", "destination": "AVIONICS-NET",
        "protocol": "UDP", "port": 502, "packet_size": 3204,
        "domain": "Maintenance",
        "anomaly_score": 0.762,
        "anomaly_reason": "Modbus port 502 access from EFB device; cross-domain protocol violation",
        "flagged": True,
        "hash": "ab91f34c7e820d55", "prev_hash": "ff3a9c12de456b78",
        "rsa_signature": "RSA-762104", "chain_valid": True
    })

    # Re-number IDs
    for i, e in enumerate(events):
        e["id"] = i + 1
    return pd.DataFrame(events)

# ══════════════════════════════════════════════════════════════════════════════
# 🔌 INTEGRATION POINT B — TEAMMATE 1 (Anomaly Detection + SHAP + LLM)
# When teammate's FastAPI is ready, replace MOCK_SHAP and chatbot responses with:
#
#   import requests
#   def get_shap_values(event_id):
#       r = requests.get(f"http://localhost:8000/shap/{event_id}")
#       return r.json()   # returns {"feature": shap_value, ...}
#
#   def query_chatbot(question, context_logs):
#       r = requests.post("http://localhost:8000/chat",
#           json={"question": question, "logs": context_logs})
#       return r.json()["answer"]
# ══════════════════════════════════════════════════════════════════════════════

MOCK_SHAP = {
    "packet_size": 0.41,
    "port": 0.28,
    "source_device": 0.18,
    "protocol": 0.09,
    "frequency": 0.04
}

PART_IS_CONTEXT = """
EU Part-IS (Regulation 2023/203) requires aviation organisations to:
- Identify and document cybersecurity incidents
- Maintain forensic-grade evidence of network events
- Report incidents to competent authorities within defined timeframes
- Implement information security management systems (ISMS)
"""

MOCK_CHAT_RESPONSES = {
    "default": "I analysed the log chain. No additional anomalies found beyond the 2 flagged events. Chain integrity is verified across all 20 entries. All RSA signatures valid.",
    "09:55": "At 09:55 UTC, I detected a CRITICAL anomaly. Source MAINT-05 (Maintenance domain) attempted an SSH connection (port 22) to AVIONICS-NET with a packet size of 4,821 bytes — 9.4× above baseline. This is consistent with lateral movement from maintenance into avionics domain. SHAP primary driver: packet_size (0.41).",
    "anomal": "2 anomalies detected this session:\n\n1. [CRITICAL · 09:55] MAINT-05 → AVIONICS-NET · Score 0.847 · SSH lateral movement · packet size 4,821B\n\n2. [HIGH · 10:12] EFB-03 → AVIONICS-NET · Score 0.762 · Modbus port 502 cross-domain violation · 3,204B\n\nBoth events are cryptographically sealed in the hash chain.",
    "chain": f"Hash chain integrity: VERIFIED. All 20 entries validated. RSA signature check: PASSED. No tampering detected. Last verified: {datetime.now().strftime('%H:%M:%S UTC')}",
    "maint": "MAINT-05 appears in 3 log entries. 1 flagged as CRITICAL (09:55 UTC). Device connected to AVIONICS-NET via SSH — outside its expected network domain. Recommend immediate quarantine and forensic imaging of MAINT-05.",
    "part-is": f"Under EU Part-IS (Reg. 2023/203):\n\n{PART_IS_CONTEXT}\n\nBlueBox has recorded 2 reportable incidents this session. The generated PDF report satisfies Part-IS documentation requirements.",
    "shap": "SHAP attribution for the CRITICAL anomaly (MAINT-05):\n\n• packet_size: 0.41 — PRIMARY DRIVER (4,821B vs baseline ~450B)\n• port: 0.28 — SSH port 22 is unexpected from maintenance domain\n• source_device: 0.18 — MAINT-05 has no prior AVIONICS-NET access history\n• protocol: 0.09 — TCP/IP cross-domain is anomalous\n• frequency: 0.04 — minor contributor"
}

# ─── SIDEBAR ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown("""
    <div style='text-align:center; padding:16px 0 8px 0;'>
      <span style='font-family:Share Tech Mono,monospace; font-size:1.4rem; color:#4a9eff; letter-spacing:0.2em;'>■ BLUEBOX</span><br>
      <span style='font-size:0.7rem; color:#4a6b8a; letter-spacing:0.1em;'>CYBER FORENSIC RECORDER</span>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    st.markdown("<span style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#4a9eff; letter-spacing:0.1em;'>▸ SYSTEM STATUS</span>", unsafe_allow_html=True)
    st.markdown("<span class='badge-ok'>● CHAIN INTEGRITY: OK</span><br><br>", unsafe_allow_html=True)
    st.markdown("<span class='badge-warn'>● ANOMALIES DETECTED: 2</span><br><br>", unsafe_allow_html=True)
    st.markdown("<span class='badge-ok'>● LOGGER: ACTIVE</span><br><br>", unsafe_allow_html=True)
    st.markdown("<span class='badge-ok'>● RSA SIGNATURES: VALID</span>", unsafe_allow_html=True)

    st.divider()
    st.markdown("<span style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#4a9eff; letter-spacing:0.1em;'>▸ FLIGHT INFO</span>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#6b9ac4; line-height:2;'>
    FLIGHT &nbsp;&nbsp;&nbsp;: SQ321<br>
    AIRCRAFT : A350-900<br>
    ROUTE &nbsp;&nbsp;&nbsp;: SIN → LHR<br>
    DATE &nbsp;&nbsp;&nbsp;&nbsp;: 2026-04-30<br>
    SESSION &nbsp;: 09:00–10:30 UTC
    </div>
    """, unsafe_allow_html=True)

    st.divider()
    st.markdown("<span style='font-family:Share Tech Mono,monospace; font-size:0.7rem; color:#4a9eff; letter-spacing:0.1em;'>▸ NETWORK DOMAINS</span>", unsafe_allow_html=True)
    st.markdown("<div class='domain-card domain-avionics'>✈ AVIONICS<br><span style='font-size:0.65rem;'>ACARS-01 · CMU-02</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='domain-card domain-cabin'>🛋 CABIN<br><span style='font-size:0.65rem;'>IFE-04 · PASS-SRV</span></div>", unsafe_allow_html=True)
    st.markdown("<div class='domain-card domain-maintenance'>🔧 MAINTENANCE<br><span style='font-size:0.65rem;'>MAINT-05 · EFB-03</span></div>", unsafe_allow_html=True)

    st.divider()
    page = st.radio(
        "NAVIGATE",
        ["📊 Dashboard", "🔗 Chain Integrity", "▶ Forensic Replay", "💬 LLM Chatbot", "📄 Report"],
        label_visibility="collapsed"
    )

# ─── HEADER ────────────────────────────────────────────────────────────────────
st.markdown("""
<div class='bb-header'>
  <h1>■ BLUEBOX</h1>
  <p>Cyber Forensic Black Box &nbsp;|&nbsp; Airbus Fly Your Ideas 2026 &nbsp;|&nbsp; Team 83-7438 &nbsp;|&nbsp; SQ321 · SIN→LHR · 2026-04-30</p>
</div>
""", unsafe_allow_html=True)

df = get_mock_logs()

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 1: DASHBOARD — Alerts + SHAP Advisory Panel
# ══════════════════════════════════════════════════════════════════════════════
if page == "📊 Dashboard":

    # KPI row
    c1, c2, c3, c4 = st.columns(4)
    c1.metric("TOTAL EVENTS", str(len(df)), "logged this session")
    c2.metric("ANOMALIES", str(df["flagged"].sum()), delta="▲ HIGH SEVERITY", delta_color="inverse")
    c3.metric("CHAIN STATUS", "VERIFIED", f"{len(df)}/{len(df)} valid")
    c4.metric("RSA SIGNATURES", "ALL VALID", "TPM verified")

    st.markdown("<br>", unsafe_allow_html=True)

    # Network domain traffic summary
    st.markdown("<div class='panel-title'>🌐 NETWORK DOMAIN TRAFFIC</div>", unsafe_allow_html=True)
    d1, d2, d3 = st.columns(3)
    for col, domain, color, icon in [
        (d1, "Avionics", "#00e676", "✈"),
        (d2, "Cabin", "#4a9eff", "🛋"),
        (d3, "Maintenance", "#ff9100", "🔧")
    ]:
        domain_df = df[df["domain"] == domain]
        flagged_count = domain_df["flagged"].sum()
        col.markdown(f"""
        <div style='background:#0d1a2e; border:1px solid {color}33; border-top: 3px solid {color};
                    border-radius:6px; padding:14px; text-align:center;'>
          <div style='font-size:1.4rem;'>{icon}</div>
          <div style='font-family:Share Tech Mono,monospace; color:{color}; font-size:0.8rem;
                      letter-spacing:0.1em; margin:4px 0;'>{domain.upper()} DOMAIN</div>
          <div style='font-size:1.6rem; color:#e0f0ff; font-family:Share Tech Mono,monospace;'>{len(domain_df)}</div>
          <div style='font-size:0.72rem; color:#6b9ac4;'>events logged</div>
          {"<div style='color:#ff1744; font-size:0.75rem; margin-top:6px; font-family:Share Tech Mono,monospace;'>⚠ " + str(flagged_count) + " ANOMAL" + ("Y" if flagged_count==1 else "IES") + "</div>" if flagged_count > 0 else "<div style='color:#00e676; font-size:0.72rem; margin-top:6px;'>✓ CLEAN</div>"}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Anomaly alerts
    st.markdown("<div class='panel-title'>⚠ ANOMALY ALERTS + SHAP ADVISORY</div>", unsafe_allow_html=True)
    for _, row in df[df["flagged"]].iterrows():
        severity = "CRITICAL" if row["anomaly_score"] > 0.8 else "HIGH"
        badge_color = "#ff1744" if severity == "CRITICAL" else "#ff9100"
        st.markdown(f"""
        <div style='background:#1a0608; border:1px solid {badge_color}; border-left:4px solid {badge_color};
                    border-radius:6px; padding:14px 18px; margin-bottom:12px;'>
          <div style='display:flex; justify-content:space-between; align-items:center;'>
            <span style='font-family:Share Tech Mono,monospace; color:{badge_color}; font-size:0.85rem; letter-spacing:0.1em;'>
              ■ ANOMALY DETECTED — {row['timestamp'].strftime('%H:%M:%S UTC')}
            </span>
            <span style='background:#0a0a0a; border:1px solid {badge_color}; color:{badge_color};
                         padding:3px 12px; border-radius:20px; font-family:Share Tech Mono,monospace; font-size:0.75rem;'>
              {severity} · Score: {row['anomaly_score']}
            </span>
          </div>
          <div style='margin-top:10px; font-size:0.82rem; color:#c9a0a0; line-height:2;'>
            <b>Source:</b> {row['source']} ({row['domain']} Domain) &nbsp;→&nbsp;
            <b>Dest:</b> {row['destination']}<br>
            <b>Protocol:</b> {row['protocol']} &nbsp;|&nbsp;
            <b>Port:</b> {row['port']} &nbsp;|&nbsp;
            <b>Packet Size:</b> {row['packet_size']} bytes
          </div>
          <div style='margin-top:8px; background:#0d0608; border-radius:4px; padding:8px 12px;
                      font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#ff9b9b;'>
            🧠 SHAP REASON: {row['anomaly_reason']}
          </div>
          <div style='margin-top:6px; font-size:0.7rem; font-family:Share Tech Mono,monospace; color:#6b4a4a;'>
            HASH: {row['hash']} &nbsp;|&nbsp; RSA: {row['rsa_signature']} &nbsp;|&nbsp; CHAIN: ✓ VERIFIED
          </div>
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # SHAP chart + anomaly score chart
    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown("<div class='panel-title'>🧠 SHAP FEATURE ATTRIBUTION</div>", unsafe_allow_html=True)
        st.caption("Why was the CRITICAL anomaly flagged? (MAINT-05 event)")
        shap_df = pd.DataFrame({
            "Feature": list(MOCK_SHAP.keys()),
            "SHAP Value": list(MOCK_SHAP.values())
        }).sort_values("SHAP Value", ascending=True)
        st.bar_chart(shap_df.set_index("Feature"), color="#ff1744", height=220)
    with col_b:
        st.markdown("<div class='panel-title'>📈 ANOMALY SCORES — ALL EVENTS</div>", unsafe_allow_html=True)
        st.caption("Scores above 0.5 are flagged as anomalous")
        chart_df = df[["timestamp", "anomaly_score"]].copy().set_index("timestamp")
        st.line_chart(chart_df, color="#4a9eff", height=220)

    st.markdown("<br>", unsafe_allow_html=True)

    # Full event log
    st.markdown("<div class='panel-title'>📋 FULL EVENT LOG</div>", unsafe_allow_html=True)
    display_df = df[["id", "timestamp", "domain", "source", "destination",
                      "protocol", "port", "packet_size", "anomaly_score",
                      "anomaly_reason", "flagged", "chain_valid"]].copy()
    display_df["timestamp"] = display_df["timestamp"].dt.strftime("%H:%M:%S")
    display_df["flagged"] = display_df["flagged"].map({True: "⚠ YES", False: "—"})
    display_df["chain_valid"] = display_df["chain_valid"].map({True: "✓", False: "✗"})
    st.dataframe(display_df, use_container_width=True, height=300)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 2: CHAIN INTEGRITY PANEL
# ══════════════════════════════════════════════════════════════════════════════
elif page == "🔗 Chain Integrity":

    st.markdown("<div class='panel-title'>🔗 CHAIN INTEGRITY PANEL</div>", unsafe_allow_html=True)

    # Integrity summary
    st.markdown("""
    <div style='background:#0a1a0a; border:1px solid #00c853; border-radius:6px; padding:14px 18px; margin-bottom:16px;'>
      <span style='font-family:Share Tech Mono,monospace; color:#00e676; font-size:0.85rem; letter-spacing:0.1em;'>
        ✓ SHA-256 HASH CHAIN: VERIFIED &nbsp;|&nbsp; RSA SIGNATURES: ALL VALID &nbsp;|&nbsp;
        TPM KEY: ACTIVE &nbsp;|&nbsp; NO TAMPERING DETECTED
      </span>
    </div>
    """, unsafe_allow_html=True)

    # How it works
    with st.expander("ℹ How the hash chain works"):
        st.markdown("""
        <div style='font-size:0.82rem; color:#6b9ac4; line-height:2;'>
        <b>HashN = f(LogN + Hash(N-1))</b><br><br>
        Every network event is hashed using <b>SHA-256</b> combined with the previous entry's hash.
        Each entry is also signed with an <b>RSA private key</b> stored in a Trusted Platform Module (TPM).<br><br>
        • Modify any entry → all subsequent hashes break → detected instantly<br>
        • Delete any entry → chain gap detected → integrity fails<br>
        • Admin access cannot silently erase evidence — the math prevents it
        </div>
        """, unsafe_allow_html=True)

    # Hash verification steps
    st.markdown("<div class='panel-title'>▸ HASH VERIFICATION + RSA SIGN CHECK</div>", unsafe_allow_html=True)
    hc1, hc2, hc3 = st.columns(3)
    hc1.markdown("""
    <div style='background:#0a1a0a; border:1px solid #00c853; border-radius:6px; padding:12px; text-align:center;'>
      <div style='font-family:Share Tech Mono,monospace; color:#00e676; font-size:0.75rem;'>SHA-256 CHAIN</div>
      <div style='font-size:1.4rem; margin:6px 0;'>✓</div>
      <div style='font-size:0.7rem; color:#4a9eff;'>20/20 entries valid</div>
    </div>
    """, unsafe_allow_html=True)
    hc2.markdown("""
    <div style='background:#0a1a0a; border:1px solid #00c853; border-radius:6px; padding:12px; text-align:center;'>
      <div style='font-family:Share Tech Mono,monospace; color:#00e676; font-size:0.75rem;'>RSA SIGNATURES</div>
      <div style='font-size:1.4rem; margin:6px 0;'>✓</div>
      <div style='font-size:0.7rem; color:#4a9eff;'>TPM key verified</div>
    </div>
    """, unsafe_allow_html=True)
    hc3.markdown("""
    <div style='background:#0a1a0a; border:1px solid #00c853; border-radius:6px; padding:12px; text-align:center;'>
      <div style='font-family:Share Tech Mono,monospace; color:#00e676; font-size:0.75rem;'>APPEND-ONLY STORE</div>
      <div style='font-size:1.4rem; margin:6px 0;'>✓</div>
      <div style='font-size:0.7rem; color:#4a9eff;'>SQLite locked</div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Chain entries
    st.markdown("<div class='panel-title'>▸ FULL HASH CHAIN LOG</div>", unsafe_allow_html=True)
    for i, row in df.iterrows():
        entry_class = "chain-entry anomaly" if row["flagged"] else "chain-entry verified"
        flag = " ⚠ ANOMALY" if row["flagged"] else " ✓"
        st.markdown(f"""
        <div class='{entry_class}'>
          [{row['id']:02d}] {row['timestamp'].strftime('%H:%M:%S')} &nbsp;|&nbsp;
          <b>{row['domain']}</b> &nbsp;|&nbsp;
          {row['source']} → {row['destination']} &nbsp;|&nbsp;
          {row['protocol']} · {row['packet_size']}B &nbsp;|&nbsp;
          HASH: {row['hash']} &nbsp;|&nbsp;
          SIG: {row['rsa_signature']}
          {flag}
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    # Tamper simulation
    st.markdown("<div class='panel-title'>🔬 TAMPER DETECTION SIMULATION</div>", unsafe_allow_html=True)
    st.caption("Demonstrates what happens when an attacker tries to silently delete a log entry.")
    if st.button("⚡ SIMULATE TAMPER ATTEMPT ON ENTRY #11"):
        with st.spinner("Simulating deletion of anomaly entry #11..."):
            time.sleep(1.5)
        st.markdown("""
        <div style='background:#1a0608; border:1px solid #ff1744; border-radius:6px; padding:14px 18px; margin-top:8px;'>
          <span style='font-family:Share Tech Mono,monospace; color:#ff1744; font-size:0.85rem; letter-spacing:0.05em;'>
            ✗ TAMPER DETECTED<br>
            Entry #11 deleted → Hash mismatch propagated across entries #12–20<br>
            RSA signature chain invalidated → Forensic alert triggered<br><br>
            <span style='color:#ff9b9b;'>An attacker with full admin access CANNOT silently erase evidence.</span>
          </span>
        </div>
        """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 3: FORENSIC REPLAY
# ══════════════════════════════════════════════════════════════════════════════
elif page == "▶ Forensic Replay":

    st.markdown("<div class='panel-title'>▶ FORENSIC REPLAY</div>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-size:0.82rem; color:#6b9ac4; margin-bottom:16px; line-height:1.8;'>
    Step through the network event timeline to reconstruct exactly what happened during the flight.
    Filter by domain or time window to focus the investigation.
    </div>
    """, unsafe_allow_html=True)

    # Filters
    fc1, fc2, fc3 = st.columns(3)
    with fc1:
        domain_filter = st.selectbox("DOMAIN FILTER",
            ["All Domains", "Avionics", "Cabin", "Maintenance"],
            key="domain_filter")
    with fc2:
        show_anomalies_only = st.checkbox("ANOMALIES ONLY", value=False)
    with fc3:
        replay_speed = st.selectbox("REPLAY MODE", ["Manual step", "Auto replay"])

    # Apply filters
    replay_df = df.copy()
    if domain_filter != "All Domains":
        replay_df = replay_df[replay_df["domain"] == domain_filter]
    if show_anomalies_only:
        replay_df = replay_df[replay_df["flagged"] == True]

    st.markdown(f"<div style='font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#4a9eff; margin:8px 0;'>SHOWING {len(replay_df)} EVENTS</div>", unsafe_allow_html=True)

    # Step control
    if "replay_step" not in st.session_state:
        st.session_state.replay_step = 0

    col_prev, col_info, col_next = st.columns([1, 3, 1])
    with col_prev:
        if st.button("◀ PREV") and st.session_state.replay_step > 0:
            st.session_state.replay_step -= 1
    with col_next:
        if st.button("NEXT ▶") and st.session_state.replay_step < len(replay_df) - 1:
            st.session_state.replay_step += 1
    with col_info:
        st.markdown(f"""
        <div style='text-align:center; font-family:Share Tech Mono,monospace; font-size:0.8rem; color:#4a9eff; padding:8px;'>
          EVENT {st.session_state.replay_step + 1} OF {len(replay_df)}
        </div>
        """, unsafe_allow_html=True)

    # Current event spotlight
    if len(replay_df) > 0:
        current = replay_df.iloc[st.session_state.replay_step]
        is_anomaly = current["flagged"]
        spot_color = "#ff1744" if is_anomaly else "#00c853"
        spot_bg = "#1a0608" if is_anomaly else "#0a1a0e"
        st.markdown(f"""
        <div style='background:{spot_bg}; border:2px solid {spot_color}; border-radius:8px;
                    padding:18px 22px; margin:12px 0;'>
          <div style='font-family:Share Tech Mono,monospace; color:{spot_color}; font-size:0.9rem; letter-spacing:0.1em; margin-bottom:10px;'>
            {"⚠ ANOMALOUS EVENT" if is_anomaly else "✓ NORMAL EVENT"} — {current['timestamp'].strftime('%H:%M:%S UTC')}
          </div>
          <div style='display:grid; grid-template-columns:1fr 1fr 1fr; gap:12px; font-size:0.82rem; color:#c9d6e3;'>
            <div><span style='color:#6b9ac4;'>SOURCE</span><br><b>{current['source']}</b></div>
            <div><span style='color:#6b9ac4;'>DOMAIN</span><br><b>{current['domain']}</b></div>
            <div><span style='color:#6b9ac4;'>DESTINATION</span><br><b>{current['destination']}</b></div>
            <div><span style='color:#6b9ac4;'>PROTOCOL</span><br><b>{current['protocol']}</b></div>
            <div><span style='color:#6b9ac4;'>PORT</span><br><b>{current['port']}</b></div>
            <div><span style='color:#6b9ac4;'>PACKET SIZE</span><br><b>{current['packet_size']} bytes</b></div>
            <div><span style='color:#6b9ac4;'>ANOMALY SCORE</span><br><b style='color:{spot_color};'>{current['anomaly_score']}</b></div>
            <div><span style='color:#6b9ac4;'>HASH</span><br><b style='font-size:0.72rem;'>{current['hash']}</b></div>
            <div><span style='color:#6b9ac4;'>RSA SIG</span><br><b>{current['rsa_signature']}</b></div>
          </div>
          {f"<div style='margin-top:12px; background:#0d0608; border-radius:4px; padding:8px 12px; font-family:Share Tech Mono,monospace; font-size:0.75rem; color:#ff9b9b;'>🧠 SHAP: {current['anomaly_reason']}</div>" if is_anomaly else ""}
        </div>
        """, unsafe_allow_html=True)

    # Timeline scroll view
    st.markdown("<div class='panel-title' style='margin-top:16px;'>▸ FULL TIMELINE</div>", unsafe_allow_html=True)
    for i, (_, row) in enumerate(replay_df.iterrows()):
        is_current = (i == st.session_state.replay_step)
        entry_class = "replay-entry anomaly-replay" if row["flagged"] else ("replay-entry active" if is_current else "replay-entry")
        marker = "▶ " if is_current else ("⚠ " if row["flagged"] else "  ")
        st.markdown(f"""
        <div class='{entry_class}'>
          {marker}[{i+1:02d}] {row['timestamp'].strftime('%H:%M:%S')} &nbsp;|&nbsp;
          {row['domain']} &nbsp;|&nbsp; {row['source']} → {row['destination']} &nbsp;|&nbsp;
          {row['protocol']} · {row['packet_size']}B &nbsp;|&nbsp; Score: {row['anomaly_score']}
        </div>
        """, unsafe_allow_html=True)

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 4: LLM CHATBOT with RAG (Part-IS)
# ══════════════════════════════════════════════════════════════════════════════
elif page == "💬 LLM Chatbot":

    st.markdown("<div class='panel-title'>💬 LLM CHATBOT — RAG ENABLED (EU PART-IS)</div>", unsafe_allow_html=True)
    st.markdown("""
    <div style='font-size:0.82rem; color:#6b9ac4; margin-bottom:12px; line-height:1.8;'>
    Ask about any network event in plain English. The chatbot uses <b>Retrieval-Augmented Generation (RAG)</b>
    grounded in EU Part-IS regulations — so answers are forensically accurate and regulation-aware.
    No cybersecurity training required.<br><br>
    <b>Try:</b> "What happened at 09:55?" &nbsp;·&nbsp; "Show anomalies" &nbsp;·&nbsp;
    "Is the chain valid?" &nbsp;·&nbsp; "What does Part-IS require?" &nbsp;·&nbsp; "Explain the SHAP results"
    </div>
    """, unsafe_allow_html=True)

    # RAG context indicator
    st.markdown("""
    <div style='background:#0a0e1a; border:1px solid #1e3a5f; border-radius:6px;
                padding:8px 14px; margin-bottom:14px; font-family:Share Tech Mono,monospace; font-size:0.72rem; color:#4a6b8a;'>
    📚 RAG CONTEXT LOADED: EU Part-IS Reg. 2023/203 &nbsp;·&nbsp; EASA Part-IS FAQ &nbsp;·&nbsp;
    BlueBox Log Chain (20 entries) &nbsp;·&nbsp; SHAP Attribution Data
    </div>
    """, unsafe_allow_html=True)

    # ── 🔌 INTEGRATION POINT B ──────────────────────────────────────────────
    # Replace mock responses below with:
    #   response = query_chatbot(user_input, df.to_dict())
    # ────────────────────────────────────────────────────────────────────────

    if "messages" not in st.session_state:
        st.session_state.messages = [
            {"role": "bot", "content": "BlueBox AI ready. RAG context loaded: EU Part-IS Reg. 2023/203 + flight SQ321 log chain (20 events, 2 anomalies). How can I help you investigate?"}
        ]

    for msg in st.session_state.messages:
        css_class = "chat-user" if msg["role"] == "user" else "chat-bot"
        prefix = "👤 ENGINEER" if msg["role"] == "user" else "🤖 BLUEBOX AI (RAG)"
        st.markdown(f"""
        <div class='{css_class}'>
          <span style='font-size:0.7rem; opacity:0.6; letter-spacing:0.1em;'>{prefix}</span><br>
          {msg['content']}
        </div>
        """, unsafe_allow_html=True)

    user_input = st.chat_input("Ask about the logs or Part-IS regulations...")
    if user_input:
        st.session_state.messages.append({"role": "user", "content": user_input})
        lower = user_input.lower()
        if "09:55" in lower or "09:5" in lower or "55" in lower:
            response = MOCK_CHAT_RESPONSES["09:55"]
        elif "anomal" in lower or "suspicious" in lower or "flag" in lower:
            response = MOCK_CHAT_RESPONSES["anomal"]
        elif "chain" in lower or "tamper" in lower or "hash" in lower or "integrity" in lower:
            response = MOCK_CHAT_RESPONSES["chain"]
        elif "maint" in lower:
            response = MOCK_CHAT_RESPONSES["maint"]
        elif "part-is" in lower or "regulation" in lower or "compliance" in lower or "eu" in lower:
            response = MOCK_CHAT_RESPONSES["part-is"]
        elif "shap" in lower or "explain" in lower or "why" in lower or "reason" in lower:
            response = MOCK_CHAT_RESPONSES["shap"]
        else:
            response = MOCK_CHAT_RESPONSES["default"]

        with st.spinner("Querying RAG + LLM..."):
            time.sleep(1.2)
        st.session_state.messages.append({"role": "bot", "content": response})
        st.rerun()

# ══════════════════════════════════════════════════════════════════════════════
# PAGE 5: ANALYSIS REPORT + COMPLIANCE ADVISORY
# ══════════════════════════════════════════════════════════════════════════════
elif page == "📄 Report":

    st.markdown("<div class='panel-title'>📄 ANALYSIS REPORT + COMPLIANCE ADVISORY</div>", unsafe_allow_html=True)

    # Compliance advisory panel
    st.markdown("""
    <div style='background:#0a1220; border:1px solid #4a9eff; border-left:4px solid #4a9eff;
                border-radius:6px; padding:16px 20px; margin-bottom:20px;'>
      <div style='font-family:Share Tech Mono,monospace; color:#4a9eff; font-size:0.8rem;
                  letter-spacing:0.1em; margin-bottom:10px;'>⚖ EU PART-IS COMPLIANCE ADVISORY</div>
      <div style='font-size:0.82rem; color:#c9d6e3; line-height:2;'>
        Under <b>EU Regulation 2023/203 (Part-IS)</b>, effective 22 February 2026, your organisation is legally required to:<br>
        <span style='color:#00e676;'>✓</span> Investigate and document cybersecurity incidents &nbsp;·&nbsp;
        <span style='color:#00e676;'>✓</span> Maintain forensic-grade evidence &nbsp;·&nbsp;
        <span style='color:#00e676;'>✓</span> Report to competent authorities<br><br>
        <b>This session:</b> 2 reportable incidents detected. BlueBox has generated cryptographically verified,
        court-admissible evidence. The report below satisfies Part-IS documentation requirements.
      </div>
    </div>
    """, unsafe_allow_html=True)

    # Report details
    rc1, rc2 = st.columns(2)
    with rc1:
        st.markdown("""
        <div style='background:#0d1a2e; border:1px solid #1e3a5f; border-radius:6px; padding:16px;
                    font-size:0.82rem; line-height:2; font-family:Share Tech Mono,monospace; color:#6b9ac4;'>
        FLIGHT &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: SQ321<br>
        AIRCRAFT &nbsp;&nbsp;&nbsp;: A350-900 (9V-SMF)<br>
        ROUTE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: SIN → LHR<br>
        DATE &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;: 2026-04-30<br>
        EVENTS LOGGED : 20<br>
        ANOMALIES &nbsp;&nbsp;: 2 (CRITICAL + HIGH)<br>
        CHAIN STATUS &nbsp;: VERIFIED<br>
        REGULATION &nbsp;&nbsp;: EU Part-IS 2023/203
        </div>
        """, unsafe_allow_html=True)
    with rc2:
        st.markdown("""
        <div style='background:#0d1a2e; border:1px solid #1e3a5f; border-radius:6px; padding:16px;
                    font-size:0.82rem; line-height:2; color:#6b9ac4;'>
        <b>Report includes:</b><br>
        ✓ Executive incident summary<br>
        ✓ Network domain breakdown (Avionics/Cabin/Maintenance)<br>
        ✓ Full verified hash chain log<br>
        ✓ SHAP feature attribution table<br>
        ✓ Anomaly event detail (×2)<br>
        ✓ Recommended engineer actions<br>
        ✓ EU Part-IS compliance statement<br>
        ✓ Chain integrity certificate
        </div>
        """, unsafe_allow_html=True)

    st.markdown("<br>", unsafe_allow_html=True)

    if st.button("⬇ GENERATE & DOWNLOAD PDF REPORT"):
        with st.spinner("Generating forensic report..."):
            time.sleep(1.5)
            try:
                from reportlab.lib.pagesizes import A4
                from reportlab.lib import colors
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
                from reportlab.lib.units import cm
                import io

                buffer = io.BytesIO()
                doc = SimpleDocTemplate(buffer, pagesize=A4,
                                        rightMargin=2*cm, leftMargin=2*cm,
                                        topMargin=2*cm, bottomMargin=2*cm)
                styles = getSampleStyleSheet()
                story = []

                title_style = ParagraphStyle('title', fontSize=18, fontName='Helvetica-Bold',
                                             textColor=colors.HexColor('#1a3a6b'), spaceAfter=4)
                sub_style = ParagraphStyle('sub', fontSize=9, fontName='Helvetica',
                                           textColor=colors.HexColor('#666666'), spaceAfter=16)
                head_style = ParagraphStyle('head', fontSize=12, fontName='Helvetica-Bold',
                                            textColor=colors.HexColor('#1a3a6b'), spaceAfter=6, spaceBefore=12)
                body_style = ParagraphStyle('body', fontSize=9, fontName='Helvetica',
                                            textColor=colors.HexColor('#333333'), spaceAfter=5, leading=14)
                advisory_style = ParagraphStyle('advisory', fontSize=9, fontName='Helvetica',
                                                textColor=colors.HexColor('#0a3a6b'),
                                                backColor=colors.HexColor('#e8f0ff'),
                                                spaceAfter=5, leading=14, leftIndent=10, rightIndent=10)

                story.append(Paragraph("BLUEBOX CYBER FORENSIC INCIDENT REPORT", title_style))
                story.append(Paragraph(
                    "EU Regulation 2023/203 (Part-IS) Compliant | Airbus Fly Your Ideas 2026 | Team 83-7438 | "
                    f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}", sub_style))

                # Flight info
                story.append(Paragraph("1. FLIGHT INFORMATION", head_style))
                flight_data = [
                    ["Flight", "SQ321", "Aircraft", "A350-900 (9V-SMF)"],
                    ["Route", "SIN → LHR", "Date", "2026-04-30"],
                    ["Session", "09:00–10:30 UTC", "Events Logged", "20"],
                    ["Anomalies", "2 (CRITICAL + HIGH)", "Chain Status", "VERIFIED"],
                    ["Regulation", "EU Part-IS 2023/203", "RSA Signatures", "ALL VALID"],
                ]
                t = Table(flight_data, colWidths=[3.5*cm, 5*cm, 3.5*cm, 5*cm])
                t.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,-1), 'Helvetica'),
                    ('FONTNAME', (0,0), (0,-1), 'Helvetica-Bold'),
                    ('FONTNAME', (2,0), (2,-1), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('ROWBACKGROUNDS', (0,0), (-1,-1), [colors.HexColor('#f0f4f8'), colors.white]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                story.append(t)
                story.append(Spacer(1, 0.3*cm))

                # Domain breakdown
                story.append(Paragraph("2. NETWORK DOMAIN SUMMARY", head_style))
                domain_summary = [["Domain", "Events", "Anomalies", "Status"]]
                for domain in ["Avionics", "Cabin", "Maintenance"]:
                    d = df[df["domain"] == domain]
                    flags = d["flagged"].sum()
                    domain_summary.append([domain, str(len(d)), str(flags),
                                           "⚠ INCIDENTS DETECTED" if flags > 0 else "CLEAN"])
                dt = Table(domain_summary, colWidths=[4*cm, 3*cm, 3*cm, 7*cm])
                dt.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a3a6b')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f5f8ff')]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                story.append(dt)
                story.append(Spacer(1, 0.3*cm))

                # Anomaly summary
                story.append(Paragraph("3. ANOMALY SUMMARY", head_style))
                story.append(Paragraph(
                    "2 anomalies were detected and cryptographically sealed in the tamper-proof hash chain. "
                    "Both involved unauthorised cross-domain access from the Maintenance domain to the Avionics network.", body_style))
                anomaly_headers = [["#", "Time", "Source", "Domain", "Dest", "Proto", "Port", "Size", "Score", "Severity"]]
                anomaly_rows = []
                for _, row in df[df["flagged"]].iterrows():
                    sev = "CRITICAL" if row["anomaly_score"] > 0.8 else "HIGH"
                    anomaly_rows.append([
                        str(row["id"]), row["timestamp"].strftime("%H:%M:%S"),
                        row["source"], row["domain"], row["destination"],
                        row["protocol"], str(row["port"]),
                        f"{row['packet_size']}B", str(row["anomaly_score"]), sev
                    ])
                at = Table(anomaly_headers + anomaly_rows,
                           colWidths=[0.6*cm,1.6*cm,1.8*cm,2.2*cm,2.2*cm,1.8*cm,1.2*cm,1.4*cm,1.4*cm,1.6*cm])
                at.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 7),
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a3a6b')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.HexColor('#fff0f0'), colors.HexColor('#ffe8e8')]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                    ('PADDING', (0,0), (-1,-1), 4),
                ]))
                story.append(at)
                story.append(Spacer(1, 0.3*cm))

                # SHAP
                story.append(Paragraph("4. SHAP FEATURE ATTRIBUTION", head_style))
                story.append(Paragraph(
                    "SHAP (SHapley Additive exPlanations) identifies which features drove each anomaly score. "
                    "Primary driver for the CRITICAL event: packet_size (0.41) — 9.4× above baseline.", body_style))
                shap_data = [["Feature", "SHAP Value", "Interpretation"]] + [
                    [k, str(v), "Primary driver" if v > 0.3 else "Contributing" if v > 0.1 else "Minor"]
                    for k, v in MOCK_SHAP.items()
                ]
                st2 = Table(shap_data, colWidths=[5*cm, 3*cm, 9*cm])
                st2.setStyle(TableStyle([
                    ('FONTNAME', (0,0), (-1,0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0,0), (-1,-1), 8),
                    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#1a3a6b')),
                    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
                    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f5f8ff')]),
                    ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor('#cccccc')),
                    ('PADDING', (0,0), (-1,-1), 5),
                ]))
                story.append(st2)
                story.append(Spacer(1, 0.3*cm))

                # Recommended actions
                story.append(Paragraph("5. RECOMMENDED ENGINEER ACTIONS", head_style))
                for rec in [
                    "1. Quarantine and forensically image maintenance laptop MAINT-05 immediately.",
                    "2. Investigate EFB-03 for unauthorised firmware or software modifications.",
                    "3. Review all SSH (port 22) and Modbus (port 502) connections from cabin/maintenance domains.",
                    "4. Submit this report to the ground SOC for deep investigation per EU Part-IS Article 12.",
                    "5. Preserve BlueBox SQLite hash chain database as primary forensic evidence.",
                    "6. Notify competent authority within the Part-IS required reporting timeframe."
                ]:
                    story.append(Paragraph(rec, body_style))
                story.append(Spacer(1, 0.3*cm))

                # Compliance advisory
                story.append(Paragraph("6. EU PART-IS COMPLIANCE ADVISORY", head_style))
                story.append(Paragraph(
                    "This report is generated in compliance with EU Regulation 2023/203 (Part-IS), "
                    "effective 22 February 2026. BlueBox provides the forensic investigation capability "
                    "legally required by Part-IS. The hash chain constitutes court-admissible evidence.", advisory_style))
                story.append(Spacer(1, 0.3*cm))

                # Chain certificate
                story.append(Paragraph("7. CHAIN INTEGRITY CERTIFICATE", head_style))
                story.append(Paragraph(
                    f"SHA-256 hash chain: VERIFIED (20/20 entries). RSA signature verification: PASSED. "
                    f"TPM key status: ACTIVE. No tampering detected. "
                    f"This document constitutes forensically sound, court-admissible cyber evidence "
                    f"per EU Part-IS Regulation 2023/203. "
                    f"Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}.", body_style))

                doc.build(story)
                buffer.seek(0)

                st.download_button(
                    label="📥 DOWNLOAD PDF REPORT",
                    data=buffer,
                    file_name=f"BlueBox_PartIS_Report_SQ321_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf",
                    mime="application/pdf"
                )
                st.success("✓ Report generated. Click above to download.")

            except Exception as e:
                st.error(f"Report generation error: {e}")