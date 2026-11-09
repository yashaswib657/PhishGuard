
import streamlit as st
from datetime import datetime
from html import escape
from detector import analyze_email

# ---------------- PAGE CONFIG ----------------

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ---------------- SESSION DATA ----------------

if "history" not in st.session_state:
    st.session_state.history = []

if "last_result" not in st.session_state:
    st.session_state.last_result = None

# ---------------- COLORS ----------------

BG = "#F7F6F1"
WHITE = "#FFFFFF"
DARK = "#292B28"
MUTED = "#85877F"
GREEN = "#829985"
GREEN_DARK = "#526D59"
PALE_GREEN = "#E8EEE7"
YELLOW = "#F4EACB"
RED = "#B96860"
BORDER = "#EAE9E2"

# ---------------- CUSTOM CSS ----------------

st.markdown("""
<style>
    .stApp {
        background: #F7F6F1;
        color: #292B28;
    }

    [data-testid="stSidebar"] {
        background: #FFFFFF;
        border-right: 1px solid #EAE9E2;
    }

    [data-testid="stSidebar"] h1 {
        font-family: Georgia, serif;
        color: #292B28;
    }

    h1, h2, h3 {
        font-family: Georgia, serif !important;
        color: #292B28 !important;
    }

    p, label, span {
        color: #292B28;
    }

    .hero {
        background: #FFFFFF;
        border: 1px solid #EAE9E2;
        border-radius: 18px;
        padding: 32px;
        margin: 12px 0 24px 0;
    }

    .hero-title {
        font-family: Georgia, serif;
        font-size: 35px;
        font-weight: 600;
        color: #292B28;
        margin-bottom: 8px;
    }

    .hero-subtitle {
        color: #85877F;
        font-size: 15px;
    }

    .metric-card {
        background: #FFFFFF;
        border: 1px solid #EAE9E2;
        border-radius: 15px;
        padding: 22px;
        min-height: 125px;
    }

    .metric-label {
        color: #85877F;
        font-size: 13px;
        margin-bottom: 12px;
    }

    .metric-value {
        font-family: Georgia, serif;
        font-size: 32px;
        font-weight: bold;
        color: #292B28;
    }

    .section-label {
        color: #85877F;
        font-size: 12px;
        letter-spacing: 2px;
        font-weight: 600;
        margin-bottom: 10px;
    }

    .result-card {
        background: #FFFFFF;
        border: 1px solid #EAE9E2;
        border-radius: 16px;
        padding: 26px;
        margin-top: 20px;
    }

    .risk-title {
        font-family: Georgia, serif;
        font-size: 27px;
        font-weight: bold;
        margin-bottom: 8px;
    }

    .risk-score {
        font-size: 42px;
        font-family: Georgia, serif;
        font-weight: bold;
    }

    .finding {
        background: #F7F6F1;
        border-radius: 9px;
        padding: 12px 15px;
        margin-top: 9px;
        color: #292B28;
        font-size: 14px;
    }

    .history-item {
        background: #FFFFFF;
        border: 1px solid #EAE9E2;
        border-radius: 12px;
        padding: 17px;
        margin-bottom: 12px;
    }

    div.stButton > button {
        background: #829985;
        color: white;
        border: none;
        border-radius: 9px;
        padding: 10px 22px;
        font-weight: 600;
    }

    div.stButton > button:hover {
        background: #526D59;
        color: white;
        border: none;
    }

    div[data-testid="stTextArea"] textarea {
        background: #FFFFFF;
        border: 1px solid #EAE9E2;
        border-radius: 12px;
        color: #292B28;
    }

    div[data-testid="stTextArea"] textarea:focus {
        border-color: #829985;
        box-shadow: 0 0 0 1px #829985;
    }

    #MainMenu {
        visibility: hidden;
    }

    footer {
        visibility: hidden;
    }
</style>
""", unsafe_allow_html=True)


# ---------------- SIDEBAR ----------------

with st.sidebar:
    st.markdown("# 🛡️ PhishGuard")
    st.caption("EMAIL SECURITY WORKSPACE")
    st.divider()

    page = st.radio(
        "NAVIGATION",
        ["Dashboard", "Email Scanner", "Scan History"],
        label_visibility="visible"
    )

    st.divider()

    st.markdown("### Your security matters")
    st.caption(
        "Analyze suspicious email content and identify "
        "potential warning signs."
    )

    st.markdown("---")
    st.caption("PhishGuard · Educational Project")


# ---------------- HELPER FUNCTIONS ----------------

def metric_card(label, value, description):
    st.markdown(f"""
    <div class="metric-card">
        <div class="metric-label">{label}</div>
        <div class="metric-value">{value}</div>
        <div style="color:#85877F;font-size:12px;margin-top:5px;">
            {description}
        </div>
    </div>
    """, unsafe_allow_html=True)


def show_result(result):
    risk = result["risk"]
    score = result["score"]

    if risk == "HIGH RISK":
        color = RED
        background = "#F8E9E7"
        icon = "🔴"

    elif risk == "SUSPICIOUS":
        color = "#A27A28"
        background = YELLOW
        icon = "🟡"

    else:
        color = GREEN_DARK
        background = PALE_GREEN
        icon = "🟢"

    findings_html = ""

    for finding in result["findings"]:
        findings_html += (
            f'<div class="finding">• {escape(finding)}</div>'
        )

    st.markdown(f"""
    <div class="result-card">
        <div class="section-label">ANALYSIS COMPLETE</div>
        <div style="background:{background};
                    display:inline-block;
                    padding:8px 14px;
                    border-radius:8px;
                    color:{color};
                    font-weight:700;">
            {icon} {risk}
        </div>
        <div style="margin-top:22px;color:#85877F;font-size:13px;">
            RISK SCORE
        </div>
        <div class="risk-score" style="color:{color};">
            {score}<span style="font-size:17px;color:#85877F;"> / 100</span>
        </div>
        <div style="margin-top:22px;font-weight:600;">
            Detection findings
        </div>
        {findings_html}
    </div>
    """, unsafe_allow_html=True)

    st.caption(
        "Important: This is a basic keyword-based educational tool. "
        "A low-risk result does not guarantee that an email is safe."
    )


# ---------------- DASHBOARD ----------------

if page == "Dashboard":

    st.markdown("""
    <div class="hero">
        <div class="section-label">YOUR SECURITY WORKSPACE</div>
        <div class="hero-title">Welcome to PhishGuard.</div>
        <div class="hero-subtitle">
            Stay alert. Identify suspicious emails. Protect your inbox.
        </div>
    </div>
    """, unsafe_allow_html=True)

    history = st.session_state.history

    total = len(history)
    high = sum(1 for item in history if item["risk"] == "HIGH RISK")
    suspicious = sum(
        1 for item in history if item["risk"] == "SUSPICIOUS"
    )
    low = sum(1 for item in history if item["risk"] == "LOW RISK")

    st.markdown("### Overview")
    st.caption("A quick look at your email security activity.")

    c1, c2, c3, c4 = st.columns(4)

    with c1:
        metric_card("TOTAL SCANS", total, "Emails analyzed")

    with c2:
        metric_card("HIGH RISK", high, "Potential warning signs")

    with c3:
        metric_card("SUSPICIOUS", suspicious, "Needs attention")

    with c4:
        metric_card("LOW RISK", low, "Fewer detected warning signs")

    st.write("")

    left, right = st.columns([1.4, 1])

    with left:
        st.markdown("### Start protecting your inbox")

        st.markdown("""
        <div class="hero">
            <div style="font-size:25px;">✉️</div>
            <h3>Analyze an email</h3>
            <p style="color:#85877F;">
                Paste suspicious email content and let PhishGuard
                check for potentially dangerous phrases.
            </p>
        </div>
        """, unsafe_allow_html=True)

        if st.button("Open Email Scanner →"):
            st.session_state.navigate_to_scanner = True
            st.rerun()

    with right:
        st.markdown("### Latest activity")

        if history:
            latest = history[-1]

            st.markdown(f"""
            <div class="history-item">
                <div class="section-label">LATEST SCAN</div>
                <h3>{escape(latest["risk"])}</h3>
                <p style="color:#85877F;">
                    Risk score: {latest["score"]}/100
                </p>
                <p style="color:#85877F;font-size:12px;">
                    {escape(latest["time"])}
                </p>
            </div>
            """, unsafe_allow_html=True)
        else:
            st.info("Your scan activity will appear here.")

    if st.session_state.get("navigate_to_scanner"):
        st.session_state.navigate_to_scanner = False
        st.info("Select Email Scanner from the sidebar to begin.")


# ---------------- EMAIL SCANNER ----------------

elif page == "Email Scanner":

    st.markdown("""
    <div class="hero">
        <div class="section-label">EMAIL ANALYSIS</div>
        <div class="hero-title">Scan your email.</div>
        <div class="hero-subtitle">
            Check suspicious messages for common phishing warning signs.
        </div>
    </div>
    """, unsafe_allow_html=True)

    st.markdown("### Email content")

    email = st.text_area(
        "Paste the email you want to analyze:",
        height=230,
        placeholder=(
            "Dear customer,\n\n"
            "Your account has been suspended. "
            "Please verify your details immediately..."
        ),
        label_visibility="collapsed"
    )

    st.caption("Tip: Include the subject and message body for analysis.")

    if st.button("🛡️ Analyze Email", use_container_width=True):

        if not email.strip():
            st.warning("Please paste an email before analyzing.")

        else:
            result = analyze_email(email)

            record = {
                "email": email,
                "score": result["score"],
                "risk": result["risk"],
                "findings": result["findings"],
                "time": datetime.now().strftime("%d %b %Y, %I:%M %p")
            }

            st.session_state.history.append(record)
            st.session_state.last_result = result

    if st.session_state.last_result:
        st.divider()
        st.markdown("### Your analysis results")
        show_result(st.session_state.last_result)


# ---------------- SCAN HISTORY ----------------

elif page == "Scan History":

    st.markdown("""
    <div class="hero">
        <div class="section-label">ACTIVITY LOG</div>
        <div class="hero-title">Scan history.</div>
        <div class="hero-subtitle">
            Review your email analysis activity.
        </div>
    </div>
    """, unsafe_allow_html=True)

    history = st.session_state.history

    if not history:
        st.info("No scans yet. Analyze an email to see your history.")

    else:
        st.markdown(f"**{len(history)} scans recorded in this session**")

        for index, item in enumerate(reversed(history), start=1):

            with st.expander(
                f'{item["risk"]} · Score {item["score"]}/100 · {item["time"]}'
            ):
                st.markdown("**Email content:**")
                st.text(item["email"])

                st.markdown("**Findings:**")
                for finding in item["findings"]:
                    st.write("•", finding)

        if st.button("Clear session history"):
            st.session_state.history = []
            st.session_state.last_result = None
            st.rerun()


# ---------------- FOOTER ----------------

st.divider()

st.markdown(
    """
    <div style="text-align:center;color:#85877F;font-size:12px;padding:10px;">
        PHISHGUARD · EMAIL SECURITY ASSISTANT<br>
        Built as an educational cybersecurity project.
    </div>
    """,
    unsafe_allow_html=True
)
