
import streamlit as st
from detector import analyze_email

st.set_page_config(
    page_title="PhishGuard",
    page_icon="🛡️",
    layout="centered"
)

st.markdown("""
<style>
.stApp {
    background-color: #F7F6F1;
}
h1, h2, h3 {
    color: #292B28;
}
.stButton > button {
    background-color: #829985;
    color: white;
    border-radius: 8px;
    border: none;
    padding: 10px 22px;
}
</style>
""", unsafe_allow_html=True)

st.title("🛡️ PhishGuard")
st.subheader("Your email security assistant")

st.write(
    "Analyze suspicious emails and identify potentially "
    "dangerous phrases."
)

email = st.text_area(
    "Paste your email content here:",
    height=220,
    placeholder="Paste the email you want to analyze..."
)

if st.button("Analyze Email"):
    if not email.strip():
        st.warning("Please paste an email before analyzing.")
    else:
        result = analyze_email(email)

        st.divider()
        st.subheader("Analysis Results")

        st.metric("Risk Score", f"{result['score']}/100")

        if result["risk"] == "HIGH RISK":
            st.error("🔴 HIGH RISK")
        elif result["risk"] == "SUSPICIOUS":
            st.warning("🟡 SUSPICIOUS")
        else:
            st.success("🟢 LOW RISK")

        st.write("**Findings:**")
        for finding in result["findings"]:
            st.write("•", finding)

        st.caption(
            "Educational tool: A low-risk result does not "
            "guarantee that an email is safe."
        )
