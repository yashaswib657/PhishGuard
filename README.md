# 🛡️ PhishGuard

### A Python-Based Phishing Email Detection Tool

PhishGuard is an educational cybersecurity project designed to analyze email content, identify common phishing indicators, and classify potentially suspicious messages using a rule-based detection approach.

🌐 **Live Web App:** https://phishguard-nk6ddy2c3bzquf7mxbrtjw.streamlit.app/

💻 **GitHub Repository:** https://github.com/yashaswib657/PhishGuard

## ✨ Features

- Suspicious keyword and phrase detection
- Risk score calculation (0–100)
- Email threat classification: Low Risk, Suspicious, and High Risk
- Detection findings explaining identified warning signs
- Interactive dashboard with scan statistics
- Email scanner with a graphical interface
- Scan history in the web application session
- SQLite-based scan history in the desktop application

## 🖥️ Application Interfaces

PhishGuard provides two interfaces:

- **Desktop Application:** Built using Python and Tkinter.
- **Web Application:** Built using Streamlit with a dashboard, email scanner, and scan history.

## 🛠️ Technologies Used

- Python
- Streamlit
- Tkinter
- SQLite
- Git and GitHub

## 🚀 How to Run Locally

### 1. Clone the repository

```bash
git clone https://github.com/yashaswib657/PhishGuard.git
cd PhishGuard
```

### 2. Create and activate a virtual environment (optional)

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the web application

```bash
streamlit run app.py
```

### 5. Run the desktop application

```bash
python3 main.py
```

## ⚠️ Disclaimer

PhishGuard is an educational, rule-based phishing detection tool. Its keyword-based approach may produce false positives or miss malicious emails. A low-risk result does not guarantee that an email is safe. Do not use it as a substitute for professional email security solutions.

## 👩‍💻 Author

**yashaswib657**

