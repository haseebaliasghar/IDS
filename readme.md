🛡️ NETRYX | Intelligent Network Intrusion Detection System

<div align="center">
<img src="logo.png" alt="Netryx Logo" width="160">







<em>Next-Generation AI Security | Real-Time Threat Analysis | Forensic Log Inspection</em>
</div>

📖 Overview

Netryx is a modern, AI-powered Network Intrusion Detection System (NIDS) designed to identify malicious network traffic in real time. Unlike traditional signature-based firewalls, Netryx uses machine learning and ensemble intelligence to detect complex cyberattacks such as DDoS, Port Scans, Botnets, and Brute Force attacks.

Built with Streamlit and trained on the industry-standard CICIDS-2017 dataset, Netryx delivers high accuracy, low false positives, and an intuitive cyber-themed interface suitable for both academic and real-world security analysis.

✨ Key Features

🔍 Real-Time Traffic Inspector

Interactive live simulator for network flow analysis

Manual input of traffic parameters (duration, packets, bytes, packet size)

One-click attack presets (DDoS Flood, Port Scan, Normal Web Traffic)

Dynamic AI confidence risk meter

🧪 Multi-Model Consensus Engine

Supports Single Engine and Consensus (A/B Testing) modes

Simultaneous execution of multiple ML models:

🌲 Random Forest (Primary Engine)

📉 Logistic Regression (Baseline)

🌳 Decision Tree (Lightweight)

Threat alerts are raised only when multiple models agree, reducing false positives

📂 Forensic Batch Analysis

Upload large CSV network logs for offline inspection

Chunked processing (50,000 rows per batch) to prevent memory crashes

Automatic classification of each flow as SAFE or THREAT - Downloadable forensic investigation reports

📊 Interactive Analytics Dashboard

Session-based prediction history tracking

Visual analytics using Altair charts:

Threat vs Safe distribution

Engine usage statistics

Designed for SOC-style monitoring and reporting

🛠️ Technical Architecture

Frontend: Streamlit (Python) with custom CSS for dark cyberpunk UI

Backend: Scikit-learn, NumPy, Pandas

Dataset: CICIDS-2017 (Canadian Institute for Cybersecurity)

Preprocessing: Feature cleaning, Min-Max Scaling, dimensional alignment

Feature Count: 78 network traffic features

📈 Model Performance

Model

Accuracy

Precision

Recall

Speed

Random Forest

99.8%

99.7%

99.8%

Fast

Decision Tree

99.5%

99.4%

99.5%

Ultra-Fast

Logistic Regression

95.9%

92.1%

89.5%

Instant

🚀 Installation & Setup

Prerequisites

Python 3.8+

Virtual environment (recommended)

1️⃣ Clone the Repository

git clone [https://github.com/haseebaliasghar/netryx-ids.git](https://github.com/haseebaliasghar/netryx-ids.git)
cd netryx-ids


2️⃣ Install Dependencies

pip install -r requirements.txt


3️⃣ Place Trained Models

Ensure the following files exist in the project root:

RandomForest_model.pkl

LogisticRegression_model.pkl

DecisionTree_model.pkl

scaler.pkl

4️⃣ Run the Application

streamlit run app.py


The app will launch at: http://localhost:8501

🤝 Usage Guide

Select Engine Mode

Single Engine for speed.

Consensus Mode for maximum detection reliability.

Live Analysis

Input traffic parameters or load a preset.

Click 🚀 Analyze Traffic to receive a verdict and confidence score.

Batch Scan

Upload a CSV log file.

Run forensic scan and download a detailed threat report.

🔮 Future Roadmap

[ ] REST API integration (FastAPI)

[ ] Database persistence (SQLite / PostgreSQL)

[ ] Live packet sniffing (Scapy integration)

[ ] Docker & cloud-native deployment

[ ] SIEM integration support

👨‍💻 Author

Haseeb Ali Asghar Lead Developer & AI Researcher Semester Final Project — AI & Network Security

🔗 GitHub: https://github.com/haseebaliasghar

📄 License

This project is licensed under the MIT License. See the LICENSE file for details.

⚠️ Disclaimer: > Netryx is designed strictly for educational, research, and defensive cybersecurity purposes. It must not be used for malicious activities.
