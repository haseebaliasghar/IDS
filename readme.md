# 🛡️ NETRYX | Intelligent Network Intrusion Detection System

<div align="center">
  <img src="logo.png" alt="Netryx Logo" width="160">
  <br><br>
  <em>Next-Generation AI Security | Real-Time Threat Analysis | Forensic Log Inspection</em>
</div>

---

## 📖 Overview

**Netryx** is a machine learning-based **Network Intrusion Detection System (NIDS)** designed to detect malicious network traffic in real-time. Unlike traditional signature-based firewalls, Netryx leverages **Ensemble Learning** to identify complex attack patterns, including DDoS, Botnets, and Brute Force attacks.

Built with **Streamlit** and trained on the **CICIDS-2017** dataset, Netryx achieves **99.8% accuracy** using a Random Forest architecture, offering a modern, dark-mode UI for security analysts.

---

## ✨ Key Features

### 🔍 1. Real-Time Traffic Inspector
- **Live Simulator:** Manually input flow parameters (Duration, Packet Size, Bytes/s) to test specific traffic signatures.
- **Traffic Presets:** One-click loading of attack profiles (e.g., *DDoS Flood*, *Port Scan*, *Normal Web Surfing*) for instant demos.
- **Visual Risk Meter:** Dynamic confidence bars visualize the AI's certainty level.

### 🧪 2. Multi-Model Consensus Engine
- **A/B Testing Mode:** Run three independent AI models simultaneously:
  - 🌲 **Random Forest** (Primary Engine)
  - 📉 **Logistic Regression** (Baseline)
  - 🌳 **Decision Tree** (Lightweight)
- **Consensus Logic:** The system triggers a critical alert only if multiple models agree on a threat verdict, reducing false positives.

### 📂 3. Forensic Batch Analysis
- **Large-Scale Log Scanning:** Upload massive CSV logs (GBs in size).
- **Chunked Processing:** Smart memory management prevents crashes by analyzing data in 50k-row chunks.
- **Automated Reporting:** Generates downloadable CSV audit reports flagging all malicious flows.

### 📊 4. Interactive Analytics
- **Session History:** Tracks every scan performed during the session.
- **Data Visualization:** Altair charts display Threat Distribution and Engine Performance metrics.

---

## 🛠️ Technical Architecture

* **Frontend:** Streamlit (Python) with custom CSS/HTML injection for "Cyberpunk" UI.
* **Backend:** Scikit-learn (Machine Learning), Pandas (Data Processing).
* **Dataset:** [CICIDS-2017](https://www.unb.ca/cic/datasets/ids-2017.html) (Canadian Institute for Cybersecurity).
* **Preprocessing:** MinMax Scaling, Label Encoding, Feature Selection (78 features).

### 📈 Model Performance
| Model | Accuracy | Precision | Recall | Speed |
| :--- | :--- | :--- | :--- | :--- |
| **Random Forest** | **99.8%** | 99.7% | 99.8% | Fast |
| Decision Tree | 99.5% | 99.4% | 99.5% | Ultra-Fast |
| Logistic Regression | 95.9% | 92.1% | 89.5% | Instant |

---

## 🚀 Installation & Setup

### Prerequisites
* Python 3.8 or higher.
* Virtual Environment (Recommended).

### 1. Clone the Repository
```bash
git clone https://github.com/haseebaliasghar/netryx-ids.git
cd netryx-ids
```

### 2. Install Dependencies
```bash
pip install -r requirements.txt
```

### 3. Place Model Files
Ensure the following `.pkl` files (trained models) are in the root directory:
- `RandomForest_model.pkl`
- `LogisticRegression_model.pkl`
- `DecisionTree_model.pkl`
- `scaler.pkl`

### 4. Run the Application
```bash
streamlit run app.py
```
The application will launch in your browser at: `http://localhost:8501`

---

## 📸 Screenshots
<div align="center">
  <!-- Screenshot 1: Dashboard -->
  <img src="https://github.com/haseebaliasghar/IDS/blob/main/screenshots/dashboard.png" alt="Dashboard" width="800">
  <p><em>Real-Time Traffic Inspector Dashboard</em></p>
  <br>

  <!-- Screenshot 2: Batch Scan -->
  <img src="https://github.com/haseebaliasghar/IDS/blob/main/screenshots/batch_scan.png" alt="Batch Scan" width="800">
  <p><em>Forensic Batch Scan Report</em></p>
  <br>

  <!-- Screenshot 3: Consensus -->
  <img src="https://github.com/haseebaliasghar/IDS/blob/main/screenshots/Consensus_scan.png" alt="Consensus Mode" width="800">
  <p><em>Multi-Model Consensus Mode</em></p>
</div>

---

## 🤝 Usage Guide

1. **Select Engine:** Choose "Single Engine" for speed or "Consensus" for maximum security via the sidebar.
2. **Input Data:** Use the sliders/inputs to define a network packet, or select a Preset (like "DDoS Attack") from the dropdown menu.
3. **Analyze:** Click **🚀 Analyze Traffic**. The system will output a verdict (Safe/Threat) with a confidence score.
4. **Batch Scan:** Switch to the "Batch Scan" tab, upload a CSV log file (e.g., `test_bad.csv`), and click "Start Scan" to generate a forensic report.

---

## 🔮 Future Roadmap

- [ ] **API Integration:** FastAPI endpoint for remote scanning.
- [ ] **Database Support:** Persistent storage (SQLite/PostgreSQL) for long-term history.
- [ ] **Live Sniffing:** Integration with Scapy to capture real packets from the network interface.
- [ ] **Dockerization:** Full container support for cloud deployment.

---

## 👨‍💻 Author

**Haseeb Ali Asghar**
* **Role:** Lead Developer & AI Researcher
* **Concept:** Semester Final Project (Network Security & AI)
* **GitHub:** [github.com/haseebaliasghar](https://github.com/haseebaliasghar)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

> **⚠️ Disclaimer:**
> This tool is designed for educational and defensive purposes only. It demonstrates the application of machine learning in network security.
