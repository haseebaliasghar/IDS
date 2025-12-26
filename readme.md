# 🛡️ NETRYX | Intelligent Network Intrusion Detection System

[![Python](https://img.shields.io/badge/Python-3.9%2B-blue?logo=python&logoColor=white)](https://www.python.org/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.31-FF4B4B?logo=streamlit&logoColor=white)](https://streamlit.io/)
[![Scikit-Learn](https://img.shields.io/badge/ML-Scikit--Learn-orange?logo=scikit-learn&logoColor=white)](https://scikit-learn.org/)
[![License](https://img.shields.io/badge/License-MIT-green)](LICENSE)

<div align="center">
  <img src="logo.png" alt="Netryx Logo" width="160">
  <br><br>
  <em>Next-Generation AI Security | Real-Time Threat Analysis | Forensic Log Inspection</em>
</div>

---

## 📖 Overview

**Netryx** is a machine learning-based **Network Intrusion Detection System (NIDS)** designed to detect malicious network traffic in real-time. Unlike traditional signature-based firewalls, Netryx leverages **Ensemble Learning** to identify complex attack patterns, including DDoS, Botnets, and Brute Force attacks.

Built with **Streamlit** and trained on the **CICIDS-2017** dataset, Netryx achieves **99.8% accuracy** using a Random Forest architecture, offering a modern, dark-mode UI for security analysts.

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

### Model Performance
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
git clone [https://github.com/yourusername/netryx-ids.git](https://github.com/yourusername/netryx-ids.git)
cd netryx-ids
