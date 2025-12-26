import streamlit as st
import pandas as pd
import numpy as np
import pickle
import time
from datetime import datetime
import altair as alt # For advanced charts

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Netryx | Intelligent IDS",
    page_icon="favicon.png", # USES YOUR UPLOADED FAVICON
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CONSTANTS & CONFIG ---
BENIGN_LABEL = 0
THREAT_LABEL = 1
MODEL_VERSION = "v4.1.1-Ultimate"
BUILD_DATE = "2025-12-26"

# Validation Constraints (To prevent crashes)
CONSTRAINTS = {
    'flow_duration': (0, 120000000),
    'fwd_pkts': (0, 200000),
    'flow_bytes': (0, 1000000000),
    'pkt_len_max': (0, 65535),
    'pkt_len_mean': (0.0, 65535.0)
}

# Full List of Feature Names (CICIDS 2017)
FEATURE_COLS = [
    'Destination Port', 'Flow Duration', 'Total Fwd Packets', 'Total Backward Packets', 
    'Total Length of Fwd Packets', 'Total Length of Bwd Packets', 'Fwd Packet Length Max', 
    'Fwd Packet Length Min', 'Fwd Packet Length Mean', 'Fwd Packet Length Std', 
    'Bwd Packet Length Max', 'Bwd Packet Length Min', 'Bwd Packet Length Mean', 
    'Bwd Packet Length Std', 'Flow Bytes/s', 'Flow Packets/s', 'Flow IAT Mean', 
    'Flow IAT Std', 'Flow IAT Max', 'Flow IAT Min', 'Fwd IAT Total', 'Fwd IAT Mean', 
    'Fwd IAT Std', 'Fwd IAT Max', 'Fwd IAT Min', 'Bwd IAT Total', 'Bwd IAT Mean', 
    'Bwd IAT Std', 'Bwd IAT Max', 'Bwd IAT Min', 'Fwd PSH Flags', 'Bwd PSH Flags', 
    'Fwd URG Flags', 'Bwd URG Flags', 'Fwd Header Length', 'Bwd Header Length', 
    'Fwd Packets/s', 'Bwd Packets/s', 'Min Packet Length', 'Max Packet Length', 
    'Packet Length Mean', 'Packet Length Std', 'Packet Length Variance', 'FIN Flag Count', 
    'SYN Flag Count', 'RST Flag Count', 'PSH Flag Count', 'ACK Flag Count', 'URG Flag Count', 
    'CWE Flag Count', 'ECE Flag Count', 'Down/Up Ratio', 'Average Packet Size', 
    'Avg Fwd Segment Size', 'Avg Bwd Segment Size', 'Fwd Header Length.1', 
    'Fwd Avg Bytes/Bulk', 'Fwd Avg Packets/Bulk', 'Fwd Avg Bulk Rate', 'Bwd Avg Bytes/Bulk', 
    'Bwd Avg Packets/Bulk', 'Bwd Avg Bulk Rate', 'Subflow Fwd Packets', 'Subflow Fwd Bytes', 
    'Subflow Bwd Packets', 'Subflow Bwd Bytes', 'Init_Win_bytes_forward', 
    'Init_Win_bytes_backward', 'act_data_pkt_fwd', 'min_seg_size_forward', 'Active Mean', 
    'Active Std', 'Active Max', 'Active Min', 'Idle Mean', 'Idle Std', 'Idle Max', 'Idle Min'
]

# --- SESSION STATE (Database Simulation) ---
if 'history' not in st.session_state:
    st.session_state.history = []

# --- CUSTOM CSS ---
st.markdown("""
    <style>
    /* Main Background */
    .main { background-color: #0b0c10; }
    
    /* Buttons */
    .stButton>button {
        width: 100%; border-radius: 5px; font-weight: bold;
        background-color: #1f2833; color: #66fcf1; border: 1px solid #45a29e;
    }
    .stButton>button:hover { background-color: #45a29e; color: #0b0c10; }
    
    /* Metrics */
    .stMetric { background-color: #1f2833; padding: 10px; border-radius: 8px; border: 1px solid #45a29e; }
    
    /* Headers */
    h1, h2, h3 { color: #66fcf1 !important; font-family: 'Segoe UI', sans-serif; text-shadow: 0 0 10px rgba(102, 252, 241, 0.3); }
    
    /* Risk Meter Bar */
    .risk-bar-container { width: 100%; background-color: #1f2833; border-radius: 10px; padding: 3px; }
    .risk-bar-fill { height: 10px; border-radius: 7px; transition: width 0.5s ease-in-out; }
    
    /* SIDEBAR WIDTH FIX */
    section[data-testid="stSidebar"] {
        width: 350px !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HELPER FUNCTIONS ---

def validate_inputs(inputs):
    """Sanitize inputs to prevent model crashes"""
    errors = []
    for key, (min_val, max_val) in CONSTRAINTS.items():
        if key in inputs:
            val = inputs[key]
            if val < min_val or val > max_val:
                errors.append(f"{key} must be between {min_val} and {max_val}")
    return errors

def update_history(model, result, confidence):
    st.session_state.history.append({
        "Timestamp": datetime.now().strftime("%H:%M:%S"),
        "Model": model,
        "Result": result,
        "Confidence": confidence
    })

def render_risk_meter(confidence, is_threat):
    if not is_threat:
        color = "#00ff41" # Green
    elif confidence > 80:
        color = "#ff0000" # Red
    else:
        color = "#ffbf00" # Orange
        
    st.markdown(f"""
    <div style="margin: 5px 0;">
        <small style="color: #c5c6c7;">Threat Probability Index</small>
        <div class="risk-bar-container">
            <div class="risk-bar-fill" style="width: {confidence}%; background-color: {color};"></div>
        </div>
    </div>
    """, unsafe_allow_html=True)

# --- LOAD RESOURCES ---
@st.cache_resource
def load_resources():
    models = {}
    scaler = None
    try:
        with open('scaler.pkl', 'rb') as f: scaler = pickle.load(f)
        for name in ['RandomForest', 'LogisticRegression', 'DecisionTree']:
            try:
                with open(f'{name}_model.pkl', 'rb') as f: models[name] = pickle.load(f)
            except: pass
        return models, scaler
    except: return None, None

models_dict, scaler = load_resources()

if not models_dict or scaler is None:
    st.error("🚨 CRITICAL: Models not found. Please upload .pkl files.")
    st.stop()

# --- SIDEBAR CONFIGURATION ---
with st.sidebar:
    st.header("⚙️ Configuration")
    
    mode = st.radio("Operation Mode", ["Single Engine", "Consensus (A/B Test)"])
    
    selected_model_name = "RandomForest" 
    active_model = None
    
    if mode == "Single Engine":
        selected_model_name = st.selectbox("Detection Engine", list(models_dict.keys()))
        active_model = models_dict[selected_model_name]
    
    st.divider()
    
    # Metadata Display (Stacked)
    st.metric("Version", MODEL_VERSION)
    st.metric("Build", "Stable")
    
    if mode == "Single Engine":
        acc = "99.8%" if "Forest" in selected_model_name else "95.9%"
        st.metric("Model Accuracy", acc)
    else:
        st.info("⚠️ Running all available models simultaneously for cross-validation.")

    st.divider()
    st.caption("©haseebaliasghar | Netryx Labs")

# --- HEADER SECTION (SIDE-BY-SIDE FIXED) ---
st.markdown("<br>", unsafe_allow_html=True) # Spacer

# Ratio 1:7 ensures the text is close to the logo, not floating far away
col1, col2 = st.columns([1, 7]) 

with col1:
    try:
        # Increased width slightly for impact
        st.image("logo.png", width=140) 
    except Exception:
        st.warning("⚠️ logo.png not found")

with col2:
    # We use padding-top to align the text vertically with the center of the logo
    st.markdown("""
        <div style="padding-top: 10px; text-align: left;">
            <h1 style='color: #66fcf1; margin-bottom: -10px; margin-top: 0px;'>NETRYX</h1>
            <h3 style='color: #c5c6c7; font-weight: normal; font-size: 20px; margin-top: 5px;'>
                Intelligent Network Intrusion Detection System
            </h3>
        </div>
        <hr style='border-color: #45a29e; margin-top: 20px; margin-bottom: 20px;'>
    """, unsafe_allow_html=True)

# --- MAIN TABS ---
tab1, tab2, tab3, tab4 = st.tabs(["⚡ Live Simulator", "📂 Batch Scan", "📊 Analytics Dashboard", "🧠 Engine Internals"])

# ==========================================
# TAB 1: LIVE SIMULATOR
# ==========================================
with tab1:
    st.subheader("🔍 Real-Time Inspector")
    
    presets = {
        "Manual Input": None,
        "Normal Web Traffic": {"dur": 60000, "pkts": 12, "len_max": 1200, "len_mean": 450, "bytes": 500},
        "DDoS Attack (Flood)": {"dur": 150, "pkts": 5000, "len_max": 0, "len_mean": 0, "bytes": 100000},
        "Port Scan (Probe)": {"dur": 50, "pkts": 2, "len_max": 0, "len_mean": 0, "bytes": 40}
    }
    
    selected_preset = st.selectbox("📝 Load Traffic Profile", list(presets.keys()))
    defaults = presets[selected_preset] if selected_preset != "Manual Input" else {"dur": 500, "pkts": 10, "len_max": 60, "len_mean": 50.0, "bytes": 100}
    
    st.divider()
    
    c1, c2, c3 = st.columns(3)
    flow_duration = c1.number_input("Flow Duration (ms)", 0, 120000000, defaults["dur"])
    fwd_pkts = c2.number_input("Total Fwd Packets", 0, 200000, defaults["pkts"])
    flow_bytes = c3.number_input("Flow Bytes/s", 0, 1000000000, defaults["bytes"])

    c4, c5 = st.columns(2)
    pkt_len_max = c4.number_input("Max Packet Length", 0, 65535, defaults["len_max"])
    pkt_len_mean = c5.number_input("Mean Packet Length", 0.0, 65535.0, float(defaults["len_mean"]))

    input_data = {'flow_duration': flow_duration, 'fwd_pkts': fwd_pkts, 'pkt_len_max': pkt_len_max}
    validation_errors = validate_inputs(input_data)
    
    if validation_errors:
        st.error(f"❌ Input Error: {', '.join(validation_errors)}")
        st.stop()

    if st.button("🚀 ANALYZE TRAFFIC", type="primary"):
        with st.spinner("Processing telemetry..."):
            time.sleep(0.5)
            
            vec = np.zeros((1, scaler.n_features_in_))
            vec[0, 1] = flow_duration
            vec[0, 2] = fwd_pkts
            vec[0, 6] = pkt_len_max
            vec[0, 8] = pkt_len_mean
            vec[0, 14] = flow_bytes
            scaled_vec = scaler.transform(vec)
            
            if mode == "Consensus (A/B Test)":
                results = []
                for name, model in models_dict.items():
                    pred = model.predict(scaled_vec)[0]
                    try: conf = np.max(model.predict_proba(scaled_vec)) * 100
                    except: conf = 100.0
                    status = "⚠️ THREAT" if pred == THREAT_LABEL else "✅ SAFE"
                    results.append({"Engine": name, "Verdict": status, "Confidence": f"{conf:.1f}%"})
                    update_history(name, status, conf)
                
                st.table(pd.DataFrame(results))
                threat_count = sum(1 for r in results if r["Verdict"] == "⚠️ THREAT")
                if threat_count >= 2:
                    st.error("🚨 CONSENSUS REACHED: MALICIOUS TRAFFIC DETECTED")
                else:
                    st.success("✅ CONSENSUS REACHED: TRAFFIC BENIGN")

            else:
                pred = active_model.predict(scaled_vec)[0]
                try: conf = np.max(active_model.predict_proba(scaled_vec)) * 100
                except: conf = 100.0
                
                is_threat = (pred == THREAT_LABEL)
                result_str = "⚠️ THREAT" if is_threat else "✅ SAFE"
                
                if is_threat:
                    st.error("🚨 THREAT DETECTED")
                    render_risk_meter(conf, True)
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Result", "MALICIOUS", delta="CRITICAL", delta_color="inverse")
                    m2.metric("Confidence", f"{conf:.2f}%")
                    m3.metric("Engine", selected_model_name)
                    st.warning("Recommendation: Isolate Source IP.")
                else:
                    st.success("✅ TRAFFIC SECURE")
                    render_risk_meter(conf, False)
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Result", "SAFE", delta="OK")
                    m2.metric("Confidence", f"{conf:.2f}%")
                    m3.metric("Action", "ALLOW")
                
                update_history(selected_model_name, result_str, conf)

# ==========================================
# TAB 2: BATCH SCAN
# ==========================================
with tab2:
    st.subheader("📂 Forensic Log Analysis")
    uploaded_file = st.file_uploader("Upload CSV Log", type=["csv"])
    
    if uploaded_file and st.button("🛡️ START SCAN"):
        try:
            chunks = pd.read_csv(uploaded_file, chunksize=50000)
            results = []
            bar = st.progress(0)
            
            for i, chunk in enumerate(chunks):
                chunk.columns = chunk.columns.str.strip()
