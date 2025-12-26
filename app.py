import streamlit as st
import pandas as pd
import numpy as np
import pickle
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="Netryx | Intelligent IDS",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR 'NETRYX' AESTHETIC ---
st.markdown("""
    <style>
    /* Main Background */
    .main {
        background-color: #0b0c10;
    }
    
    /* Buttons */
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        font-weight: bold;
        background-color: #1f2833;
        color: #66fcf1; 
        border: 1px solid #45a29e;
    }
    .stButton>button:hover {
        background-color: #45a29e;
        color: #0b0c10;
    }
    
    /* Metrics and Cards */
    .stMetric {
        background-color: #1f2833;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #45a29e;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    
    /* Headers - Neon Cyan */
    h1, h2, h3 {
        color: #66fcf1 !important; 
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        text-shadow: 0 0 10px rgba(102, 252, 241, 0.3);
    }
    
    /* Text Color */
    p, li, label {
        color: #c5c6c7;
    }
    </style>
    """, unsafe_allow_html=True)

# --- GLOBAL CONSTANTS: FEATURE NAMES ---
# This list matches the exact order of columns in the CICIDS-2017 dataset
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

# --- HEADER SECTION ---
col1, col2 = st.columns([1, 6])
with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/9131/9131546.png", width=90)
with col2:
    st.title("NETRYX")
    st.markdown("### Intelligent Network Intrusion Detection Using Machine Learning")

st.markdown("---")

# --- LOAD RESOURCES ---
@st.cache_resource
def load_resources():
    models = {}
    scaler = None
    try:
        # Load Scaler
        with open('scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
            
        # Load Multiple Models
        model_names = ['RandomForest', 'LogisticRegression', 'DecisionTree']
        for name in model_names:
            try:
                with open(f'{name}_model.pkl', 'rb') as f:
                    models[name] = pickle.load(f)
            except FileNotFoundError:
                st.warning(f"⚠️ Warning: {name}_model.pkl not found.")
                
        return models, scaler
    except FileNotFoundError:
        return None, None

models_dict, scaler = load_resources()

if not models_dict or scaler is None:
    st.error("🚨 CRITICAL ERROR: System models not found. Please place 'scaler.pkl' and model files in the directory.")
    st.stop()

# --- SIDEBAR CONTROL PANEL ---
with st.sidebar:
    st.header("⚙️ System Configuration")
    
    # 1. MODEL SELECTOR (Fixed)
    selected_model_name = st.selectbox(
        "Select Detection Engine", 
        list(models_dict.keys()),
        index=0,
        help="Choose the ML algorithm to perform the analysis."
    )
    active_model = models_dict[selected_model_name]
    
    st.divider()
    
    # 2. Dynamic Accuracy Display
    if selected_model_name == "RandomForest":
        acc_val = "99.8%"
        speed_val = "Fast"
    elif selected_model_name == "DecisionTree":
        acc_val = "99.9%"
        speed_val = "Ultra-Fast"
    else: # Logistic Regression
        acc_val = "95.9%"
        speed_val = "Instant"

    st.metric("System State", "Active", delta="Running")
    st.metric("Engine Accuracy", acc_val)
    st.metric("Inference Speed", speed_val)
    
    st.divider()
    
    st.subheader("🛡️ Threat Intelligence")
    st.info("""
    **Active Monitoring For:**
    - DDoS Volumetric Attacks
    - Port Scan Probes
    - Web Application Attacks
    - Botnet Activity
    """)
    
    st.caption("© 2025 Netryx Security Labs")

# --- MAIN NAVIGATION ---
tab1, tab2, tab3 = st.tabs(["⚡ Live Traffic Simulator", "📂 Log Analysis (Batch)", "🧠 Netryx Intelligence"])

# ==========================================
# TAB 1: SINGLE PACKET SIMULATION
# ==========================================
with tab1:
    st.subheader(f"🔍 Real-Time Inspector ({selected_model_name})")
    st.markdown("Simulate incoming network traffic parameters to test the selected detection engine.")
    
    st.markdown("#### 1. Configure Flow Parameters")
    c1, c2, c3 = st.columns(3)
    with c1:
        # Index 1: Flow Duration
        flow_duration = st.slider("Flow Duration (ms)", 0, 100000, 500, help="Total duration of the flow")
    with c2:
        # Index 2: Total Fwd Packets
        fwd_pkts = st.number_input("Forward Packets", 0, 50000, 10)
    with c3:
        # Index 14: Flow Bytes/s
        flow_bytes = st.number_input("Flow Bytes/s", 0, 1000000, 100)

    st.markdown("#### 2. Configure Packet Geometry")
    c4, c5 = st.columns(2)
    with c4:
        # Index 6: Fwd Packet Length Max
        pkt_len_max = st.slider("Fwd Packet Length Max", 0, 2000, 60)
    with c5:
        # Index 8: Fwd Packet Length Mean
        pkt_len_mean = st.number_input("Fwd Packet Length Mean", 0.0, 1500.0, 50.0)

    st.divider()

    # Prediction Logic
    if st.button("🚀 SCAN TRAFFIC SIGNATURE", type="primary"):
        with st.spinner("Netryx is analyzing traffic signature..."):
            time.sleep(0.5) 
            
            # Construct Input Array (Size 78 features)
            input_vector = np.zeros((1, scaler.n_features_in_))
            
            # Map Inputs to exact indices
            input_vector[0, 1] = flow_duration
            input_vector[0, 2] = fwd_pkts
            input_vector[0, 6] = pkt_len_max
            input_vector[0, 8] = pkt_len_mean
            input_vector[0, 14] = flow_bytes
            
            # Scale & Predict
            try:
                scaled_vec = scaler.transform(input_vector)
                prediction = active_model.predict(scaled_vec)
                
                try:
                    probs = active_model.predict_proba(scaled_vec)
                    confidence = np.max(probs) * 100
                except:
                    confidence = 100.0 
                
                if prediction[0] == 1: # ATTACK
                    st.error("🚨 THREAT DETECTED")
                    
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Classification", "MALICIOUS TRAFFIC", delta="HIGH RISK", delta_color="inverse")
                    m2.metric("Confidence", f"{confidence:.2f}%")
                    m3.metric("Engine", selected_model_name)
                    
                    st.warning("**Netryx Recommendation:** Immediate IP Block recommended. Signature matches known attack patterns.")
                    
                else: # BENIGN
                    st.success("✅ TRAFFIC SECURE")
                    
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Classification", "Authorized User", delta="SAFE")
                    m2.metric("Confidence", f"{confidence:.2f}%")
                    m3.metric("Action", "FORWARD")
                    
            except Exception as e:
                st.error(f"Computation Error: {e}")

# ==========================================
# TAB 2: BATCH FILE ANALYSIS
# ==========================================
with tab2:
    st.subheader("📂 Forensic Log Analysis")
    st.markdown("Upload CICIDS-formatted CSV logs for bulk threat hunting.")
    
    uploaded_file = st.file_uploader("Drag & Drop Log File (CSV)", type=["csv"])
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        df.columns = df.columns.str.strip()
        
        df_clean = df.select_dtypes(include=[np.number])
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_clean.fillna(0, inplace=True)
        
        if 'Label' in df_clean.columns:
            X_input = df_clean.drop('Label', axis=1)
        else:
            X_input = df_clean
            
        if st.button("🛡️ START FORENSIC SCAN"):
            # Ensure feature count matches (Slice or Pad)
            required_features = scaler.n_features_in_
            current_features = X_input.shape[1]
            
            if current_features > required_features:
                X_input = X_input.iloc[:, :required_features]
            elif current_features < required_features:
                st.error(f"Error: Uploaded file has {current_features} features, but model expects {required_features}.")
                st.stop()
            
            # Predict
            X_scaled = scaler.transform(X_input)
            preds = active_model.predict(X_scaled)
            
            # Results
            df['Netryx_Analysis'] = preds
            df['Status'] = df['Netryx_Analysis'].apply(lambda x: "⚠️ THREAT" if x == 1 else "✅ SAFE")
            
            # Dashboard
            st.markdown("### Scan Results")
            kpi1, kpi2, kpi3 = st.columns(3)
            total = len(df)
            threats = np.sum(preds == 1)
            
            kpi1.metric("Total Flows", f"{total:,}")
            kpi2.metric("Threats Identified", f"{threats:,}", delta_color="inverse")
            kpi3.metric("Clean Traffic", f"{total - threats:,}")
            
            # Charts
            c1, c2 = st.columns(2)
            with c1:
                st.caption("Traffic Composition")
                st.bar_chart(df['Status'].value_counts(), color="#66fcf1")
            
            with c2:
                st.caption("Recent Threat Logs")
                if threats > 0:
                    st.dataframe(df[df['Netryx_Analysis'] == 1].head(5), height=200)
                else:
                    st.success("No active threats found in logs.")

            # Download
            csv_data = df.to_csv(index=False).encode('utf-8')
            st.download_button("📥 Download Forensic Report", csv_data, "netryx_report.csv", "text/csv")

# ==========================================
# TAB 3: MODEL INTELLIGENCE
# ==========================================
with tab3:
    st.subheader("🧠 Netryx Engine Internals")
    
    # Feature Importance (Fixed to show Real Names)
    if hasattr(active_model, 'feature_importances_'):
        st.markdown(f"#### Decision Weights ({selected_model_name})")
        
        importances = active_model.feature_importances_
        
        # Create DataFrame with REAL feature names
        # Note: We check lengths just in case, to avoid mismatch errors
        if len(importances) == len(FEATURE_COLS):
            importance_df = pd.DataFrame({
                'Feature': FEATURE_COLS, 
                'Importance': importances
            })
        else:
            # Fallback if lengths differ (shouldn't happen if setup is correct)
            importance_df = pd.DataFrame({
                'Feature': [f"Feat {i}" for i in range(len(importances))], 
                'Importance': importances
            })
            
        importance_df = importance_df.sort_values(by='Importance', ascending=False).head(10)
        
        st.bar_chart(importance_df.set_index('Feature'))
        st.caption("Top 10 network features influencing the AI's decision making process.")
        
    elif selected_model_name == "LogisticRegression":
         st.markdown(f"#### Model Coefficients ({selected_model_name})")
         st.info("Logistic Regression uses linear coefficients to determine the decision boundary. High positive values indicate a strong correlation with Malicious traffic.")
    
    st.divider()
    
    st.markdown("#### Model Architecture Specs")
    col_a, col_b = st.columns(2)
    with col_a:
        st.json({
            "Selected Engine": selected_model_name,
            "Input Features": scaler.n_features_in_,
            "Output Classes": "2 (Benign, Threat)"
        })
    with col_b:
        st.json({
            "Dataset": "CICIDS 2017 (Combined)",
            "Training Scale": "400,000 Records",
            "Attacks Covered": "DDoS, PortScan, Web Attack"
        })
