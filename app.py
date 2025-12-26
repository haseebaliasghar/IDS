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
    try:
        with open('ids_model.pkl', 'rb') as f:
            model = pickle.load(f)
        with open('scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        return model, scaler
    except FileNotFoundError:
        return None, None

model, scaler = load_resources()

if model is None:
    st.error("🚨 CRITICAL ERROR: System models (ids_model.pkl, scaler.pkl) not found. Initialize training module.")
    st.stop()

# --- SIDEBAR (Restored to the version you liked) ---
with st.sidebar:
    st.header("⚙️ System Status")
    
    # Simulating System Metrics
    st.metric("System State", "Active", delta="Running")
    st.metric("Detection Engine", "Netryx AI (RF)", delta="v2.1")
    st.metric("Model Accuracy", "99.8%", delta="+0.2%")
    
    st.divider()
    
    st.subheader("🛡️ Threat Intelligence")
    st.info("""
    **Active Monitoring For:**
    - DDoS Volumetric Attacks
    - Botnet Patterns
    - Malformed Packet Headers
    """)
    
    st.markdown("---")
    st.caption("© 2025 Netryx Security Labs")

# --- MAIN NAVIGATION ---
tab1, tab2, tab3 = st.tabs(["⚡ Live Traffic Simulator", "📂 Log Analysis (Batch)", "🧠 Netryx Intelligence"])

# ==========================================
# TAB 1: SINGLE PACKET SIMULATION
# ==========================================
with tab1:
    st.subheader("🔍 Real-Time Packet Inspector")
    st.markdown("Simulate incoming network traffic to test Netryx's detection capabilities.")
    
    st.markdown("#### 1. Configure Flow Parameters")
    c1, c2, c3 = st.columns(3)
    with c1:
        flow_duration = st.slider("Flow Duration (ms)", 0, 100000, 500, help="Total duration of the flow")
    with c2:
        fwd_pkts = st.number_input("Forward Packets", 0, 50000, 10)
    with c3:
        flow_bytes = st.number_input("Flow Bytes/s", 0, 1000000, 100)

    st.markdown("#### 2. Configure Packet Geometry")
    c4, c5 = st.columns(2)
    with c4:
        pkt_len_max = st.slider("Max Packet Length", 0, 2000, 60)
    with c5:
        pkt_len_mean = st.number_input("Mean Packet Length", 0.0, 1500.0, 50.0)

    st.divider()

    # Prediction Logic
    if st.button("🚀 SCAN TRAFFIC", type="primary"):
        with st.spinner("Netryx is analyzing traffic signature..."):
            time.sleep(0.8) # UI effect
            
            # Construct Input
            input_vector = np.zeros((1, scaler.n_features_in_))
            
            # Map inputs (Dummy mapping for demo purposes)
            input_vector[0, 1] = flow_duration
            input_vector[0, 2] = fwd_pkts
            input_vector[0, 10] = pkt_len_max
            input_vector[0, 11] = pkt_len_mean
            
            # Scale & Predict
            try:
                scaled_vec = scaler.transform(input_vector)
                prediction = model.predict(scaled_vec)
                probs = model.predict_proba(scaled_vec)
                
                confidence = np.max(probs) * 100
                
                if prediction[0] == 1: # ATTACK
                    st.error("🚨 THREAT DETECTED")
                    
                    m1, m2, m3 = st.columns(3)
                    m1.metric("Classification", "MALICIOUS (DDoS)", delta="HIGH RISK", delta_color="inverse")
                    m2.metric("Confidence", f"{confidence:.2f}%")
                    m3.metric("Action", "DROP PACKET")
                    
                    st.warning("**Netryx Recommendation:** Immediate IP Block recommended. Signature matches Volumetric DDoS.")
                    
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
        
        # Preprocessing
        df.columns = df.columns.str.strip()
        df_clean = df.select_dtypes(include=[np.number])
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_clean.fillna(0, inplace=True)
        
        if st.button("🛡️ START FORENSIC SCAN"):
            # Slice to match features
            if df_clean.shape[1] > scaler.n_features_in_:
                X_input = df_clean.iloc[:, :scaler.n_features_in_]
            else:
                X_input = df_clean
            
            # Predict
            X_scaled = scaler.transform(X_input)
            preds = model.predict(X_scaled)
            
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
    
    # Feature Importance
    if hasattr(model, 'feature_importances_'):
        st.markdown("#### Decision Weights (Feature Importance)")
        importances = model.feature_importances_
        feature_names = [f"Feature {i}" for i in range(len(importances))]
        
        importance_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
        importance_df = importance_df.sort_values(by='Importance', ascending=False).head(10)
        
        st.bar_chart(importance_df.set_index('Feature'))
        st.caption("Top 10 features influencing the AI's decision making process.")
    
    st.divider()
    
    st.markdown("#### Model Architecture Specs")
    col_a, col_b = st.columns(2)
    with col_a:
        st.json({
            "Core": "Scikit-Learn Random Forest",
            "Ensemble Size": "100 Trees",
            "Split Criterion": "Gini Impurity"
        })
    with col_b:
        st.json({
            "Dataset": "CICIDS 2017",
            "Training Scale": "5000 Samples (Lightweight)",
            "Optimization": "MinMax Scaling"
        })
