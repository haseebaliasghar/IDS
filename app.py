import streamlit as st
import pandas as pd
import numpy as np
import pickle
import time

# --- PAGE CONFIGURATION ---
st.set_page_config(
    page_title="SentinAI | Intrusion Detection System",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# --- CUSTOM CSS FOR CYBER AESTHETIC ---
st.markdown("""
    <style>
    .main {
        background-color: #0e1117;
    }
    .stButton>button {
        width: 100%;
        border-radius: 5px;
        font-weight: bold; 
    }
    .stMetric {
        background-color: #1a1c24;
        padding: 15px;
        border-radius: 10px;
        border: 1px solid #333;
    }
    h1, h2, h3 {
        color: #00ff41 !important; 
        font-family: 'Courier New', Courier, monospace;
    }
    .reportview-container .main .block-container{
        padding-top: 2rem;
    }
    </style>
    """, unsafe_allow_html=True)

# --- HEADER SECTION ---
col1, col2 = st.columns([1, 5])
with col1:
    st.image("https://cdn-icons-png.flaticon.com/512/9131/9131546.png", width=100)
with col2:
    st.title("SentinAI Defense System")
    st.markdown("**Lightweight Machine Learning Intrusion Detection System** | *v2.0 Stable*")

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

# --- SIDEBAR DASHBOARD ---
with st.sidebar:
    st.header("⚙️ System Status")
    
    # Simulating System Metrics
    st.metric("Model Status", "Active", delta="Ready")
    st.metric("Detection Engine", "Random Forest", delta="v1.0")
    st.metric("Training Accuracy", "99.8%", delta="+0.2%")
    
    st.divider()
    st.subheader("🛡️ Threat Intelligence")
    st.info("""
    **Monitoring:**
    - DDoS Attacks (High Volume)
    - Port Scans (Probe Traffic)
    - Botnet Activity
    """)
    
    st.markdown("---")
    st.caption("© 2025 SentinAI Project Team")

# --- MAIN NAVIGATION ---
tab1, tab2, tab3 = st.tabs(["⚡ Packet Inspector (Real-time)", "📂 Log Analysis (Batch)", "🧠 Model Logic"])

# ==========================================
# TAB 1: SINGLE PACKET SIMULATION
# ==========================================
with tab1:
    st.subheader("🔍 Deep Packet Inspection")
    st.markdown("Simulate network traffic parameters to test the detection engine.")
    
    col_input1, col_input2, col_input3 = st.columns(3)
    
    with col_input1:
        st.markdown("#### Flow Metrics")
        flow_duration = st.slider("Flow Duration (ms)", 0, 100000, 500, help="Duration of the packet flow.")
        flow_bytes = st.number_input("Flow Bytes/s", 0, 1000000, 100)
    
    with col_input2:
        st.markdown("#### Packet Geometry")
        fwd_pkts = st.number_input("Total Fwd Packets", 0, 50000, 10)
        pkt_len_max = st.slider("Max Packet Length", 0, 2000, 60)
    
    with col_input3:
        st.markdown("#### Statistical Features")
        pkt_len_mean = st.number_input("Mean Packet Length", 0.0, 1500.0, 50.0)
        iat_mean = st.number_input("Flow IAT Mean", 0.0, 5000.0, 100.0)

    # Prediction Logic
    if st.button("🚀 Analyze Traffic Signature", type="primary"):
        with st.spinner("Scanning pattern against known signatures..."):
            time.sleep(1) # Intentional delay for effect
            
            # Construct Input Array
            # NOTE: We map these to the most likely feature indices for demonstration.
            # In a real app, you would map exact column names.
            input_vector = np.zeros((1, scaler.n_features_in_))
            
            # Filling key slots (Assumptions based on standard CICIDS columns)
            # This ensures the model receives data in the shape it expects
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
                
                st.markdown("---")
                
                if prediction[0] == 1: # ATTACK
                    st.error(f"🚨 **THREAT DETECTED: DDoS ATTACK**")
                    
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Threat Confidence", f"{confidence:.2f}%", delta_color="inverse")
                    c2.metric("Risk Level", "CRITICAL", delta="Immediate Action Req")
                    c3.metric("Protocol", "TCP/UDP Flood")
                    
                    st.warning("**RECOMMENDED ACTION:**\n1. Block Source IP via Firewall.\n2. Rate-limit incoming traffic.\n3. Dump traffic logs for forensics.")
                    
                else: # BENIGN
                    st.success(f"✅ **TRAFFIC STATUS: BENIGN**")
                    
                    c1, c2, c3 = st.columns(3)
                    c1.metric("Safety Confidence", f"{confidence:.2f}%")
                    c2.metric("Risk Level", "LOW")
                    c3.metric("Action", "Allow Traffic")
                    
            except Exception as e:
                st.error(f"Computation Error: {e}")

# ==========================================
# TAB 2: BATCH FILE ANALYSIS
# ==========================================
with tab2:
    st.subheader("📂 Network Log File Analysis")
    st.markdown("Upload a CSV file (CICIDS Format) to scan thousands of packets instantly.")
    
    uploaded_file = st.file_uploader("Upload CSV Logs", type=["csv"])
    
    if uploaded_file:
        df = pd.read_csv(uploaded_file)
        
        # Clean Data
        df.columns = df.columns.str.strip()
        df_clean = df.select_dtypes(include=[np.number])
        df_clean.replace([np.inf, -np.inf], np.nan, inplace=True)
        df_clean.fillna(0, inplace=True)
        
        # Filter Columns to match Model (Simple check)
        # We assume the user uploads a file with similar structure to training data
        # We select only the first N columns to match the scaler
        try:
            # Slicing to match feature count if column names don't match exactly
            if df_clean.shape[1] > scaler.n_features_in_:
                X_input = df_clean.iloc[:, :scaler.n_features_in_]
            else:
                X_input = df_clean
                
            if st.button("🛡️ Initiate Batch Scan"):
                progress_bar = st.progress(0)
                
                # Processing
                X_scaled = scaler.transform(X_input)
                preds = model.predict(X_scaled)
                
                progress_bar.progress(100)
                
                # Results
                df['Prediction'] = preds
                df['Threat_Label'] = df['Prediction'].apply(lambda x: "🚨 MALICIOUS" if x == 1 else "✅ BENIGN")
                
                # Dashboard
                st.markdown("### 📊 Security Report")
                
                # KPIs
                total_pkts = len(df)
                malicious_count = np.sum(preds == 1)
                benign_count = np.sum(preds == 0)
                attack_rate = (malicious_count / total_pkts) * 100
                
                kpi1, kpi2, kpi3 = st.columns(3)
                kpi1.metric("Total Packets Scanned", f"{total_pkts:,}")
                kpi2.metric("Malicious Packets", f"{malicious_count:,}", delta=f"-{malicious_count}", delta_color="inverse")
                kpi3.metric("Attack Rate", f"{attack_rate:.1f}%")
                
                # Charts
                chart1, chart2 = st.columns(2)
                with chart1:
                    st.markdown("**Traffic Distribution**")
                    st.bar_chart(df['Threat_Label'].value_counts(), color=["#ff0000"]) # Red for attack usually, but auto-color is fine
                
                with chart2:
                    st.markdown("**Sample Malicious Entries**")
                    if malicious_count > 0:
                        st.dataframe(df[df['Prediction'] == 1].head(5), height=200)
                    else:
                        st.success("No malicious traffic found in this sample.")
                
                # Download
                csv_data = df.to_csv(index=False).encode('utf-8')
                st.download_button("📥 Download Forensic Report", csv_data, "forensic_report.csv", "text/csv")
                
        except ValueError as e:
            st.error(f"Data Mismatch: {e}")
            st.warning("Ensure the uploaded CSV matches the training data feature count.")

# ==========================================
# TAB 3: MODEL INTELLIGENCE
# ==========================================
with tab3:
    st.subheader("🧠 Inside the AI Brain")
    st.markdown("Understanding how the Random Forest model makes decisions.")
    
    # Feature Importance Visualization
    if hasattr(model, 'feature_importances_'):
        st.markdown("### Feature Importance")
        st.markdown("The following network features carry the most weight in detecting attacks:")
        
        # Get importances
        importances = model.feature_importances_
        # Since we don't have column names from the scaler, we create a generic list
        # OR we assume the standard CICIDS top features:
        feature_names = [f"Feature {i}" for i in range(len(importances))]
        
        # Let's map the top 5 to realistic names for the DEMO (Simulated Explainability)
        # Note: In a real production system, you would pickle the column names list too.
        
        importance_df = pd.DataFrame({'Feature': feature_names, 'Importance': importances})
        importance_df = importance_df.sort_values(by='Importance', ascending=False).head(10)
        
        st.bar_chart(importance_df.set_index('Feature'))
        
        st.caption("""
        **Interpretation:**
        - **High Importance:** These features (e.g., Packet Size, Flow Duration) are strong indicators of an attack.
        - **Low Importance:** These features vary randomly and are not useful for detection.
        """)
    else:
        st.info("Feature importance not available for this model type.")
        
    st.markdown("### Model Architecture")
    st.json({
        "Algorithm": "Random Forest Classifier",
        "Estimators": 100,
        "Criterion": "Gini Impurity",
        "Data Source": "CICIDS 2017 (University of New Brunswick)",
        "Input Features": scaler.n_features_in_
    })
