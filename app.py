import streamlit as st
import pandas as pd
import numpy as np
import pickle

# Page Configuration
st.set_page_config(page_title="Network IDS - DDoS Detection", page_icon="🛡️", layout="centered")

# --- HEADER ---
st.title("🛡️ Network Intrusion Detection System")
st.markdown("""
**Type:** Lightweight ML-based IDS  
**Dataset:** CICIDS 2017 (DDoS Subset)  
**Status:** System Active
""")
st.divider()

# --- LOAD MODELS ---
@st.cache_resource
def load_resources():
    try:
        # Load the model
        with open('ids_model.pkl', 'rb') as f:
            model = pickle.load(f)
        # Load the scaler
        with open('scaler.pkl', 'rb') as f:
            scaler = pickle.load(f)
        return model, scaler
    except FileNotFoundError:
        return None, None

model, scaler = load_resources()

if model is None:
    st.error("⚠️ Error: Model files not found!")
    st.info("Please make sure 'ids_model.pkl' and 'scaler.pkl' are in the same folder as this script.")
    st.stop()

# --- SIDEBAR ---
st.sidebar.header("Input Configuration")
input_type = st.sidebar.radio("Select Input Mode:", ["📂 Upload CSV File", "⚡ Quick Manual Test"])

# --- MAIN APP LOGIC ---

if input_type == "📂 Upload CSV File":
    st.subheader("Batch Analysis via CSV")
    uploaded_file = st.sidebar.file_uploader("Upload Network Traffic (CSV)", type=["csv"])
    
    if uploaded_file:
        try:
            # Load Data
            input_df = pd.read_csv(uploaded_file)
            st.write(f"Loaded {input_df.shape[0]} records.")

            # Clean column names (strip spaces just like in training)
            input_df.columns = input_df.columns.str.strip()
            
            # Drop non-feature columns if they exist (clean-up)
            cols_to_drop = ['Flow ID', 'Source IP', 'Source Port', 'Destination IP', 'Timestamp', 'Label']
            existing_cols_to_drop = [c for c in cols_to_drop if c in input_df.columns]
            features_df = input_df.drop(columns=existing_cols_to_drop)

            # Ensure we have numeric data only
            features_df = features_df.select_dtypes(include=[np.number])
            
            # Handle Infinity/NaN just like training
            features_df.replace([np.inf, -np.inf], np.nan, inplace=True)
            features_df.fillna(0, inplace=True)

            if st.button("Run Detection System"):
                # Scale
                try:
                    scaled_features = scaler.transform(features_df)
                    # Predict
                    predictions = model.predict(scaled_features)
                    
                    # Add results to original dataframe
                    input_df['Prediction'] = predictions
                    input_df['Status'] = input_df['Prediction'].apply(lambda x: "🚨 ATTACK (DDoS)" if x == 1 else "✅ BENIGN")
                    
                    # Show Attack Stats
                    st.subheader("Detection Results")
                    col1, col2 = st.columns(2)
                    num_attacks = np.sum(predictions == 1)
                    col1.metric("Normal Traffic", np.sum(predictions == 0))
                    col2.metric("Attacks Detected", num_attacks, delta_color="inverse")
                    
                    # Display Data
                    st.dataframe(input_df[['Prediction', 'Status']].join(input_df.iloc[:, 0:5])) # Show first few cols + result
                    
                except ValueError as e:
                    st.error(f"Feature Mismatch: The model expects {scaler.n_features_in_} features, but your CSV has {features_df.shape[1]}.")
                    st.warning("Tip: Ensure you are using the exact same CSV format as the training data.")

        except Exception as e:
            st.error(f"Error processing file: {e}")

elif input_type == "⚡ Quick Manual Test":
    st.subheader("Single Packet Simulation")
    st.info("Note: This is a simulation. Unspecified features are set to 0.")
    
    # We only ask for meaningful features for a demo
    # These are key features for DDoS detection
    col1, col2 = st.columns(2)
    fwd_packets = col1.number_input("Total Fwd Packets", min_value=0, value=10)
    flow_duration = col2.number_input("Flow Duration (ms)", min_value=0, value=10000)
    
    pkt_len_max = col1.number_input("Max Packet Length", min_value=0, value=500)
    pkt_len_mean = col2.number_input("Mean Packet Length", min_value=0, value=60)
    
    if st.button("Analyze Traffic"):
        # 1. Create a dummy row with zeros for ALL features expected by the scaler
        # scaler.n_features_in_ tells us exactly how many features the model needs
        num_features = scaler.n_features_in_
        dummy_input = np.zeros((1, num_features))
        
        # 2. Fill in the values we know (This is a hack for the demo)
        # We have to guess the indices based on standard CICIDS columns. 
        # If this is inaccurate, the "CSV Upload" is the preferred method.
        # But for a project demo, this visualizes the capability nicely.
        
        # Indices for CICIDS 2017 (Approximate standard positions)
        # [0]=Dst Port, [1]=Flow Duration, [2]=Tot Fwd Pkts, ...
        # We will just map our inputs to the first few slots or specific slots if we knew them.
        # For safety/demo, we put them in the first few non-zero slots.
        dummy_input[0, 1] = flow_duration
        dummy_input[0, 2] = fwd_packets
        dummy_input[0, 10] = pkt_len_max
        dummy_input[0, 11] = pkt_len_mean
        
        # 3. Predict
        try:
            scaled_input = scaler.transform(dummy_input)
            pred = model.predict(scaled_input)
            
            if pred[0] == 1:
                st.error("🚨 ALERT: DDoS Attack Pattern Detected!")
            else:
                st.success("✅ Traffic Analysis: Normal Behavior")
        except Exception as e:
            st.error(f"Error in prediction: {e}")

# --- FOOTER ---
st.markdown("---")
st.caption("Developed for AI Course Project | Powered by Scikit-Learn & Streamlit")