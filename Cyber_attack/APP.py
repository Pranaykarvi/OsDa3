import streamlit as st
import pandas as pd
import joblib

# Load the saved model
model = joblib.load("Cyber_attack/cyber_attack_model.joblib")
data = pd.read_csv("Cyber_attack/cyber_attack_model.joblib")  # Update path as necessary

# Define the layout and title for the Streamlit app
st.set_page_config(page_title="Cyber Attack Type Detection", layout="wide")
st.title("Cyber Attack Type Detection")

# Sidebar navigation with a dropdown
st.sidebar.title("Navigation")
page = st.sidebar.selectbox("Choose a page", ["Home", "About Us", "Predict"])

# Home Section
if page == "Home":
    st.header("Our Approach")
    st.write("""
      This application leverages a Random Forest model to classify different types of cyber attacks by analyzing network traffic data. The model has been trained on a well-curated dataset containing labeled instances that represent both benign and malicious network activities. This training allows the model to identify specific patterns in the data that correspond to various types of cyber attacks, such as Distributed Denial of Service (DDoS), phishing, malware, or reconnaissance activities, while distinguishing these from normal network behavior.

Our approach prioritizes robust data preprocessing and feature selection to enhance the model's accuracy and efficiency. In preprocessing, we address issues like missing values, noise reduction, and normalization or scaling to ensure that all network features contribute meaningfully to the model’s learning process. For feature selection, we apply techniques such as correlation analysis and feature importance rankings to isolate the most significant features, which helps improve computational efficiency and avoid model overfitting. 

The Random Forest algorithm was selected for its strength in handling high-dimensional data and its capacity for parallel processing, making it highly suitable for real-time or near-real-time applications in network security. By training on comprehensive attack patterns and benign behaviors, the model is able to accurately classify and flag various cyber threats, allowing for faster and more effective response actions in a cybersecurity setting.
    """)

# About Us Section
elif page == "About Us":
    
   
    st.write("""
        ### **Team Name:** DDoS Detection System
        #### **Member 1**: Pranay Karvi, Registration Number: 23BDS1137
        #### **Member 2**: Aryan Mahawar, Registration Number: 23BDS1095
        #### **Member 3**: Tapan Batla, Registration Number: 23BDS1151
    """)

# Predict Section
elif page == "Predict":
    st.header("Predict Cyber Attack Type")
    
    # Input fields for prediction based on the eight required features
    protocol = st.selectbox("Protocol", data['Protocol'].unique())
    packet_type = st.selectbox("Packet Type", data['Packet Type'].unique())
    traffic_type = st.selectbox("Traffic Type", data['Traffic Type'].unique())
    malware_indicators = st.selectbox("Malware Indicators", data['Malware Indicators'].unique())
    anomaly_scores = st.number_input("Anomaly Scores", min_value=0.0, max_value=100.0, value=0.0)
    alerts_warnings = st.selectbox("Alerts/Warnings", data['Alerts/Warnings'].unique())
    attack_signature = st.selectbox("Attack Signature", data['Attack Signature'].unique())
    severity_level = st.selectbox("Severity Level", data['Severity Level'].unique())

    # Button for making prediction
    if st.button("Predict"):
        # Encode inputs as per the provided encoding logic
        protocol_encoded = {'ICMP': 0, 'UDP': 1, 'TCP': 2}.get(protocol, -1)
        packet_type_encoded = {'Control': 0, 'Data': 1}.get(packet_type, -1)
        traffic_type_encoded = {'HTTP': 0, 'DNS': 1, 'FTP': 2}.get(traffic_type, -1)
        malware_indicators_encoded = 1 if malware_indicators == 'IoC Detected' else (0 if pd.isna(malware_indicators) else malware_indicators)
        alerts_warnings_encoded = 1 if alerts_warnings == 'Alert Triggered' else 0
        attack_signature_encoded = {'Known Pattern A': 0, 'Known Pattern B': 1}.get(attack_signature, -1)
        severity_level_encoded = {'Low': 0, 'Medium': 1, 'High': 2}.get(severity_level, -1)

        # Collect features into a DataFrame
        input_data = pd.DataFrame({
            "Protocol": [protocol_encoded],
            "Packet Type": [packet_type_encoded],
            "Traffic Type": [traffic_type_encoded],
            "Malware Indicators": [malware_indicators_encoded],
            "Anomaly Scores": [anomaly_scores],
            "Alerts/Warnings": [alerts_warnings_encoded],
            "Attack Signature": [attack_signature_encoded],
            "Severity Level": [severity_level_encoded]
        })

        # Prediction using the model
        prediction = model.predict(input_data)
        st.write("Raw Prediction Output:", prediction)

        # Display the corresponding message based on prediction result
        if prediction[0] == 0:
            result = "DDoS is detected"
        elif prediction[0] == 1:
            result = "Intrusion detected"
        elif prediction[0] == 2:
            result = "Malware detected"
        else:
            result = "Unknown threat detected"

        st.write("Prediction:", result)
