from flask import Flask, render_template, request, jsonify
from scapy.all import sniff, TCP, IP, UDP, ICMP
import pandas as pd
import threading
import time
import joblib
from datetime import datetime
import os

app = Flask(__name__)

# Global Variables
features_list = []
stop_sniffing = False
data_interval = 10  # Default interval in seconds
output_dir = './extracted_data'
os.makedirs(output_dir, exist_ok=True)

# Load trained models
dt_clf = joblib.load("dt_model.pkl")
svm_clf = joblib.load("svm_model.pkl")
rf_clf = joblib.load("rf_model.pkl")
pca = joblib.load("pca.pkl")

# Monitoring Thread
def capture_packets(interface):
    global stop_sniffing, features_list
    stop_sniffing = False

    def packet_callback(packet):
        if stop_sniffing:
            raise KeyboardInterrupt
        features = extract_features(packet)
        features_list.append(features)

    while not stop_sniffing:
        sniff(iface=interface, prn=packet_callback, count=1, store=False)

def extract_features(packet):
    features = {
        'Protocol': 'Unknown',
        'Source IP': '',
        'Destination IP': '',
        'Source Port': 0,
        'Destination Port': 0,
        'Packet Length': 0,
        'Flags': '',
        'Payload Size': 0,
    }

    if packet.haslayer(IP):
        features['Source IP'] = packet[IP].src
        features['Destination IP'] = packet[IP].dst
        features['Packet Length'] = len(packet)

        if packet.haslayer(TCP):
            features['Protocol'] = 'TCP'
            features['Source Port'] = packet[TCP].sport
            features['Destination Port'] = packet[TCP].dport

        elif packet.haslayer(UDP):
            features['Protocol'] = 'UDP'
            features['Source Port'] = packet[UDP].sport
            features['Destination Port'] = packet[UDP].dport

        elif packet.haslayer(ICMP):
            features['Protocol'] = 'ICMP'

    return features

@app.route("/monitoring", methods=["GET", "POST"])
def monitoring():
    global stop_sniffing, features_list, data_interval
    if request.method == "POST":
        action = request.form.get("action")
        interface = request.form.get("interface")
        interval = request.form.get("interval")
        data_interval = int(interval) if interval else data_interval

        if action == "start":
            stop_sniffing = False
            thread = threading.Thread(target=capture_packets, args=(interface,))
            thread.start()
            return render_template("monitoring.html", message="Monitoring started!")
        elif action == "stop":
            stop_sniffing = True
            time.sleep(1)
            return render_template("monitoring.html", message="Monitoring stopped.")
    return render_template("monitoring.html", message=None)

@app.route("/save_data", methods=["POST"])
def save_data():
    global features_list, output_dir
    filename = f"{output_dir}/features_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    df = pd.DataFrame(features_list)
    df.to_excel(filename, index=False, engine="openpyxl")
    features_list.clear()
    return jsonify({"message": f"Data saved to {filename}", "file": filename})

@app.route("/data_processing", methods=["GET", "POST"])
def data_processing():
    if request.method == "POST":
        file_path = request.form.get("file_path")
        data = pd.read_excel(file_path)
        processed_data = preprocess_data(data)
        return render_template("data_processing.html", data_preview=processed_data.head().to_html(), file=file_path)
    saved_files = os.listdir(output_dir)
    return render_template("data_processing.html", saved_files=saved_files)

@app.route("/prediction_results", methods=["POST"])
def prediction_results():
    file_path = request.form.get("file_path")
    data = pd.read_excel(file_path)
    processed_data = preprocess_data(data)
    predictions = predict(processed_data)
    return render_template("prediction_results.html", predictions=predictions)

def preprocess_data(data):
    # Replace with your preprocessing logic
    data['Processed'] = data['Packet Length'] * 2  # Example processing
    return data

def predict(data):
    global dt_clf, svm_clf, rf_clf, pca
    input_pca = pca.transform(data)
    dt_preds = dt_clf.predict(input_pca)
    svm_preds = svm_clf.predict(input_pca)
    rf_preds = rf_clf.predict(input_pca)

    # Combine predictions
    final_preds = (dt_preds + svm_preds + rf_preds) // 3
    return {"dt": dt_preds.tolist(), "svm": svm_preds.tolist(), "rf": rf_preds.tolist(), "final": final_preds.tolist()}

if __name__ == "__main__":
    app.run(debug=True)
