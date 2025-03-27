from flask import Flask, request, jsonify, render_template
import pandas as pd
import numpy as np
import joblib
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.model_selection import train_test_split
from scipy.stats import mode
import matplotlib.pyplot as plt
import io
import base64
from scapy.all import sniff, IP, TCP, UDP, ICMP, get_if_list, Raw
from datetime import datetime
import os
import threading

app = Flask(__name__)

# Load pre-trained models and PCA
dt_clf = joblib.load("dt_model.pkl")
svm_clf = joblib.load("svm_model.pkl")
rf_clf = joblib.load("rf_model.pkl")

# Global variables for data
processed_data, y = None, None
connections = {}
stop_sniffing = False
sniff_thread = None
captured_data = []
sniffing_active = False

# -------------------------------------
# Data Preprocessing Function
# -------------------------------------
def preprocess_data(df):
    """Preprocess the dataset and split it into training and test sets."""
    
    columns = [
        'duration', 'protocol_type', 'service', 'flag', 'src_bytes', 'dst_bytes',
        'land', 'wrong_fragment', 'urgent', 'hot', 'num_failed_logins', 'logged_in',
        'num_compromised', 'root_shell', 'su_attempted', 'num_root',
        'num_file_creations', 'num_shells', 'num_access_files', 'num_outbound_cmds',
        'is_host_login', 'is_guest_login', 'count', 'srv_count', 'serror_rate',
        'srv_serror_rate', 'rerror_rate', 'srv_rerror_rate', 'same_srv_rate',
        'diff_srv_rate', 'srv_diff_host_rate', 'dst_host_count',
        'dst_host_srv_count', 'dst_host_same_srv_rate', 'dst_host_diff_srv_rate',
        'dst_host_same_src_port_rate', 'dst_host_srv_diff_host_rate',
        'dst_host_serror_rate', 'dst_host_srv_serror_rate', 'dst_host_rerror_rate',
        'dst_host_srv_rerror_rate', 'attack', 'level'
    ]
    df.columns = columns

    # Frequency encoding for categorical features
    categorical_features = ['protocol_type', 'service', 'flag']
    for col in categorical_features:
        freq_encoding = df[col].value_counts(normalize=True)
        df[col + '_encoded'] = df[col].map(freq_encoding)

    df.drop(columns=categorical_features, inplace=True)

    # Convert 'attack' to binary
    df['attack'] = df['attack'].apply(lambda x: 0 if x == 'normal' else 1)

    # Prepare features and labels
    X = df.drop('attack', axis=1)
    y = df['attack']

    # Standardize the data
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Apply PCA
    pca = PCA(n_components=35)
    X_pca = pca.fit_transform(X_scaled)

    # Split the data
    # X_train, X_test, y_train, y_test = train_test_split(X_pca, y, test_size=0.3, random_state=42)

    return X_pca, y


# -------------------------------------
# Model Prediction Function
# -------------------------------------
def make_predictions(models, input_data):
    """Make predictions using the trained models."""
    dt_clf, svm_clf, rf_clf = models

    y_pred_dt = dt_clf.predict(input_data)
    y_pred_svm = svm_clf.predict(input_data)
    y_pred_rf = rf_clf.predict(input_data)

    # Majority voting
    predictions = np.array([y_pred_dt, y_pred_svm, y_pred_rf])
    final_predictions, _ = mode(predictions, axis=0)

    return {
        "Decision Tree Prediction": y_pred_dt.tolist(),
        "SVM Prediction": y_pred_svm.tolist(),
        "Random Forest Prediction": y_pred_rf.tolist(),
        "Final Prediction (Majority Voting)": final_predictions.flatten().tolist()
    }

def start_sniffing(interface, time_interval):
    global stop_sniffing, sniffing_active
    stop_sniffing = False
    try:
        sniff(iface=interface, prn=process_packet, store = False, timeout=time_interval)
    except KeyboardInterrupt:
        print("Sniffing stopped.")

    stop_sniffing = True
    sniffing_active = False
    file_path = save_captured_data()

def process_packet(packet):
    global stop_sniffing

    if stop_sniffing: 
        raise KeyboardInterrupt

    features = {
        "duration": 0, "protocol_type": "", "service": "", "flag": "",
        "src_bytes": 0, "dst_bytes": 0, "land": 0, "wrong_fragment": 0, "urgent": 0,
        "hot": 0, "num_failed_logins": 0, "logged_in": 0, "num_compromised": 0,
        "root_shell": 0, "su_attempted": 0, "num_root": 0, "num_file_creations": 0,
        "num_shells": 0, "num_access_files": 0, "num_outbound_cmds": 0, "is_host_login": 0, "is_guest_login": 0,
        "count": 0, "srv_count": 0, "serror_rate": 0.0, "srv_serror_rate": 0.0,
        "rerror_rate": 0.0, "srv_rerror_rate": 0.0, "same_srv_rate": 0.0, "diff_srv_rate": 0.0,
        "srv_diff_host_rate": 0.0, "dst_host_count": 0, "dst_host_srv_count": 0,
        "dst_host_same_srv_rate": 0.0, "dst_host_diff_srv_rate": 0.0,
        "dst_host_same_src_port_rate": 0.0, "dst_host_srv_diff_host_rate": 0.0,
        "dst_host_serror_rate": 0.0, "dst_host_srv_serror_rate": 0.0,
        "dst_host_rerror_rate": 0.0, "dst_host_srv_rerror_rate": 0.0,
        "attack": 0, "level": 0
    }

    if IP in packet:
        # Extract basic features
        features["protocol_type"] = "tcp" if TCP in packet else "udp" if UDP in packet else "icmp"
        features["src_bytes"] = len(packet[Raw].load) if Raw in packet else 0
        features["dst_bytes"] = packet[IP].len - features["src_bytes"]
        features["land"] = 1 if packet[IP].src == packet[IP].dst else 0
        features["urgent"] = 1 if TCP in packet and packet[TCP].flags & 0x20 else 0  # URG flag
        features["wrong_fragment"] = 1 if packet[IP].frag > 0 else 0
        features["flag"] = str(packet[TCP].flags) if TCP in packet else "OTH"

        # Map destination port to service (NSL-KDD encoding)
        port_service_map = {80: "http", 22: "ssh", 21: "ftp", 53: "dns", 443: "https", 25: "smtp"}
        features["service"] = port_service_map.get(getattr(packet, "dport", None), "other")

        # Safe retrieval of ports (for UDP/TCP)
        sport = getattr(packet.getlayer(TCP) or packet.getlayer(UDP), "sport", None)
        dport = getattr(packet.getlayer(TCP) or packet.getlayer(UDP), "dport", None)

        connection_key = (sport, dport, features["protocol_type"])

        # Track connection duration & stats
        if connection_key not in connections:
            connections[connection_key] = {
                "start_time": datetime.now(), "last_time": datetime.now(), "packet_count": 0,
                "syn_error_count": 0, "rst_error_count": 0, "srv_count": 0,
                "dst_host_count": 0, "dst_host_srv_count": 0, "same_srv_count": 0,
                "diff_srv_count": 0, "same_src_port_count": 0
            }
        else:
            connections[connection_key]["last_time"] = datetime.now()

        # Calculate duration
        conn = connections[connection_key]
        features["duration"] = (conn["last_time"] - conn["start_time"]).total_seconds()
        conn["packet_count"] += 1

        # Error tracking (SYN & RST errors)
        if TCP in packet and "S" in str(packet[TCP].flags) and "A" not in str(packet[TCP].flags):
            conn["syn_error_count"] += 1
        if TCP in packet and "R" in str(packet[TCP].flags):
            conn["rst_error_count"] += 1

        # Traffic-based features
        conn["same_srv_count"] += 1 if features["service"] == "http" else 0
        conn["diff_srv_count"] += 1 if features["service"] != "http" else 0
        conn["same_src_port_count"] += 1 if hasattr(packet, "sport") else 0

        features["count"] = conn["packet_count"]
        features["srv_count"] = conn["srv_count"]
        features["serror_rate"] = conn["syn_error_count"] / (conn["packet_count"] + 1e-6)
        features["srv_serror_rate"] = conn["syn_error_count"] / (conn["srv_count"] + 1e-6)
        features["rerror_rate"] = conn["rst_error_count"] / (conn["packet_count"] + 1e-6)
        features["srv_rerror_rate"] = conn["rst_error_count"] / (conn["srv_count"] + 1e-6)
        features["same_srv_rate"] = conn["same_srv_count"] / (conn["packet_count"] + 1e-6)
        features["diff_srv_rate"] = conn["diff_srv_count"] / (conn["packet_count"] + 1e-6)

        # Destination host-based features
        conn["dst_host_count"] += 1
        conn["dst_host_srv_count"] += 1 if features["service"] == "http" else 0
        features["dst_host_count"] = conn["dst_host_count"]
        features["dst_host_srv_count"] = conn["dst_host_srv_count"]
        features["dst_host_same_srv_rate"] = conn["same_srv_count"] / (conn["dst_host_count"] + 1e-6)
        features["dst_host_diff_srv_rate"] = conn["diff_srv_count"] / (conn["dst_host_count"] + 1e-6)
        features["dst_host_same_src_port_rate"] = conn["same_src_port_count"] / (conn["dst_host_count"] + 1e-6)
        features["dst_host_serror_rate"] = conn["syn_error_count"] / (conn["dst_host_count"] + 1e-6)
        features["dst_host_srv_serror_rate"] = conn["syn_error_count"] / (conn["dst_host_srv_count"] + 1e-6)
        features["dst_host_rerror_rate"] = conn["rst_error_count"] / (conn["dst_host_count"] + 1e-6)
        features["dst_host_srv_rerror_rate"] = conn["rst_error_count"] / (conn["dst_host_srv_count"] + 1e-6)
        features["attack"] = 1

        for key, value in features.items():
            if isinstance(value, (int, float)):
                features[key] = round(value)

        # Append features to captured_data
        captured_data.append(features)

def save_captured_data():
    """Save captured packets to an Excel file."""
    if captured_data:
        output_dir = "network_data"
        os.makedirs(output_dir, exist_ok=True)
        file_path = os.path.join(output_dir, f"monitored_traffic_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx")
        pd.DataFrame(captured_data).to_excel(file_path, index=False)
        return file_path
    return None


# -------------------------------------
# Routes for Workflows
# -------------------------------------
@app.route('/')
def home():
    """Home page with links to workflows."""
    return render_template('home.html')


@app.route("/monitor_network", methods=["GET", "POST"])
def monitor_network():
    global sniff_thread, stop_sniffing, captured_data, sniffing_active

    try:
        if request.method == "POST":
            action = request.form.get("action")

            if action == "start":
                if sniffing_active:
                    return render_template("monitoring.html", message="Monitoring is already running...")

                interface = request.form.get("interface", "Wi-Fi")
                time_interval = int(request.form.get("interval", 30))

                # Start sniffing in a separate thread if not already running
                if sniff_thread is None or not sniff_thread.is_alive():
                    captured_data.clear()  # Clear old captured data before starting
                    sniff_thread = threading.Thread(target=start_sniffing, args=(interface, time_interval))
                    sniff_thread.start()
                    sniffing_active = True
                    return render_template("monitoring.html", message="Monitoring started!")

            elif action == "stop":
                if not sniffing_active:
                    return render_template("monitoring.html", message="No monitoring session is running!")
                stop_sniffing = True  # Set flag to stop sniffing

                # Wait for sniffing thread to stop
                if sniff_thread and sniff_thread.is_alive():
                    sniff_thread.join()
                sniffing_active = False

                # Save captured data if available
                file_path = save_captured_data()
                if file_path:
                    return render_template("monitoring.html", message=f"Traffic monitoring stopped. Data saved to {file_path}.")
                else:
                    return render_template("monitoring.html", message="No traffic captured before stopping.")
    except Exception as e:
        return render_template("monitoring.html", message={e.message})

    return render_template("monitoring.html", message=None)


@app.route("/load_data", methods=["GET", "POST"])
def load_data():
    """Load and preprocess data."""
    global processed_data, y
    if request.method == "POST":
        file = request.files.get('file')  # Retrieve the file from the form
        if not file:
            return render_template('load_data.html', message="No file uploaded.")

        try:
            if file.filename.endswith('.txt'):
                df = pd.read_csv(file, header=None)  # Handle text files
            elif file.filename.endswith(('.xls', '.xlsx')):
                df = pd.read_excel(file)  # Handle Excel files
            else:
                return render_template('load_data.html', message="Unsupported file format. Please upload a .txt or .xlsx/.xls file.")

            # Pass the DataFrame to the preprocess_data function
            processed_data, y = preprocess_data(df)
            return render_template('load_data.html', message="Data loaded and processed successfully.")
        except Exception as e:
            return render_template('load_data.html', message=f"Error processing file: {str(e)}")

    return render_template('load_data.html', message=None)


@app.route("/predict", methods=["GET", "POST"])
def predict():
    global dt_clf, svm_clf, rf_clf, processed_data

    if not dt_clf or not svm_clf or not rf_clf:
        return render_template("predict.html", error="Models are not loaded. Please ensure models are available.")

    predictions = None
    error = None
    threat_level = "No threat detected"

    if request.method == "POST":
        try:
            # Get predictions
            y_pred_dt = dt_clf.predict(processed_data)
            y_pred_svm = svm_clf.predict(processed_data)
            y_pred_rf = rf_clf.predict(processed_data)

            # Majority voting
            # predictions_array = np.array([y_pred_dt, y_pred_svm, y_pred_rf])
            # final_predictions, _ = mode(predictions_array, axis=0)

            final_predictions = []
            for i in range(0, len(y_pred_dt)):
                t = y_pred_dt[i] + y_pred_svm[i] + y_pred_rf[i]
                final_predictions.append(1) if t > 1 else final_predictions.append(0)


            # Truncate predictions to show only the first 10
            truncated_predictions = final_predictions[:20]

            # Calculate threat level based on the number of '1's (attacks)
            attack_count = np.sum(final_predictions)
            total_predictions = len(final_predictions)

            # Define threat level based on attack percentage
            threat_percentage = (attack_count / total_predictions) * 100

            if threat_percentage == 0:
                threat_level = "No threat detected. Your network is safe."
            elif 0 < threat_percentage <= 20:
                threat_level = "Low threat level detected. No immediate danger."
            elif 20 < threat_percentage <= 50:
                threat_level = "Moderate threat level detected. Monitor network activity."
            elif 50 < threat_percentage <= 80:
                threat_level = "High threat level detected! Possible network intrusion."
            else:
                threat_level = "Critical threat level detected! Take immediate action!"

            return render_template("predict.html", predictions=truncated_predictions, threat_level=threat_level)

        except Exception as e:
            error = f"Error processing input data: {str(e)}"

    return render_template("predict.html", predictions=None, threat_level = threat_level, error=error)


@app.route("/visualize", methods=["GET"])
def visualize():
    global processed_data, y

    # if X_test is None or y_test is None:
        # return render_template('visualize.html', error="Data not available for visualization. Load the data first.", image=None)

    plt.figure(figsize=(8, 6))
    plt.scatter(processed_data[:, 0], processed_data[:, 1], c=y, cmap='coolwarm', s=50, edgecolor='k', alpha=0.7)
    plt.title('PCA 2D Visualization of Attack vs. Normal Traffic')
    plt.xlabel('Principal Component 1')
    plt.ylabel('Principal Component 2')
    plt.colorbar(label='Attack (1) or Normal (0)')

    # Save plot to a bytes buffer
    buf = io.BytesIO()
    plt.savefig(buf, format='png')
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    buf.close()

    return render_template('visualize.html', error=None, image=img_base64)


if __name__ == "__main__":
    app.run(debug=True)
