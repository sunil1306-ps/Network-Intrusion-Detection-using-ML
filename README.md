# **Network Intrusion Detection System (NIDS) Using Machine Learning**  

## **Table of Contents**  
1️⃣ [Project Overview](#project-overview)  
2️⃣ [Features](#features)  
3️⃣ [Project Structure](#project-structure)  
4️⃣ [Installation & Setup](#installation--setup)  
5️⃣ [How to Use?](#how-to-use)  
   - [Start Network Monitoring](#start-network-monitoring)  
   - [Load and Process Captured Data](#load-and-process-captured-data)  
   - [Predict and Analyze Threat Level](#predict-and-analyze-threat-level)  
6️⃣ [Threat Level Calculation](#threat-level-calculation)  
7️⃣ [Machine Learning Models Used](#machine-learning-models-used)  
8️⃣ [Example Output](#example-output)  
9️⃣ [Technologies Used](#technologies-used)  
🔟 [Future Improvements](#future-improvements)  
1️⃣1️⃣ [Contributors](#contributors)  
1️⃣2️⃣ [License](#license)  

---

## **Project Overview**  
This project is a **Network Intrusion Detection System (NIDS)** that uses **machine learning models** to detect malicious network activities such as **Port Scanning, Brute Force Attacks, DoS, SQL Injection, and Cross-Site Scripting (XSS)**. The system captures live network traffic, extracts features, processes the data, and applies **Decision Tree, SVM, and Random Forest** models to detect potential attacks.

---

## **Features**  
✅ **Live Network Traffic Capture** – Uses Scapy to monitor network packets.  
✅ **Feature Extraction** – Extracts 43 NSL-KDD-like features from network data.  
✅ **Machine Learning Models** – Decision Tree, SVM, and Random Forest models trained on NSL-KDD & real network traffic.  
✅ **Attack Detection** – Identifies **Port Scanning, Brute Force, DoS, SQL Injection, XSS** attacks.  
✅ **Threat Level Analysis** – Determines risk severity based on detected attacks.  
✅ **Web Interface (Flask + HTML/CSS)** – Interactive dashboard for monitoring & predictions.  
✅ **Data Visualization** – PCA, feature distributions, and attack classification plots.  

---

## **Project Structure**  
```
/NIDS_Project/
│── /static/                 # Static files (CSS, images)
│   ├── /css/                # Stylesheets
│   │   ├── styles.css
│   ├── /images/             # Background & UI images
│   │   ├── cyber_bg.jpg
│── /templates/              # HTML templates
│   ├── home.html            # Homepage (Start/Stop Monitoring)
│   ├── monitoring.html       # Live network monitoring UI
│   ├── load_data.html        # Upload and process captured data
│   ├── predict.html          # Show ML predictions & threat level
│── /network_data/           # Captured network traffic (Excel files)
│── packet_capture.py        # Captures network traffic using Scapy
│── feature_extraction.py    # Extracts NSL-KDD features
│── preprocess.py            # Preprocessing & PCA
│── train_models.py          # Trains ML models (Decision Tree, SVM, RF)
│── app.py                   # Flask web application
│── requirements.txt         # Required dependencies
│── README.md                # Project documentation
```

---

## **Installation & Setup**  
### **1️⃣ Clone the Repository**  
```bash
git clone https://github.com/sunil1306-ps/NIDS_Project.git
cd NIDS_Project
```

### **2️⃣ Install Dependencies**  
```bash
pip install -r requirements.txt
```

### **3️⃣ Run the Flask Application**  
```bash
python app.py
```
- Open **http://127.0.0.1:5000/** in a web browser.  

---

## **How to Use?**  
### **🔹 Start Network Monitoring**  
1. Open **http://127.0.0.1:5000/monitor_network**.  
2. Select **Network Interface** and **Time Interval**.  
3. Click **"Start Monitoring"** to capture live traffic.  
4. Click **"Stop Monitoring"** or wait for the time to expire.  
5. Data is automatically saved in **/network_data/**.  

### **🔹 Load and Process Captured Data**  
1. Navigate to **"Load and Process Data"** page.  
2. Upload the captured network traffic file (.xlsx).  
3. Data is preprocessed (encoding, scaling, PCA).  

### **🔹 Predict and Analyze Threat Level**  
1. Navigate to **"Predict"** page.  
2. Click **"Run Prediction"** – The system will:  
   - Run **Decision Tree, SVM, and Random Forest models**.  
   - Use **majority voting** to determine attack or normal traffic.  
   - Show **first 10 predictions & threat level**.  
3. If high threat is detected, take **security actions** (e.g., block IPs).  

---

## **Threat Level Calculation**
- The **threat level** is based on the **percentage of detected attacks** in the prediction array.
- **Severity Levels:**
  - 🟢 **0% Attacks** → **No Threat**
  - 🟡 **1-20% Attacks** → **Low Risk**
  - 🟠 **21-50% Attacks** → **Moderate Risk**
  - 🔴 **51-80% Attacks** → **High Risk**
  - 🔥 **81-100% Attacks** → **Critical Risk! Immediate Action Needed!**

---

## **Machine Learning Models Used**
✅ **Decision Tree Classifier**  
✅ **Support Vector Machine (SVM)**  
✅ **Random Forest Classifier**  
- Models are trained using **NSL-KDD dataset** and **real network traffic**.  
- **PCA (Principal Component Analysis)** is applied for dimensionality reduction.  

---

## **Example Output**
**First 10 Predictions:**  
```
[0, 1, 0, 1, 0, 0, 1, 0, 1, 1]
```
**Threat Level:**  
🔴 **"High threat level detected! Possible network intrusion."**

---

## **Technologies Used**
- **Python** (Flask, Scapy, NumPy, Pandas, Sklearn, Matplotlib)
- **Machine Learning** (Decision Tree, SVM, Random Forest)
- **Network Security** (Packet Sniffing with Scapy)
- **Flask Web App** (HTML, CSS, JavaScript)

---

## **Future Improvements**
🔹 **Deep Learning Model** (CNN/RNN for advanced attack detection).  
🔹 **Live Real-Time Alerts** (Send email/SMS when high threat is detected).  
🔹 **Distributed NIDS** (Deploy across multiple devices).  

---

## **Contributors**
👤 **Sunil Saragadam** (Project Developer)  
📧 **saragadamsunil7@gmail.com**  
🔗 [GitHub Profile](https://github.com/sunil1306-ps)  

---

## **License**
This project is licensed under the **MIT License**.  

---
