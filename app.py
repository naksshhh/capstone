from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import pandas as pd
import numpy as np
import tldextract
import math
import re
from collections import Counter

# --- CONFIGURATION ---
app = Flask(__name__)
# Enable CORS so Chrome Extension can send data to localhost
CORS(app) 

# --- LOAD TRAINED MODEL ON STARTUP ---
print("Loading model and feature order...")
try:
    model = joblib.load('phishing_model.pkl')
    feature_order = joblib.load('feature_order.pkl')
    print("Model loaded successfully!")
except Exception as e:
    print(f"Error loading model: {e}")
    print("Make sure 'phishing_model.pkl' and 'feature_order.pkl' are in the same folder.")

def calculate_entropy(text):
    if not text: return 0
    counts = Counter(text)
    length = len(text)
    entropy = 0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

def longest_digit_continuation(text):
    longest = 0
    current = 0
    for char in text:
        if char.isdigit(): current += 1
        else:
            longest = max(longest, current)
            current = 0
    return max(longest, current)

def extract_features(url):
    ext = tldextract.extract(url)
    domain_part = ext.domain + "." + ext.suffix
    subdomain_part = ext.subdomain
    features = {}
    features['url_length'] = len(url)
    features['domain_length'] = len(domain_part)
    features['subdomain_count'] = len(subdomain_part.split('.')) if subdomain_part else 0
    features['dot_count'] = url.count('.')
    features['at_count'] = url.count('@')
    features['hyphen_count'] = url.count('-')
    features['slash_count'] = url.count('/')
    features['domain_entropy'] = calculate_entropy(domain_part)
    total_chars = len(url)
    digit_count = sum(c.isdigit() for c in url)
    features['digit_ratio'] = digit_count / total_chars if total_chars > 0 else 0
    features['max_digit_streak'] = longest_digit_continuation(url)
    ip_pattern = r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$"
    features['is_ip'] = 1 if re.match(ip_pattern, ext.domain) else 0
    suspicious_words = ['login', 'verify', 'update', 'secure', 'bank', 'account']
    features['has_sus_keyword'] = 1 if any(w in url.lower() for w in suspicious_words) else 0
    return features


@app.route('/status', methods=['GET'])
def status():
    return jsonify({'status': 'API is running', 'model_loaded': 'phishing_model.pkl' in globals()})

@app.route('/predict', methods=['POST'])
def predict():
    try:
        # 1. Get URL from the POST request
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Remove trailing slash to prevent slash_count overfitting
        target_url = data['url'].rstrip('/')
        
        # 2. Extract Features
        features_dict = extract_features(target_url)
        
        # 3. Create DataFrame and Align Columns
        input_df = pd.DataFrame([features_dict])
        
        # Ensure columns are in the EXACT order as training (critical for Random Forest)
        # If a feature is missing (rare), fill with 0
        for col in feature_order:
            if col not in input_df.columns:
                input_df[col] = 0
        
        input_df = input_df[feature_order]
        
        # 4. Make Prediction
        # 0 = Phishing, 1 = Legitimate (From your dataset)
        prediction = model.predict(input_df)[0]
        probability = model.predict_proba(input_df)[0]
        
        # 5. Format Response
        # We invert the probability logic here to return "Phishing Probability"
        # If prediction is 0 (Phish), confidence is probability[0]
        # If prediction is 1 (Safe), confidence is probability[1]
        
        is_phishing = bool(prediction == 0) # True if Phishing
        confidence = probability[0] if is_phishing else probability[1]
        
        response = {
            'url': target_url,
            'is_phishing': is_phishing,
            'verdict': "PHISHING" if is_phishing else "LEGITIMATE",
            'confidence': float(confidence), # Convert numpy float to python float
            'risk_score': int(probability[0] * 100) # 0-100 score of how "phishy" it is
        }
        
        return jsonify(response)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# --- RUN SERVER ---
if __name__ == '__main__':
    # Running on port 5000
    app.run(debug=True, port=5000)