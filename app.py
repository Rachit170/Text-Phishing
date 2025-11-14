from flask import Flask, request, jsonify
from flask_cors import CORS
from transformers import pipeline, DistilBertForSequenceClassification, DistilBertTokenizer
import torch
import os
from dotenv import load_dotenv
import logging

load_dotenv()

app = Flask(__name__)
CORS(app)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global model and tokenizer
classifier = None
tokenizer = None
device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

def load_model():
    """Load the fine-tuned DistilBERT model"""
    global classifier, tokenizer
    try:
        model_path = os.getenv("MODEL_PATH", "./models/phishing_detector")
        if os.path.exists(model_path):
            logger.info(f"Loading model from {model_path}")
            tokenizer = DistilBertTokenizer.from_pretrained(model_path)
            model = DistilBertForSequenceClassification.from_pretrained(model_path)
            model.to(device)
            classifier = pipeline("text-classification", model=model, tokenizer=tokenizer, device=0 if torch.cuda.is_available() else -1)
            logger.info("Fine-tuned model loaded successfully")
        else:
            logger.warning(f"Model path {model_path} not found. Using pretrained DistilBERT model.")
            logger.warning("Make sure to run train_model.py first to create the trained model.")
            classifier = pipeline("text-classification", model="distilbert-base-uncased", device=0 if torch.cuda.is_available() else -1)
            logger.info("Pretrained model loaded as fallback")
    except Exception as e:
        logger.error(f"Error loading model: {e}")
        logger.warning("Falling back to pretrained DistilBERT model")
        classifier = pipeline("text-classification", model="distilbert-base-uncased", device=0 if torch.cuda.is_available() else -1)

def preprocess_email(subject, sender, body, links):
    """Preprocess email content for analysis"""
    combined_text = f"Subject: {subject}\nFrom: {sender}\nBody: {body}\nLinks: {', '.join(links) if links else 'None'}"
    return combined_text[:512]  # Limit to 512 tokens

def extract_phishing_keywords(text):
    """Extract common phishing keywords and patterns"""
    phishing_keywords = [
        "verify", "confirm", "urgent", "immediate", "click", "update",
        "account", "suspicious", "activity", "click here", "validate",
        "action required", "unauthorized", "limited time", "act now",
        "reset password", "confirm identity", "unusual activity"
    ]
    
    text_lower = text.lower()
    found_keywords = [kw for kw in phishing_keywords if kw in text_lower]
    return found_keywords

def generate_explanation(prediction, keywords, sender, subject):
    """Generate human-readable explanation for the prediction"""
    base_explanation = ""
    
    if prediction["label"] == "LABEL_1":  # Phishing
        base_explanation = "This email shows characteristics of a phishing attempt."
        if keywords:
            base_explanation += f" Suspicious keywords detected: {', '.join(keywords[:3])}."
        if "@" not in sender or sender.count("@") > 1:
            base_explanation += " Sender email appears suspicious."
    else:  # Safe
        base_explanation = "This email appears to be legitimate."
        if len(keywords) < 2:
            base_explanation += " Few phishing indicators detected."
    
    confidence = prediction["score"]
    if confidence > 0.9:
        base_explanation += " High confidence."
    elif confidence < 0.6:
        base_explanation += " Low confidence - please verify manually."
    
    return base_explanation

@app.route("/", methods=["GET"])
def home():
    """Root endpoint - lists available endpoints"""
    return jsonify({
        "message": "Phishing Detection API",
        "endpoints": {
            "GET /": "This help message",
            "GET /health": "Health check",
            "POST /predict": "Predict single email",
            "POST /batch-predict": "Predict multiple emails"
        }
    }), 200

@app.route("/health", methods=["GET"])
def health():
    """Health check endpoint"""
    return jsonify({"status": "ok", "model_loaded": classifier is not None}), 200

@app.route("/predict", methods=["POST"])
def predict():
    """Predict if email is phishing
    
    Expected JSON:
    {
        "subject": "Email subject",
        "sender": "sender@example.com",
        "body": "Email body text",
        "links": ["http://example.com", ...]
    }
    """
    try:
        data = request.json
        
        # Validate input
        if not data or "subject" not in data or "body" not in data:
            return jsonify({"error": "Missing required fields: subject, body"}), 400
        
        subject = data.get("subject", "").strip()[:200]
        sender = data.get("sender", "unknown").strip()[:100]
        body = data.get("body", "").strip()[:1000]
        links = data.get("links", [])
        
        if not subject and not body:
            return jsonify({"error": "Email must have subject or body"}), 400
        
        # Preprocess email
        processed_text = preprocess_email(subject, sender, body, links)
        
        # Get prediction
        if classifier is None:
            return jsonify({"error": "Model not loaded"}), 500
        
        prediction = classifier(processed_text)[0]
        keywords = extract_phishing_keywords(processed_text)
        explanation = generate_explanation(prediction, keywords, sender, subject)
        
        # Format response
        response = {
            "label": "phishing" if prediction["label"] == "LABEL_1" else "safe",
            "confidence": round(prediction["score"], 4),
            "score": round(prediction["score"], 4),
            "explanation": explanation,
            "keywords_detected": keywords,
            "sender_risk": "high" if "@" not in sender or sender.count("@") > 1 else "low"
        }
        
        return jsonify(response), 200
    
    except Exception as e:
        logger.error(f"Prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@app.route("/batch-predict", methods=["POST"])
def batch_predict():
    """Batch predict multiple emails"""
    try:
        data = request.json
        emails = data.get("emails", [])
        
        if not emails:
            return jsonify({"error": "No emails provided"}), 400
        
        results = []
        for email in emails:
            subject = email.get("subject", "").strip()[:200]
            sender = email.get("sender", "unknown").strip()[:100]
            body = email.get("body", "").strip()[:1000]
            links = email.get("links", [])
            
            processed_text = preprocess_email(subject, sender, body, links)
            prediction = classifier(processed_text)[0]
            keywords = extract_phishing_keywords(processed_text)
            explanation = generate_explanation(prediction, keywords, sender, subject)
            
            results.append({
                "label": "phishing" if prediction["label"] == "LABEL_1" else "safe",
                "confidence": round(prediction["score"], 4),
                "explanation": explanation,
                "keywords_detected": keywords
            })
        
        return jsonify({"results": results}), 200
    
    except Exception as e:
        logger.error(f"Batch prediction error: {e}")
        return jsonify({"error": str(e)}), 500

@app.errorhandler(404)
def not_found(error):
    return jsonify({"error": "Endpoint not found"}), 404

@app.errorhandler(500)
def internal_error(error):
    return jsonify({"error": "Internal server error"}), 500

if __name__ == "__main__":
    load_model()
    logger.info("Starting Flask server on port 5000")
    logger.info("Available endpoints: GET /, GET /health, POST /predict, POST /batch-predict")
    app.run(debug=os.getenv("FLASK_ENV", "production") == "development", port=5000, host="0.0.0.0")
