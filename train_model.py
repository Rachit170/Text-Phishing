"""
DistilBERT Model Training Script for Phishing Detection
"""
import torch
import numpy as np
import pandas as pd
import os
from transformers import DistilBertTokenizer, DistilBertForSequenceClassification, Trainer, TrainingArguments
from datasets import Dataset
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.model_selection import train_test_split

def load_phishing_dataset(test_size=0.2):
    """Load and prepare phishing email dataset from CSV"""
    csv_file = "phishing_email.csv"
    
    if not os.path.exists(csv_file):
        raise FileNotFoundError(f"Dataset not found at {csv_file}")
    
    df = pd.read_csv(csv_file)
    print(f"Loaded dataset with {len(df)} samples")
    print(f"Columns: {df.columns.tolist()}")
    
    # Use exact column names from your dataset
    text_column = "text_combined"
    label_column = "label"
    
    print(f"Using text column: '{text_column}', label column: '{label_column}'")
    
    # Prepare data
    data = []
    for idx, row in df.iterrows():
        text = str(row[text_column]).strip()
        label = int(row[label_column])
        
        if len(text) > 0:
            data.append({"text": text, "label": label})
    
    print(f"Prepared {len(data)} samples after cleaning")
    
    # Split data
    train_data, val_data = train_test_split(
        data,
        test_size=test_size,
        random_state=42,
        stratify=[d["label"] for d in data]
    )
    
    print(f"Train: {len(train_data)}, Validation: {len(val_data)}")
    train_labels = [d["label"] for d in train_data]
    print(f"Train distribution - Legitimate: {train_labels.count(0)}, Phishing: {train_labels.count(1)}")
    
    return train_data, val_data

def prepare_dataset(data):
    """Prepare dataset for training"""
    texts = [item["text"] for item in data]
    labels = [item["label"] for item in data]
    return Dataset.from_dict({"text": texts, "label": labels})

def tokenize_function(examples, tokenizer):
    """Tokenize examples"""
    return tokenizer(
        examples["text"],
        padding="max_length",
        truncation=True,
        max_length=512
    )

def compute_metrics(eval_pred):
    """Compute evaluation metrics"""
    predictions, labels = eval_pred
    predictions = np.argmax(predictions, axis=1)
    
    return {
        "accuracy": accuracy_score(labels, predictions),
        "precision": precision_score(labels, predictions, average="weighted", zero_division=0),
        "recall": recall_score(labels, predictions, average="weighted", zero_division=0),
        "f1": f1_score(labels, predictions, average="weighted", zero_division=0)
    }

def train_model():
    """Train DistilBERT model on phishing dataset"""
    print("Loading dataset...")
    train_data, val_data = load_phishing_dataset(test_size=0.2)
    
    print("Loading tokenizer...")
    tokenizer = DistilBertTokenizer.from_pretrained("distilbert-base-uncased")
    
    print("Preparing datasets...")
    train_dataset = prepare_dataset(train_data)
    val_dataset = prepare_dataset(val_data)
    
    print("Tokenizing datasets...")
    tokenized_train = train_dataset.map(
        lambda x: tokenize_function(x, tokenizer),
        batched=True
    )
    tokenized_val = val_dataset.map(
        lambda x: tokenize_function(x, tokenizer),
        batched=True
    )
    
    print("Loading model...")
    model = DistilBertForSequenceClassification.from_pretrained(
        "distilbert-base-uncased",
        num_labels=2
    )
    
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    model.to(device)
    print(f"Using device: {device}")
    
    training_args = TrainingArguments(
        output_dir="./models/phishing_detector",
        num_train_epochs=3,
        per_device_train_batch_size=8,
        per_device_eval_batch_size=8,
        warmup_steps=500,
        weight_decay=0.01,
        logging_dir="./logs",
        logging_steps=100,
        eval_strategy="epoch",
        save_strategy="epoch",
        load_best_model_at_end=True,
    )
    
    trainer = Trainer(
        model=model,
        args=training_args,
        train_dataset=tokenized_train,
        eval_dataset=tokenized_val,
        compute_metrics=compute_metrics,
    )
    
    print("Starting training...")
    trainer.train()
    
    print("Saving model...")
    model.save_pretrained("./models/phishing_detector")
    tokenizer.save_pretrained("./models/phishing_detector")
    print("Training complete! Model saved to ./models/phishing_detector")

if __name__ == "__main__":
    train_model()
