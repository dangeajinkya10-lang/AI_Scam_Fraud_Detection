import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score

import joblib


# 1. Load dataset
data = pd.read_csv("dataset/scam_messages.csv")


# 2. Separate message and label
X = data["message"]
y = data["label"]


# 3. Split dataset
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42
)


# 4. Convert text into numbers
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english"
)

X_train_vector = vectorizer.fit_transform(X_train)
X_test_vector = vectorizer.transform(X_test)


# 5. Create ML model
model = LogisticRegression()


# 6. Train model
model.fit(X_train_vector, y_train)


# 7. Test model
y_pred = model.predict(X_test_vector)

accuracy = accuracy_score(y_test, y_pred)

print("Model Accuracy:", accuracy)


# 8. Save model
joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("Model saved successfully!")