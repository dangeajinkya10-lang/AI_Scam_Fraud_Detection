import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression

from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)


# =====================================
# STEP 1: LOAD DATASET
# =====================================

data = pd.read_csv("dataset/scam_messages.csv")

# Remove rows with missing required values
data = data.dropna(subset=["message", "label"])

# Convert text columns to strings
data["message"] = data["message"].astype(str).str.strip()
data["label"] = data["label"].astype(str).str.strip().str.lower()

# Remove empty messages
data = data[data["message"] != ""]

print("\nDataset Loaded Successfully!")
print("Total Messages:", len(data))

print("\nLabel Distribution:")
print(data["label"].value_counts())


# =====================================
# STEP 2: PREPARE SCAM / SAFE MODEL
# =====================================

X = data["message"]
y = data["label"]

# Convert text into numerical features
vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000,
    sublinear_tf=True
)

# Split raw text BEFORE fitting the vectorizer
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

# Learn vocabulary from training messages only
X_train_vectorized = vectorizer.fit_transform(X_train)

# Transform test messages using the same vectorizer
X_test_vectorized = vectorizer.transform(X_test)


# =====================================
# STEP 3: TRAIN SCAM / SAFE MODEL
# =====================================

model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=42
)

model.fit(X_train_vectorized, y_train)


# =====================================
# STEP 4: EVALUATE MODEL
# =====================================

predictions = model.predict(X_test_vectorized)

accuracy = accuracy_score(y_test, predictions)

print("\n=====================================")
print("SCAM / SAFE MODEL EVALUATION")
print("=====================================")

print(f"Accuracy: {accuracy:.2%}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))


# =====================================
# STEP 5: SAVE SCAM / SAFE MODEL
# =====================================

joblib.dump(model, "model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\nScam/Safe Model Saved Successfully!")


# =====================================
# STEP 6: PREPARE CATEGORY MODEL
# =====================================

# Select scam messages only
scam_data = data[
    data["label"] == "scam"
].copy()

# Check category column
if "category" not in scam_data.columns:
    raise ValueError(
        "Dataset must contain a 'category' column."
    )

# Remove messages without category labels
scam_data = scam_data.dropna(
    subset=["category"]
)

scam_data["category"] = (
    scam_data["category"].astype(str).str.strip()
)

scam_data = scam_data[
    scam_data["category"] != ""
]

if scam_data["category"].nunique() < 2:
    raise ValueError(
        "At least two scam categories are required "
        "to train the category model."
    )


# =====================================
# STEP 7: TRAIN CATEGORY MODEL
# =====================================

X_category = scam_data["message"]
y_category = scam_data["category"]

category_vectorizer = TfidfVectorizer(
    lowercase=True,
    stop_words="english",
    ngram_range=(1, 2),
    max_features=10000,
    sublinear_tf=True
)

X_category_vectorized = (
    category_vectorizer.fit_transform(X_category)
)

category_model = LogisticRegression(
    max_iter=2000,
    class_weight="balanced",
    random_state=42
)

category_model.fit(
    X_category_vectorized,
    y_category
)


# =====================================
# STEP 8: SAVE CATEGORY MODEL
# =====================================

joblib.dump(
    category_model,
    "category_model.pkl"
)

joblib.dump(
    category_vectorizer,
    "category_vectorizer.pkl"
)

print("\n=====================================")
print("CATEGORY MODEL INFORMATION")
print("=====================================")

print(
    "Available Categories:",
    list(category_model.classes_)
)

print("\nAll Models Saved Successfully!")
print("Training Completed!")