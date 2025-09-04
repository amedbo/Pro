from transformers import pipeline
import re

# --- Named Entity Recognition (NER) for IOCs ---

# Load the NER pipeline once when the module is loaded.
# This is crucial for performance as model loading is slow.
print("Loading NER model for IOC extraction...")
try:
    ner_pipeline = pipeline(
        "ner",
        model="PranavaKailash/CyNER-2.0-DeBERTa-v3-base",
        aggregation_strategy="simple" # Groups word pieces into whole entities
    )
    print("NER model loaded successfully.")
except Exception as e:
    print(f"Failed to load NER model: {e}")
    ner_pipeline = None

# Mapping from model's entity labels to our IndicatorType enum
# This will require inspecting the model's output to get the labels right.
# I'm guessing based on the model card.
ENTITY_TO_IOC_TYPE = {
    "Indicator": "unknown", # Generic indicator, will need further classification
    "Malware": "malware_name", # This isn't in my enum, but I can add it or handle it.
    # ... etc. I will need to refine this.
}

# Regex for validation after NER has proposed an entity
# This adds a layer of verification.
IOC_VALIDATION_PATTERNS = {
    "ipv4": re.compile(r"^((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$"),
    "domain": re.compile(r"^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"),
    "file_hash_sha256": re.compile(r"^[A-Fa-f0-9]{64}$"),
    "url": re.compile(r"^https?://[^\s/$.?#].[^\s]*$"),
}

def classify_indicator_value(value: str) -> str:
    """Classifies a generic 'Indicator' value into a specific type using regex."""
    for ioc_type, pattern in IOC_VALIDATION_PATTERNS.items():
        if pattern.match(value):
            return ioc_type
    return "unknown" # Could not classify

def extract_iocs_with_ner(text: str):
    """
    Extracts Indicators of Compromise from text using a fine-tuned NER model.
    """
    if not ner_pipeline:
        print("NER pipeline not available. Cannot extract IOCs.")
        return []

    print(f"Running NER analysis on text...")
    entities = ner_pipeline(text)
    print(f"Found entities: {entities}")

    iocs = []
    for entity in entities:
        entity_type = entity['entity_group']
        entity_value = entity['word']

        # The model identifies generic 'Indicator' entities. We need to classify them further.
        if entity_type == 'Indicator':
            specific_ioc_type = classify_indicator_value(entity_value)
            if specific_ioc_type != "unknown":
                iocs.append({
                    "indicator_type": specific_ioc_type,
                    "value": entity_value
                })

    return iocs


# --- Zero-Shot Classification for Threat Type ---

# (I will add the classification logic here later in this step)
print("Loading Zero-Shot Classification model...")
try:
    classifier_pipeline = pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    print("Zero-Shot Classification model loaded successfully.")
except Exception as e:
    print(f"Failed to load Zero-Shot model: {e}")
    classifier_pipeline = None

THREAT_CLASSES = ['ransomware', 'phishing', 'apt', 'malware', 'exploit', 'data leak']

def classify_threat(text: str):
    """
    Classifies the threat type based on its description using a zero-shot model.
    """
    if not classifier_pipeline:
        print("Classifier pipeline not available. Cannot classify threat.")
        return "unknown"

    result = classifier_pipeline(text, THREAT_CLASSES)
    # The top score is the most likely class
    top_class = result['labels'][0]
    top_score = result['scores'][0]

    print(f"Classification result: {result['labels']} with scores {result['scores']}")

    # Only accept the classification if the score is reasonably high
    if top_score > 0.5:
        return top_class
    else:
        return "unknown"

if __name__ == '__main__':
    test_text = "We have observed new C2 servers being activated by the ShadowNet APT group. One of the primary servers is located at 198.51.100.23. They are using the domain evil-c2-server.net for communication. Our malware analysis team has identified a new dropper with the SHA256 hash: a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2. This is a classic ransomware attack."

    print("\n" + "="*20)
    print("RUNNING STANDALONE ANALYSIS")
    print("="*20)
    print(f"INPUT TEXT: \n{test_text}\n")

    print("\n--- Testing IOC Extraction ---")
    extracted_iocs = extract_iocs_with_ner(test_text)
    print("\n[RESULT] Extracted IOCs:")
    for ioc in extracted_iocs:
        print(f"- Type: {ioc['indicator_type']}, Value: {ioc['value']}")

    print("\n--- Testing Threat Classification ---")
    threat_class = classify_threat(test_text)
    print(f"\n[RESULT] Classified as: {threat_class}")
    print("\n" + "="*20)
