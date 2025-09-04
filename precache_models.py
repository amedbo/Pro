from transformers import pipeline

print("Starting model pre-caching process...")

print("Caching NER model: PranavaKailash/CyNER-2.0-DeBERTa-v3-base")
try:
    pipeline(
        "ner",
        model="PranavaKailash/CyNER-2.0-DeBERTa-v3-base"
    )
    print("NER model cached successfully.")
except Exception as e:
    print(f"An error occurred while caching NER model: {e}")


print("Caching Zero-Shot model: facebook/bart-large-mnli")
try:
    pipeline("zero-shot-classification", model="facebook/bart-large-mnli")
    print("Zero-Shot model cached successfully.")
except Exception as e:
    print(f"An error occurred while caching Zero-Shot model: {e}")

print("Pre-caching process finished.")
