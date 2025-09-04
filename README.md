# Amedbo - Proactive Threat Intelligence Platform

This project is a proof-of-concept for a Proactive and Integrated Threat Intelligence Unit, as envisioned by the user. It provides the core software components for collecting, analyzing, and managing cybersecurity threat intelligence. The platform is built with a powerful Python backend using FastAPI and a simple, interactive frontend.

The key feature of this platform is its "deep and advanced" analysis capability, which uses modern machine learning models to automatically extract intelligence from unstructured text, just like a real cyber intelligence cell would.

## Features

- **RESTful API**: A robust backend API for managing threats and Indicators of Compromise (IOCs).
- **Automated OSINT Collection**: A collector script that simulates gathering data from open sources, parsing it for IOCs, and adding it to the platform.
- **Advanced ML Analysis**:
    - **Named Entity Recognition (NER)**: Uses a fine-tuned cybersecurity transformer model (`PranavaKailash/CyNER-2.0-DeBERTa-v3-base`) to automatically discover IOCs, malware names, threat groups, and more from plain text.
    - **Zero-Shot Classification**: Uses a powerful zero-shot model (`facebook/bart-large-mnli`) to automatically classify threats (e.g., as 'ransomware', 'phishing') based on their description.
- **Interactive Frontend**: A simple, single-page dashboard to view threats, submit new intelligence, and see the results of the automated analysis.

## Project Structure

```
/
|-- backend/
|   |-- app/                # Core FastAPI application
|   |   |-- __init__.py
|   |   |-- main.py         # API endpoints
|   |   |-- models.py       # SQLAlchemy database models
|   |   |-- schemas.py      # Pydantic data schemas
|   |   |-- crud.py         # Database interaction logic
|   |   |-- analyzer.py     # Machine Learning analysis module
|   |-- tests/              # Pytest unit tests
|   |-- collector.py        # Standalone OSINT collector script
|   |-- requirements.txt    # Python dependencies
|-- frontend/
|   |-- index.html          # The single-page frontend application
|-- data/
|   |-- osint_feed.txt      # Sample data for the collector
|-- precache_models.py      # Script to download ML models
|-- README.md               # This file
```

## How to Run

**NOTE:** The ML models are very large. The initial setup will download several gigabytes of data.

### 1. Installation

First, install all the required Python packages:
```bash
pip install -r backend/requirements.txt
```

### 2. Pre-cache the Machine Learning Models

The server may time out on first run while trying to download the models. Run the `precache_models.py` script to download and cache them first.

```bash
python3 precache_models.py
```

### 3. Run the Backend API Server

Once the models are cached, you can run the API server. The project uses an in-memory SQLite database, so no external database is needed. All data will be reset when the server restarts.

```bash
PYTHONPATH=. uvicorn backend.app.main:app --host 0.0.0.0 --port 8000
```
The server will be available at `http://127.0.0.1:8000`.

### 4. Use the Frontend Dashboard

Open the `frontend/index.html` file in a modern web browser. The dashboard will connect to the running backend server and allow you to interact with the platform.

### 5. Run the OSINT Collector (Optional)

To simulate gathering new intelligence, you can run the collector script while the API server is running.

```bash
python3 backend/collector.py
```

## Running the Tests

To run the unit tests, use `pytest` from the root directory:

```bash
PYTHONPATH=. pytest
```
