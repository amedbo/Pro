from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import Dict
import numpy as np

# Import the modules we've created
from data_processing import EXPECTED_FEATURES, load_data_from_stream, extract_features, preprocess_and_normalize
from threat_detector import ThreatDetector

# 1. Initialize the FastAPI app
app = FastAPI(
    title="SecureVPN AI Threat Detection API",
    description="An API to get threat predictions for network traffic.",
    version="0.1.0"
)

# 2. Initialize our Threat Detector model
# In a production environment, you would load a pre-trained model on startup.
try:
    detector = ThreatDetector()
except Exception as e:
    # If TensorFlow or other heavy libraries fail, the app should not start.
    raise RuntimeError(f"Failed to initialize ThreatDetector: {e}")

# 3. Define the Pydantic model for input validation
# This ensures that any request to the /predict endpoint has the correct structure and data types.
class TrafficData(BaseModel):
    packet_size_mean: float
    packet_size_std: float
    packet_interval_mean: float
    packet_interval_std: float
    protocol_type: float
    destination_port: float
    source_port: float
    tcp_flags: float
    payload_entropy: float
    connection_duration: float
    bytes_sent: float
    bytes_received: float
    geolocation_distance: float
    time_of_day: float
    day_of_week: float

    class Config:
        schema_extra = {
            "example": {feature: np.random.rand() for feature in EXPECTED_FEATURES}
        }

# 4. Define the prediction endpoint
@app.post("/predict/", response_model=Dict)
async def predict_threat(traffic_data: TrafficData):
    """
    Accepts network traffic data and returns a threat prediction.
    This is the main integration point for the Go-based network core.
    """
    try:
        # Convert the Pydantic model to a dictionary, then to a DataFrame
        data_dict = traffic_data.dict()
        raw_df = load_data_from_stream(data_dict)

        # Process the data using our modules
        feature_df = extract_features(raw_df)
        normalized_data = preprocess_and_normalize(feature_df)

        # Get a prediction
        score = detector.predict(normalized_data)

        verdict = "Threat" if score > 0.5 else "Normal"

        # Return a detailed response
        return {
            "input_data": data_dict,
            "threat_score": float(score),
            "verdict": verdict
        }
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An internal error occurred: {str(e)}")

# 5. Define a root endpoint for health checks
@app.get("/")
def read_root():
    """A simple health check endpoint."""
    return {"status": "AI Engine is running"}

# To run this server from your terminal:
# uvicorn main:app --reload --host 0.0.0.0 --port 8000
#
# Make sure you are in the 'ai-engine' directory.
