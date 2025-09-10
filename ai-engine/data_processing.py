import numpy as np
import pandas as pd
from sklearn.preprocessing import MinMaxScaler

# A list of expected features, based on the initial project description.
# This serves as a contract for the data that this module expects.
EXPECTED_FEATURES = [
    'packet_size_mean',
    'packet_size_std',
    'packet_interval_mean',
    'packet_interval_std',
    'protocol_type',
    'destination_port',
    'source_port',
    'tcp_flags',
    'payload_entropy',
    'connection_duration',
    'bytes_sent',
    'bytes_received',
    'geolocation_distance',
    'time_of_day',
    'day_of_week'
]

def load_data_from_stream(data_stream: dict) -> pd.DataFrame:
    """
    Loads network traffic data from a dictionary (simulating a stream).

    In a real system, this would consume a live stream of data from the
    core network components via the API.

    Args:
        data_stream: A dictionary representing a single data point.

    Returns:
        A pandas DataFrame containing the raw network data.
    """
    print("Simulating loading data from a stream...")
    df = pd.DataFrame([data_stream])
    return df

def extract_features(raw_data: pd.DataFrame) -> pd.DataFrame:
    """
    Extracts and engineers features from the raw data.

    This function ensures that the data conforms to the expected feature set.
    Future feature engineering logic would be added here.

    Args:
        raw_data: A pandas DataFrame with raw network data.

    Returns:
        A pandas DataFrame with the engineered features.
    """
    # For now, we assume the raw data already contains the expected features.
    # We'll just validate that all expected columns are present.
    missing_cols = set(EXPECTED_FEATURES) - set(raw_data.columns)
    if missing_cols:
        raise ValueError(f"Missing expected feature columns: {missing_cols}")

    print("Feature extraction successful.")
    return raw_data[EXPECTED_FEATURES]

def preprocess_and_normalize(features: pd.DataFrame) -> np.ndarray:
    """
    Preprocesses the features and normalizes them for the neural network.

    This typically involves scaling numerical features to a common range (e.g., 0-1).

    Args:
        features: A pandas DataFrame of features.

    Returns:
        A numpy array of normalized data, ready for the model.
    """
    # NOTE: In a real application, the scaler should be fitted on the training
    # data and saved. For inference, you would load and use the *same* scaler
    # to transform new data, not fit it again. This is a simplification.
    scaler = MinMaxScaler()
    normalized_data = scaler.fit_transform(features)

    print("Data preprocessing and normalization complete.")
    return normalized_data

if __name__ == '__main__':
    # Example usage of the module for a single prediction
    print("--- Running Data Processing Module Standalone Example ---")

    # 1. Simulate incoming data from the network core
    sample_data_point = {feature: np.random.rand() for feature in EXPECTED_FEATURES}

    # 2. Load data from the simulated stream
    raw_df = load_data_from_stream(sample_data_point)
    print(f"Loaded 1 record.")

    # 3. Extract features
    feature_df = extract_features(raw_df)
    print(f"Extracted {len(feature_df.columns)} features.")

    # 4. Preprocess and normalize
    processed_data = preprocess_and_normalize(feature_df)
    print(f"Processed data shape: {processed_data.shape}")
    print("--- Example Run Complete ---")
