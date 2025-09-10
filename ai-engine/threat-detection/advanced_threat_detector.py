# ai-engine/threat-detection/advanced_threat_detector.py
import numpy as np
import tensorflow as tf
from sklearn.ensemble import IsolationForest
import joblib
from federated_learning import FederatedAIModel

class AdvancedThreatDetector:
    def __init__(self, use_federated_learning=True):
        self.local_model = self.build_advanced_neural_network()
        self.anomaly_detector = IsolationForest(contamination=0.1, random_state=42)
        self.is_trained = False

        # Federated learning for privacy-preserving AI
        if use_federated_learning:
            self.federated_model = FederatedAIModel()

    def build_advanced_neural_network(self):
        """Build a more sophisticated neural network for threat detection"""
        model = tf.keras.Sequential([
            tf.keras.layers.Dense(256, activation='relu', input_shape=(15,)),
            tf.keras.layers.Dropout(0.4),
            tf.keras.layers.BatchNormalization(),
            tf.keras.layers.Dense(128, activation='relu'),
            tf.keras.layers.Dropout(0.3),
            tf.keras.layers.Dense(64, activation='relu'),
            tf.keras.layers.Dense(32, activation='relu'),
            tf.keras.layers.Dense(1, activation='sigmoid')
        ])

        model.compile(
            optimizer=tf.keras.optimizers.Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )
        return model

    def extract_advanced_features(self, network_data):
        """Extract comprehensive features from network data for analysis"""
        features = [
            network_data['packet_size_mean'],
            network_data['packet_size_std'],
            network_data['packet_interval_mean'],
            network_data['packet_interval_std'],
            network_data['protocol_type'],
            network_data['destination_port'],
            network_data['source_port'],
            network_data['tcp_flags'],
            network_data['payload_entropy'],
            network_data['connection_duration'],
            network_data['bytes_sent'],
            network_data['bytes_received'],
            network_data['geolocation_distance'],
            network_data['time_of_day'],
            network_data['day_of_week']
        ]
        return np.array(features).reshape(1, -1)

    def detect_threat(self, network_data):
        """Detect threats using ensemble AI methods"""
        features = self.extract_advanced_features(network_data)

        # Deep learning prediction
        dl_prediction = self.local_model.predict(features, verbose=0)[0][0]

        # Anomaly detection
        anomaly_score = self.anomaly_detector.decision_function(features)[0]

        # Federated learning consensus (if enabled)
        if hasattr(self, 'federated_model'):
            fl_prediction = self.federated_model.predict(features)
            # Combine predictions with weighted average
            threat_score = 0.6 * dl_prediction + 0.2 * (1 - anomaly_score) + 0.2 * fl_prediction
        else:
            threat_score = 0.7 * dl_prediction + 0.3 * (1 - anomaly_score)

        return threat_score > 0.5, threat_score

    def train_federated(self, local_data):
        """Train using federated learning approach"""
        if hasattr(self, 'federated_model'):
            model_update = self.federated_model.train_round(local_data)
            return model_update
        return None

    def update_with_global_model(self, global_model_weights):
        """Update local model with global federated weights"""
        if hasattr(self, 'federated_model'):
            self.federated_model.update_weights(global_model_weights)
