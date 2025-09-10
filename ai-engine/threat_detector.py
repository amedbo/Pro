import tensorflow as tf
from tensorflow.keras.layers import Input, Dense, Dropout, BatchNormalization
from tensorflow.keras.models import Model
from tensorflow.keras.optimizers import Adam
import numpy as np

# Import from our other module to show linkage
from data_processing import EXPECTED_FEATURES, preprocess_and_normalize, load_data_from_stream

class ThreatDetector:
    """
    Manages the threat detection model, including its architecture,
    training, and prediction.
    """
    def __init__(self, model_path: str = None):
        """
        Initializes the ThreatDetector.

        Args:
            model_path: Optional path to a pre-trained model file. If None,
                        a new, untrained model is created.
        """
        self.input_shape = (len(EXPECTED_FEATURES),)
        if model_path:
            print(f"Loading pre-trained model from {model_path}...")
            # In a real implementation:
            # self.model = tf.keras.models.load_model(model_path)
            self.model = self._build_model() # Fallback for now
        else:
            print("Building a new, untrained model...")
            self.model = self._build_model()

        self.model.summary()

    def _build_model(self) -> Model:
        """
        Builds the sophisticated neural network for threat detection.
        """
        # Using the Keras Functional API for a more flexible architecture
        inputs = Input(shape=self.input_shape)

        # Layer 1
        x = Dense(256, activation='relu')(inputs)
        x = BatchNormalization()(x)
        x = Dropout(0.4)(x)

        # Layer 2
        x = Dense(128, activation='relu')(x)
        x = BatchNormalization()(x)
        x = Dropout(0.3)(x)

        # Layer 3
        x = Dense(64, activation='relu')(x)

        # Output Layer
        outputs = Dense(1, activation='sigmoid')(x)

        model = Model(inputs=inputs, outputs=outputs)

        model.compile(
            optimizer=Adam(learning_rate=0.001),
            loss='binary_crossentropy',
            metrics=['accuracy', tf.keras.metrics.Precision(), tf.keras.metrics.Recall()]
        )

        return model

    def predict(self, preprocessed_data: np.ndarray) -> float:
        """
        Makes a threat prediction on preprocessed data.

        Args:
            preprocessed_data: A numpy array of normalized data.

        Returns:
            A float representing the threat score (0.0 to 1.0).
        """
        if preprocessed_data.shape[1] != self.input_shape[0]:
            raise ValueError(f"Input data has {preprocessed_data.shape[1]} features, but model expects {self.input_shape[0]}")

        prediction = self.model.predict(preprocessed_data, verbose=0)
        return prediction[0][0]

    def train(self, X_train: np.ndarray, y_train: np.ndarray, epochs: int = 10):
        """
        A placeholder for the model training logic.
        """
        print(f"\n--- Simulating Model Training ---")
        print(f"Training with {len(X_train)} samples for {epochs} epochs.")
        # In a real scenario, the following line would be executed:
        # self.model.fit(X_train, y_train, epochs=epochs, validation_split=0.2)
        print("Model training simulation complete.")
        # self.model.save('threat_detector_model.h5')


if __name__ == '__main__':
    print("\n--- Running Threat Detector Module Standalone Example ---")

    # 1. Initialize the detector
    detector = ThreatDetector()

    # 2. Simulate incoming data and process it
    sample_data_point = {feature: np.random.rand() for feature in EXPECTED_FEATURES}
    raw_df = load_data_from_stream(sample_data_point)
    processed_data = preprocess_and_normalize(raw_df[EXPECTED_FEATURES])

    # 3. Make a prediction
    threat_score = detector.predict(processed_data)
    print(f"\nPredicted Threat Score: {threat_score:.4f}")
    if threat_score > 0.5:
        print("Verdict: Threat Detected")
    else:
        print("Verdict: No Threat Detected")

    # 4. Simulate training
    num_samples = 1000
    X_dummy = np.random.rand(num_samples, len(EXPECTED_FEATURES))
    y_dummy = np.random.randint(0, 2, size=(num_samples, 1))
    detector.train(X_dummy, y_dummy)
