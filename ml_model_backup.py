"""
Network Anomaly Detection System with Baseline Collection and Detection Modes
Implements adaptive learning system with automatic mode switching
"""

import logging
import joblib
import json
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import precision_score, recall_score, f1_score

from config.config import config


class NetworkAnomalyDetector:
    """
    Network Anomaly Detection System with two modes:
    1. Baseline Collection Mode: Collects normal traffic data
    2. Detection Mode: Performs anomaly detection on incoming traffic
    """
    
    def __init__(self, model_dir: str = "models"):
        """Initialize the anomaly detector"""
        self.model_dir = Path(model_dir)
        self.model_dir.mkdir(parents=True, exist_ok=True)
        
        # Model file paths
        self.untrained_model_path = self.model_dir / "untrained_model.pkl"
        self.baseline_model_path = self.model_dir / "baseline_model.pkl"
        self.scaler_path = self.model_dir / "scaler.pkl"
        self.metadata_path = self.model_dir / "model_metadata.json"
        
        # Model components
        self.model = None
        self.scaler = StandardScaler()
        self.is_trained = False
        self.mode = "baseline_collection"  # "baseline_collection" or "detection"
        
        # Configuration
        self.min_baseline_samples = config.get('ml.min_baseline_samples', 1000)
        self.contamination = config.get('ml.contamination', 0.1)
        self.baseline_data = []
        
        # Initialize the system
        self._initialize_system()
        
        logging.info(f"NetworkAnomalyDetector initialized in {self.mode} mode")
    
    def _initialize_system(self):
        """Initialize the system by checking for existing models"""
        # Check if baseline model exists
        if self.baseline_model_path.exists():
            logging.info("Found existing baseline model, loading...")
            if self._load_baseline_model():
                self.mode = "detection"
                self.is_trained = True
                logging.info("System initialized in DETECTION MODE")
            else:
                logging.warning("Failed to load baseline model, falling back to collection mode")
                self._create_untrained_model()
        else:
            # Check if untrained model exists, if not create it
            if not self.untrained_model_path.exists():
                self._create_untrained_model()
            
            self._load_untrained_model()
            self.mode = "baseline_collection"
            self.is_trained = False
            logging.info("System initialized in BASELINE COLLECTION MODE")
    
    def _create_untrained_model(self):
        """Create and save an untrained IsolationForest model"""
        try:
            untrained_model = IsolationForest(
                contamination=self.contamination,
                random_state=42,
                n_jobs=-1
            )
            
            # Save the untrained model
            joblib.dump(untrained_model, self.untrained_model_path)
            
            # Save initial metadata
            metadata = {
                'created_at': datetime.utcnow().isoformat(),
                'model_type': 'IsolationForest',
                'contamination': self.contamination,
                'is_trained': False,
                'baseline_samples_collected': 0,
                'mode': 'baseline_collection'
            }
            
            with open(self.metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            
            logging.info(f"Created untrained model: {self.untrained_model_path}")
            
        except Exception as e:
            logging.error(f"Error creating untrained model: {e}")
            raise
    
    def _load_untrained_model(self):
        """Load the untrained model"""
        try:
            self.model = joblib.load(self.untrained_model_path)
            logging.info("Loaded untrained model")
        except Exception as e:
            logging.error(f"Error loading untrained model: {e}")
            self._create_untrained_model()
            self.model = joblib.load(self.untrained_model_path)
    
    def _load_baseline_model(self):
        """Load the trained baseline model"""
        try:
            self.model = joblib.load(self.baseline_model_path)
            
            # Load scaler if it exists
            if self.scaler_path.exists():
                self.scaler = joblib.load(self.scaler_path)
            
            # Load metadata
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r') as f:
                    metadata = json.load(f)
                    logging.info(f"Loaded model trained on {metadata.get('baseline_samples_collected', 0)} samples")
            
            logging.info("Successfully loaded baseline model")
            return True
            
        except Exception as e:
            logging.error(f"Error loading baseline model: {e}")
            return False
    
    def add_baseline_sample(self, features: List[float]) -> Dict[str, Any]:
        """
        Add a sample to the baseline collection
        
        Args:
            features: Feature vector representing normal network traffic
            
        Returns:
            Status information about baseline collection
        """
        if self.mode != "baseline_collection":
            return {
                'error': 'System is not in baseline collection mode',
                'mode': self.mode
            }
        
        try:
            # Add to baseline data
            self.baseline_data.append(features)
            
            samples_collected = len(self.baseline_data)
            
            # Update metadata
            self._update_metadata({
                'baseline_samples_collected': samples_collected,
                'last_sample_added': datetime.utcnow().isoformat()
            })
            
            # Check if we have enough samples to train
            if samples_collected >= self.min_baseline_samples:
                logging.info(f"Collected {samples_collected} baseline samples, ready for training")
                return {
                    'samples_collected': samples_collected,
                    'min_required': self.min_baseline_samples,
                    'ready_for_training': True,
                    'progress': 100.0
                }
            else:
                progress = (samples_collected / self.min_baseline_samples) * 100
                return {
                    'samples_collected': samples_collected,
                    'min_required': self.min_baseline_samples,
                    'ready_for_training': False,
                    'progress': progress
                }
                
        except Exception as e:
            logging.error(f"Error adding baseline sample: {e}")
            return {'error': str(e)}
    
    def train_baseline_model(self) -> Dict[str, Any]:
        """
        Train the baseline model and switch to detection mode
        
        Returns:
            Training results and status
        """
        if self.mode != "baseline_collection":
            return {
                'error': 'System is not in baseline collection mode',
                'mode': self.mode
            }
        
        if len(self.baseline_data) < self.min_baseline_samples:
            return {
                'error': f'Insufficient baseline samples. Have {len(self.baseline_data)}, need {self.min_baseline_samples}',
                'samples_needed': self.min_baseline_samples - len(self.baseline_data)
            }
        
        try:
            logging.info(f"Training baseline model with {len(self.baseline_data)} samples")
            
            # Convert to numpy array
            X = np.array(self.baseline_data)
            
            # Fit scaler
            X_scaled = self.scaler.fit_transform(X)
            
            # Train the model
            self.model.fit(X_scaled)
            
            # Save the trained model
            joblib.dump(self.model, self.baseline_model_path)
            joblib.dump(self.scaler, self.scaler_path)
            
            # Update metadata
            training_metadata = {
                'trained_at': datetime.utcnow().isoformat(),
                'training_samples': len(self.baseline_data),
                'is_trained': True,
                'mode': 'detection',
                'model_type': 'IsolationForest',
                'contamination': self.contamination
            }
            
            self._update_metadata(training_metadata)
            
            # Switch to detection mode
            self.mode = "detection"
            self.is_trained = True
            
            # Clear baseline data to free memory
            self.baseline_data = []
            
            logging.info("Successfully trained baseline model and switched to DETECTION MODE")
            
            return {
                'success': True,
                'training_samples': len(X),
                'mode': self.mode,
                'trained_at': training_metadata['trained_at']
            }
            
        except Exception as e:
            logging.error(f"Error training baseline model: {e}")
            return {'error': str(e)}
    
    def predict_anomaly(self, features: List[float]) -> Dict[str, Any]:
        """
        Predict if the given features represent an anomaly
        
        Args:
            features: Feature vector to analyze
            
        Returns:
            Prediction results
        """
        if self.mode != "detection":
            return {
                'error': 'System is not in detection mode',
                'mode': self.mode,
                'suggestion': 'Complete baseline collection first'
            }
        
        if not self.is_trained:
            return {
                'error': 'Model is not trained',
                'mode': self.mode
            }
        
        try:
            # Convert to numpy array and reshape
            X = np.array(features).reshape(1, -1)
            
            # Scale features
            X_scaled = self.scaler.transform(X)
            
            # Make prediction
            prediction = self.model.predict(X_scaled)[0]
            anomaly_score = self.model.decision_function(X_scaled)[0]
            
            # Convert prediction (-1 for anomaly, 1 for normal)
            is_anomaly = prediction == -1
            
            return {
                'is_anomaly': bool(is_anomaly),
                'anomaly_score': float(anomaly_score),
                'prediction': int(prediction),
                'confidence': abs(float(anomaly_score)),
                'timestamp': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Error predicting anomaly: {e}")
            return {'error': str(e)}
    
    def reset_system(self) -> Dict[str, Any]:
        """
        Reset the system to empty model state by deleting the baseline model
        
        Returns:
            Reset operation status
        """
        try:
            # Delete baseline model files
            files_deleted = []
            
            if self.baseline_model_path.exists():
                self.baseline_model_path.unlink()
                files_deleted.append("baseline_model.pkl")
            
            if self.scaler_path.exists():
                self.scaler_path.unlink()
                files_deleted.append("scaler.pkl")
            
            # Reset system state
            self.is_trained = False
            self.mode = "baseline_collection"
            self.baseline_data = []
            
            # Load untrained model
            self._load_untrained_model()
            
            # Update metadata
            self._update_metadata({
                'reset_at': datetime.utcnow().isoformat(),
                'is_trained': False,
                'mode': 'baseline_collection',
                'baseline_samples_collected': 0
            })
            
            logging.info("System reset to baseline collection mode")
            
            return {
                'success': True,
                'files_deleted': files_deleted,
                'mode': self.mode,
                'is_trained': self.is_trained,
                'reset_at': datetime.utcnow().isoformat()
            }
            
        except Exception as e:
            logging.error(f"Error resetting system: {e}")
            return {'error': str(e)}
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get current system status and statistics"""
        try:
            # Load current metadata
            metadata = {}
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r') as f:
                    metadata = json.load(f)
            
            status = {
                'mode': self.mode,
                'is_trained': self.is_trained,
                'baseline_samples_collected': len(self.baseline_data) if self.mode == "baseline_collection" else metadata.get('baseline_samples_collected', 0),
                'min_baseline_samples': self.min_baseline_samples,
                'model_exists': self.baseline_model_path.exists(),
                'untrained_model_exists': self.untrained_model_path.exists(),
                'files': {
                    'baseline_model': self.baseline_model_path.exists(),
                    'untrained_model': self.untrained_model_path.exists(),
                    'scaler': self.scaler_path.exists(),
                    'metadata': self.metadata_path.exists()
                }
            }
            
            # Add progress information
            if self.mode == "baseline_collection":
                samples = len(self.baseline_data)
                status['progress'] = {
                    'samples_collected': samples,
                    'samples_needed': max(0, self.min_baseline_samples - samples),
                    'percentage': min(100.0, (samples / self.min_baseline_samples) * 100),
                    'ready_for_training': samples >= self.min_baseline_samples
                }
            
            # Add metadata information
            status.update(metadata)
            
            return status
            
        except Exception as e:
            logging.error(f"Error getting system status: {e}")
            return {'error': str(e)}
    
    def _update_metadata(self, updates: Dict[str, Any]):
        """Update metadata file with new information"""
        try:
            metadata = {}
            if self.metadata_path.exists():
                with open(self.metadata_path, 'r') as f:
                    metadata = json.load(f)
            
            metadata.update(updates)
            metadata['last_updated'] = datetime.utcnow().isoformat()
            
            with open(self.metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
                
        except Exception as e:
            logging.error(f"Error updating metadata: {e}")


class MLModelManager:
    """
    High-level ML Model Manager that wraps the NetworkAnomalyDetector
    Provides compatibility with existing code while adding new functionality
    """
    
    def __init__(self):
        self.detector = NetworkAnomalyDetector()
        logging.info("MLModelManager initialized")
    
    def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        return self.detector.get_system_status()
    
    def add_baseline_sample(self, features: List[float]) -> Dict[str, Any]:
        """Add a baseline sample (wrapper method)"""
        return self.detector.add_baseline_sample(features)
    
    def train_baseline_model(self) -> Dict[str, Any]:
        """Train the baseline model (wrapper method)"""
        return self.detector.train_baseline_model()
    
    def predict_anomaly(self, features) -> Dict[str, Any]:
        """Predict anomaly (wrapper method with flexible input)"""
        # Handle different input types
        if isinstance(features, dict):
            feature_list = list(features.values())
        elif isinstance(features, (list, tuple)):
            feature_list = list(features)
        elif isinstance(features, np.ndarray):
            feature_list = features.flatten().tolist()
        else:
            feature_list = [float(features)]
        
        return self.detector.predict_anomaly(feature_list)
    
    def reset_system(self) -> Dict[str, Any]:
        """Reset system (wrapper method)"""
        return self.detector.reset_system()
    
    def get_mode(self) -> str:
        """Get current operating mode"""
        return self.detector.mode
    
    def is_trained(self) -> bool:
        """Check if model is trained"""
        return self.detector.is_trained
    
    def can_detect_anomalies(self) -> bool:
        """Check if system can detect anomalies"""
        return self.detector.mode == "detection" and self.detector.is_trained
    
    def get_baseline_progress(self) -> Dict[str, Any]:
        """Get baseline collection progress"""
        status = self.detector.get_system_status()
        return status.get('progress', {})
    
    # Compatibility methods for existing code
    def train_models(self, training_data=None) -> bool:
        """Legacy compatibility method"""
        if self.detector.mode == "baseline_collection":
            result = self.detector.train_baseline_model()
            return result.get('success', False)
        return True
    
    def get_model_status(self) -> Dict[str, Any]:
        """Legacy compatibility method"""
        status = self.detector.get_system_status()
        return {
            'is_trained': status['is_trained'],
            'mode': status['mode'],
            'model_exists': status['model_exists']
        }


# Global instance
ml_model_manager = MLModelManager()
    """Mock autoencoder neural network for anomaly detection"""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        """
        Initialize mock autoencoder
        
        Args:
            input_dim: Input dimension
            encoding_dim: Encoding dimension
        """
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.threshold = 0.1
        self.scaler = StandardScaler()
        self.is_trained = False
    
    def build_model(self) -> None:
        """Mock build autoencoder model"""
        logging.info("Mock AutoEncoder model built")
        self.model = "mock_model"  # Mock model placeholder
    
    def fit(self, X: np.ndarray, validation_split: float = 0.2, epochs: int = 100) -> Dict[str, Any]:
        """
        Mock train the autoencoder
        
        Args:
            X: Training data
            validation_split: Validation split ratio
            epochs: Number of epochs
            
        Returns:
            Mock training history
        """
        try:
            logging.info(f"Mock AutoEncoder training on {X.shape[0]} samples for {epochs} epochs")
            
            # Scale data
            X_scaled = self.scaler.fit_transform(X)
            
            # Mock training process
            if self.model is None:
                self.build_model()
            
            # Mock reconstruction errors for threshold calculation
            reconstruction_errors = np.random.random(len(X_scaled)) * 0.2
            self.threshold = np.percentile(reconstruction_errors, 95)
            self.is_trained = True
            
            # Mock training history
            history = {
                'loss': [0.1 - i*0.001 for i in range(epochs)],
                'val_loss': [0.12 - i*0.0012 for i in range(epochs)]
            }
            
            logging.info(f"Mock AutoEncoder training completed. Threshold: {self.threshold:.4f}")
            return history
            
        except Exception as e:
            logging.error(f"Mock AutoEncoder training error: {e}")
            return {'loss': [], 'val_loss': []}
    
    def predict(self, X: np.ndarray) -> np.ndarray:
        """
        Mock predict reconstruction errors
        
        Args:
            X: Input data
            
        Returns:
            Mock reconstruction errors
        """
        try:
            if not self.is_trained:
                logging.warning("Mock AutoEncoder not trained, training with provided data")
                self.fit(X)
            
            X_scaled = self.scaler.transform(X)
            
            # Mock reconstruction errors - random values with some pattern
            reconstruction_errors = np.random.random(len(X_scaled)) * 0.3
            
            return reconstruction_errors
            
        except Exception as e:
            logging.error(f"Mock AutoEncoder prediction error: {e}")
            return np.zeros(len(X))
    
    def save(self, filepath: str) -> None:
        """Mock save autoencoder"""
        try:
            # Save metadata
            metadata = {
                'input_dim': self.input_dim,
                'encoding_dim': self.encoding_dim,
                'threshold': self.threshold,
                'is_trained': self.is_trained
            }
            
            with open(f"{filepath}_metadata.json", 'w') as f:
                json.dump(metadata, f, indent=2)
            
            # Save scaler
            joblib.dump(self.scaler, f"{filepath}_scaler.pkl")
            
            logging.info(f"Mock AutoEncoder saved to {filepath}")
            
        except Exception as e:
            logging.error(f"Error saving mock AutoEncoder: {e}")
    
    def load(self, filepath: str) -> bool:
        """Mock load autoencoder"""
        try:
            # Load metadata
            with open(f"{filepath}_metadata.json", 'r') as f:
                metadata = json.load(f)
            
            self.input_dim = metadata['input_dim']
            self.encoding_dim = metadata['encoding_dim']
            self.threshold = metadata['threshold']
            self.is_trained = metadata['is_trained']
            
            # Load scaler
            self.scaler = joblib.load(f"{filepath}_scaler.pkl")
            
            # Mock model
            self.model = "mock_model_loaded"
            
            logging.info(f"Mock AutoEncoder loaded from {filepath}")
            return True
            
        except Exception as e:
            logging.error(f"Error loading mock AutoEncoder: {e}")
            return False
        """
        Train the autoencoder
        
        Args:
            X: Training data
            validation_split: Validation split ratio
            epochs: Number of epochs
            
        Returns:
            Training history
        """
        try:
            # Scale the data
            X_scaled = self.scaler.fit_transform(X)
            
            # Build model if not already built
            if self.model is None:
                self.build_model()
            
            # Early stopping callback
            early_stopping = EarlyStopping(
                monitor='val_loss',
                patience=10,
                restore_best_weights=True
            )
            
            # Train the model
            history = self.model.fit(
                X_scaled, X_scaled,
                epochs=epochs,
                batch_size=32,
                validation_split=validation_split,
                callbacks=[early_stopping],
                verbose=0
            )
            
            # Calculate reconstruction threshold
            reconstructions = self.model.predict(X_scaled, verbose=0)
            mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
            self.threshold = np.percentile(mse, 95)  # 95th percentile as threshold
            
            return {
                'loss': history.history['loss'][-1],
                'val_loss': history.history['val_loss'][-1],
                'threshold': self.threshold
            }
            
        except Exception as e:
            logging.error(f"Error training autoencoder: {e}")
            return {}
    
    def predict(self, X: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        """
        Predict anomalies
        
        Args:
            X: Input data
            
        Returns:
            Tuple of (anomaly_scores, predictions)
        """
        try:
            X_scaled = self.scaler.transform(X)
            reconstructions = self.model.predict(X_scaled, verbose=0)
            
            # Calculate reconstruction error
            mse = np.mean(np.power(X_scaled - reconstructions, 2), axis=1)
            
            # Normalize scores to 0-1 range
            if self.threshold and self.threshold > 0:
                anomaly_scores = mse / self.threshold
            else:
                anomaly_scores = mse
            
            # Binary predictions
            predictions = (mse > self.threshold).astype(int) if self.threshold else np.zeros(len(mse))
            
            return anomaly_scores, predictions
            
        except Exception as e:
            logging.error(f"Error predicting with autoencoder: {e}")
            return np.array([]), np.array([])
    
    def save(self, filepath: str) -> None:
        """Save model to file"""
        try:
            model_dir = Path(filepath).parent
            model_dir.mkdir(parents=True, exist_ok=True)
            
            # Save Keras model
            self.model.save(f"{filepath}_model.h5")
            
            # Save scaler and threshold
            joblib.dump({
                'scaler': self.scaler,
                'threshold': self.threshold,
                'input_dim': self.input_dim,
                'encoding_dim': self.encoding_dim
            }, f"{filepath}_params.pkl")
            
        except Exception as e:
            logging.error(f"Error saving autoencoder: {e}")
    
    def load(self, filepath: str) -> None:
        """Load model from file"""
        try:
            # Load Keras model
            self.model = load_model(f"{filepath}_model.h5")
            
            # Load scaler and threshold
            params = joblib.load(f"{filepath}_params.pkl")
            self.scaler = params['scaler']
            self.threshold = params['threshold']
            self.input_dim = params['input_dim']
            self.encoding_dim = params['encoding_dim']
            
        except Exception as e:
            logging.error(f"Error loading autoencoder: {e}")

class EnsembleAnomalyDetector:
    """Ensemble model combining multiple anomaly detection algorithms"""
    
    def __init__(self):
        """Initialize ensemble detector"""
        self.isolation_forest = None
        self.one_class_svm = None
        self.autoencoder = None
        self.scaler = RobustScaler()
        self.feature_selector = None
        self.models = {}
        self.thresholds = {}
        self.weights = {'isolation_forest': 0.4, 'one_class_svm': 0.3, 'autoencoder': 0.3}
        
    def _prepare_data(self, X: np.ndarray) -> np.ndarray:
        """
        Prepare data for training/prediction
        
        Args:
            X: Input data
            
        Returns:
            Preprocessed data
        """
        # Handle missing values
        X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
        
        # Scale features
        X_scaled = self.scaler.transform(X)
        
        # Feature selection
        if self.feature_selector:
            X_scaled = self.feature_selector.transform(X_scaled)
        
        return X_scaled
    
    def fit(self, X: np.ndarray, y: Optional[np.ndarray] = None) -> Dict[str, Any]:
        """
        Train the ensemble model
        
        Args:
            X: Training data
            y: Labels (optional, for semi-supervised learning)
            
        Returns:
            Training metrics
        """
        try:
            logging.info(f"Training ensemble model with {X.shape[0]} samples, {X.shape[1]} features")
            
            # Handle missing values
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            # Scale features
            X_scaled = self.scaler.fit_transform(X)
            
            # Feature selection
            n_features = min(config.get('machine_learning.features.n_features', 50), X_scaled.shape[1])
            if X_scaled.shape[1] > n_features and y is not None:
                self.feature_selector = SelectKBest(score_func=f_classif, k=n_features)
                X_scaled = self.feature_selector.fit_transform(X_scaled, y)
            else:
                # Use all features if no labels or fewer features than target
                self.feature_selector = None
            
            training_results = {}
            
            # Train Isolation Forest
            try:
                if_config = config.get('machine_learning.models.isolation_forest', {})
                self.isolation_forest = IsolationForest(
                    contamination=if_config.get('contamination', 0.1),
                    n_estimators=if_config.get('n_estimators', 100),
                    random_state=if_config.get('random_state', 42),
                    n_jobs=-1
                )
                self.isolation_forest.fit(X_scaled)
                
                # Calculate threshold
                scores = self.isolation_forest.decision_function(X_scaled)
                self.thresholds['isolation_forest'] = np.percentile(scores, 10)  # 10th percentile
                
                training_results['isolation_forest'] = {'status': 'success'}
                logging.info("Isolation Forest trained successfully")
                
            except Exception as e:
                logging.error(f"Error training Isolation Forest: {e}")
                training_results['isolation_forest'] = {'status': 'failed', 'error': str(e)}
            
            # Train One-Class SVM
            try:
                svm_config = config.get('machine_learning.models.one_class_svm', {})
                self.one_class_svm = OneClassSVM(
                    kernel=svm_config.get('kernel', 'rbf'),
                    gamma=svm_config.get('gamma', 'scale'),
                    nu=svm_config.get('nu', 0.1)
                )
                
                # Use subset for SVM if data is large (SVM doesn't scale well)
                if X_scaled.shape[0] > 10000:
                    indices = np.random.choice(X_scaled.shape[0], 10000, replace=False)
                    X_svm = X_scaled[indices]
                else:
                    X_svm = X_scaled
                
                self.one_class_svm.fit(X_svm)
                
                # Calculate threshold
                scores = self.one_class_svm.decision_function(X_svm)
                self.thresholds['one_class_svm'] = np.percentile(scores, 10)
                
                training_results['one_class_svm'] = {'status': 'success'}
                logging.info("One-Class SVM trained successfully")
                
            except Exception as e:
                logging.error(f"Error training One-Class SVM: {e}")
                training_results['one_class_svm'] = {'status': 'failed', 'error': str(e)}
            
            # Train Autoencoder
            try:
                ae_config = config.get('machine_learning.models.autoencoder', {})
                self.autoencoder = AutoEncoder(
                    input_dim=X_scaled.shape[1],
                    encoding_dim=ae_config.get('encoding_dim', 32)
                )
                
                ae_results = self.autoencoder.fit(
                    X_scaled,
                    validation_split=ae_config.get('validation_split', 0.2),
                    epochs=ae_config.get('epochs', 100)
                )
                
                self.thresholds['autoencoder'] = ae_results.get('threshold', 0.5)
                training_results['autoencoder'] = {'status': 'success', **ae_results}
                logging.info("Autoencoder trained successfully")
                
            except Exception as e:
                logging.error(f"Error training Autoencoder: {e}")
                training_results['autoencoder'] = {'status': 'failed', 'error': str(e)}
            
            # Store models
            self.models = {
                'isolation_forest': self.isolation_forest,
                'one_class_svm': self.one_class_svm,
                'autoencoder': self.autoencoder
            }
            
            return training_results
            
        except Exception as e:
            logging.error(f"Error training ensemble model: {e}")
            return {'error': str(e)}
    
    def predict(self, X: np.ndarray) -> Dict[str, Any]:
        """
        Predict anomalies using ensemble
        
        Args:
            X: Input data
            
        Returns:
            Prediction results
        """
        try:
            X_processed = self._prepare_data(X)
            
            predictions = {}
            scores = {}
            
            # Isolation Forest predictions
            if self.isolation_forest:
                try:
                    if_scores = self.isolation_forest.decision_function(X_processed)
                    if_predictions = (if_scores < self.thresholds['isolation_forest']).astype(int)
                    predictions['isolation_forest'] = if_predictions
                    scores['isolation_forest'] = if_scores
                except Exception as e:
                    logging.error(f"Error with Isolation Forest prediction: {e}")
            
            # One-Class SVM predictions
            if self.one_class_svm:
                try:
                    svm_scores = self.one_class_svm.decision_function(X_processed)
                    svm_predictions = (svm_scores < self.thresholds['one_class_svm']).astype(int)
                    predictions['one_class_svm'] = svm_predictions
                    scores['one_class_svm'] = svm_scores
                except Exception as e:
                    logging.error(f"Error with One-Class SVM prediction: {e}")
            
            # Autoencoder predictions
            if self.autoencoder:
                try:
                    ae_scores, ae_predictions = self.autoencoder.predict(X_processed)
                    predictions['autoencoder'] = ae_predictions
                    scores['autoencoder'] = ae_scores
                except Exception as e:
                    logging.error(f"Error with Autoencoder prediction: {e}")
            
            # Ensemble predictions
            ensemble_scores = np.zeros(X.shape[0])
            ensemble_predictions = np.zeros(X.shape[0])
            total_weight = 0
            
            for model_name, weight in self.weights.items():
                if model_name in predictions:
                    ensemble_scores += weight * self._normalize_scores(scores[model_name])
                    ensemble_predictions += weight * predictions[model_name]
                    total_weight += weight
            
            if total_weight > 0:
                ensemble_scores /= total_weight
                ensemble_predictions = (ensemble_predictions / total_weight > 
                                      config.get('detection.thresholds.ensemble', 0.6)).astype(int)
            
            return {
                'ensemble_scores': ensemble_scores,
                'ensemble_predictions': ensemble_predictions,
                'individual_scores': scores,
                'individual_predictions': predictions
            }
            
        except Exception as e:
            logging.error(f"Error in ensemble prediction: {e}")
            return {
                'ensemble_scores': np.array([]),
                'ensemble_predictions': np.array([]),
                'individual_scores': {},
                'individual_predictions': {}
            }
    
    def _normalize_scores(self, scores: np.ndarray) -> np.ndarray:
        """Normalize scores to 0-1 range"""
        try:
            if len(scores) == 0:
                return scores
            
            min_score = np.min(scores)
            max_score = np.max(scores)
            
            if max_score > min_score:
                return (scores - min_score) / (max_score - min_score)
            else:
                return np.zeros_like(scores)
        except:
            return np.zeros_like(scores)
    
    def evaluate(self, X: np.ndarray, y: np.ndarray) -> Dict[str, Any]:
        """
        Evaluate model performance
        
        Args:
            X: Test data
            y: True labels
            
        Returns:
            Evaluation metrics
        """
        try:
            results = self.predict(X)
            metrics = {}
            
            # Evaluate ensemble
            ensemble_pred = results['ensemble_predictions']
            if len(ensemble_pred) > 0:
                metrics['ensemble'] = {
                    'precision': precision_score(y, ensemble_pred, zero_division=0),
                    'recall': recall_score(y, ensemble_pred, zero_division=0),
                    'f1_score': f1_score(y, ensemble_pred, zero_division=0)
                }
            
            # Evaluate individual models
            for model_name, predictions in results['individual_predictions'].items():
                if len(predictions) > 0:
                    metrics[model_name] = {
                        'precision': precision_score(y, predictions, zero_division=0),
                        'recall': recall_score(y, predictions, zero_division=0),
                        'f1_score': f1_score(y, predictions, zero_division=0)
                    }
            
            return metrics
            
        except Exception as e:
            logging.error(f"Error evaluating model: {e}")
            return {}
    
    def save(self, filepath: str) -> None:
        """Save ensemble model"""
        try:
            model_dir = Path(filepath).parent
            model_dir.mkdir(parents=True, exist_ok=True)
            
            # Save sklearn models
            if self.isolation_forest:
                joblib.dump(self.isolation_forest, f"{filepath}_isolation_forest.pkl")
            
            if self.one_class_svm:
                joblib.dump(self.one_class_svm, f"{filepath}_one_class_svm.pkl")
            
            # Save autoencoder
            if self.autoencoder:
                self.autoencoder.save(f"{filepath}_autoencoder")
            
            # Save preprocessors and metadata
            joblib.dump({
                'scaler': self.scaler,
                'feature_selector': self.feature_selector,
                'thresholds': self.thresholds,
                'weights': self.weights
            }, f"{filepath}_metadata.pkl")
            
            logging.info(f"Ensemble model saved to {filepath}")
            
        except Exception as e:
            logging.error(f"Error saving ensemble model: {e}")
    
    def load(self, filepath: str) -> None:
        """Load ensemble model"""
        try:
            # Load sklearn models
            if Path(f"{filepath}_isolation_forest.pkl").exists():
                self.isolation_forest = joblib.load(f"{filepath}_isolation_forest.pkl")
            
            if Path(f"{filepath}_one_class_svm.pkl").exists():
                self.one_class_svm = joblib.load(f"{filepath}_one_class_svm.pkl")
            
            # Load autoencoder
            if Path(f"{filepath}_autoencoder_model.h5").exists():
                self.autoencoder = AutoEncoder(input_dim=1, encoding_dim=32)  # Temp values
                self.autoencoder.load(f"{filepath}_autoencoder")
            
            # Load preprocessors and metadata
            metadata = joblib.load(f"{filepath}_metadata.pkl")
            self.scaler = metadata['scaler']
            self.feature_selector = metadata['feature_selector']
            self.thresholds = metadata['thresholds']
            self.weights = metadata['weights']
            
            # Update models dict
            self.models = {
                'isolation_forest': self.isolation_forest,
                'one_class_svm': self.one_class_svm,
                'autoencoder': self.autoencoder
            }
            
            logging.info(f"Ensemble model loaded from {filepath}")
            
        except Exception as e:
            logging.error(f"Error loading ensemble model: {e}")

class MLModelManager:
    """Manages machine learning models and training pipeline"""
    
    def __init__(self):
        """Initialize ML model manager"""
        self.current_model = None
        self.model_history = []
        self.training_data_cache = []
        self.last_training_time = None
        
        # Create models directory
        self.models_dir = Path("models")
        self.models_dir.mkdir(exist_ok=True)
    
    def prepare_training_data(self, days: int = 7) -> Tuple[np.ndarray, np.ndarray, List[str]]:
        """
        Prepare training data from database
        
        Args:
            days: Number of days of data to use
            
        Returns:
            Tuple of (features, labels, feature_names)
        """
        try:
            # Get training data from database
            df = db_manager.get_training_data(days=days)
            
            if df.empty:
                logging.warning("No training data available")
                return np.array([]), np.array([]), []
            
            # Remove non-feature columns
            feature_columns = [col for col in df.columns 
                             if col not in ['timestamp', 'flow_id']]
            
            X = df[feature_columns].values
            
            # For unsupervised learning, we don't have true labels
            # We'll use anomaly detection on historical data or create synthetic labels
            y = np.zeros(len(X))  # Assume all normal for now
            
            # Handle missing values
            X = np.nan_to_num(X, nan=0.0, posinf=0.0, neginf=0.0)
            
            return X, y, feature_columns
            
        except Exception as e:
            logging.error(f"Error preparing training data: {e}")
            return np.array([]), np.array([]), []
    
    def train_model(self, retrain: bool = False) -> Dict[str, Any]:
        """
        Train or retrain the model
        
        Args:
            retrain: Force retraining even if recent model exists
            
        Returns:
            Training results
        """
        try:
            # Check if retraining is needed
            if not retrain and self.last_training_time:
                time_since_training = (datetime.now() - self.last_training_time).total_seconds()
                retrain_interval = config.get('machine_learning.training.retrain_interval', 86400)
                
                if time_since_training < retrain_interval:
                    logging.info("Model training not needed yet")
                    return {'status': 'skipped', 'reason': 'Recent model exists'}
            
            # Prepare training data
            X, y, feature_names = self.prepare_training_data()
            
            if len(X) == 0:
                return {'status': 'failed', 'reason': 'No training data available'}
            
            min_samples = config.get('machine_learning.training.min_samples', 1000)
            if len(X) < min_samples:
                logging.warning(f"Insufficient training data: {len(X)} < {min_samples}")
                return {'status': 'failed', 'reason': f'Insufficient data: {len(X)} samples'}
            
            # Initialize new model
            model = EnsembleAnomalyDetector()
            
            # Train the model
            logging.info(f"Starting model training with {len(X)} samples")
            training_results = model.fit(X, y)
            
            # Evaluate on test set
            test_size = config.get('machine_learning.training.test_size', 0.2)
            if len(X) > 100:  # Only split if we have enough data
                X_train, X_test, y_train, y_test = train_test_split(
                    X, y, test_size=test_size, random_state=42
                )
                
                # For unsupervised evaluation, we'll use the model's own predictions
                # In a real scenario, you would have labeled anomalies
                test_results = model.predict(X_test)
                evaluation_metrics = {
                    'test_samples': len(X_test),
                    'anomaly_rate': np.mean(test_results['ensemble_predictions'])
                }
            else:
                evaluation_metrics = {'test_samples': 0}
            
            # Save the model
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            model_path = self.models_dir / f"ensemble_model_{timestamp}"
            model.save(str(model_path))
            
            # Update current model
            self.current_model = model
            self.last_training_time = datetime.now()
            
            # Save model metadata to database
            model_metadata = {
                'model_name': f"ensemble_model_{timestamp}",
                'model_type': 'ensemble',
                'training_timestamp': self.last_training_time,
                'model_path': str(model_path),
                'training_samples': len(X),
                'test_samples': evaluation_metrics.get('test_samples', 0),
                'accuracy': evaluation_metrics.get('anomaly_rate', 0),
                'precision': 0,  # Would be calculated with true labels
                'recall': 0,     # Would be calculated with true labels
                'f1_score': 0,   # Would be calculated with true labels
                'parameters': training_results,
                'feature_importance': {}  # Could be extracted from models
            }
            
            db_manager.insert_model_metadata(model_metadata)
            
            logging.info("Model training completed successfully")
            
            return {
                'status': 'success',
                'model_path': str(model_path),
                'training_samples': len(X),
                'training_results': training_results,
                'evaluation_metrics': evaluation_metrics
            }
            
        except Exception as e:
            logging.error(f"Error training model: {e}")
            return {'status': 'error', 'error': str(e)}
    
    def load_latest_model(self) -> bool:
        """
        Load the latest trained model
        
        Returns:
            True if model loaded successfully
        """
        try:
            # Find latest model file
            model_files = list(self.models_dir.glob("ensemble_model_*_metadata.pkl"))
            
            if not model_files:
                logging.warning("No trained models found")
                return False
            
            # Sort by modification time
            latest_model_file = max(model_files, key=lambda x: x.stat().st_mtime)
            model_path = str(latest_model_file).replace("_metadata.pkl", "")
            
            # Load the model
            self.current_model = EnsembleAnomalyDetector()
            self.current_model.load(model_path)
            
            logging.info(f"Loaded model from {model_path}")
            return True
            
        except Exception as e:
            logging.error(f"Error loading model: {e}")
            return False
    
    def predict_anomaly(self, features: np.ndarray) -> Dict[str, Any]:
        """
        Predict anomaly for given features
        
        Args:
            features: Feature array
            
        Returns:
            Prediction results
        """
        try:
            if self.current_model is None:
                # Try to load latest model
                if not self.load_latest_model():
                    return {'error': 'No trained model available'}
            
            # Make prediction
            results = self.current_model.predict(features.reshape(1, -1))
            
            # Extract results for single prediction
            prediction_result = {
                'is_anomaly': bool(results['ensemble_predictions'][0]) if len(results['ensemble_predictions']) > 0 else False,
                'anomaly_score': float(results['ensemble_scores'][0]) if len(results['ensemble_scores']) > 0 else 0.0,
                'individual_scores': {
                    model: float(scores[0]) if len(scores) > 0 else 0.0
                    for model, scores in results['individual_scores'].items()
                },
                'individual_predictions': {
                    model: bool(preds[0]) if len(preds) > 0 else False
                    for model, preds in results['individual_predictions'].items()
                }
            }
            
            return prediction_result
            
        except Exception as e:
            logging.error(f"Error predicting anomaly: {e}")
            return {'error': str(e)}
    
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about current model"""
        info = {
            'model_loaded': self.current_model is not None,
            'last_training_time': self.last_training_time.isoformat() if self.last_training_time else None,
            'models_directory': str(self.models_dir),
            'available_models': len(list(self.models_dir.glob("ensemble_model_*_metadata.pkl")))
        }
        
        if self.current_model:
            info['model_components'] = list(self.current_model.models.keys())
            info['thresholds'] = self.current_model.thresholds
            info['weights'] = self.current_model.weights
        
        return info

# Global ML model manager instance
ml_model_manager = MLModelManager()
