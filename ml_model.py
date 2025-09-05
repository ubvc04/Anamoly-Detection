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
