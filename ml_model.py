"""
Machine Learning Pipeline Module
Implements adaptive learning system with multiple algorithms for anomaly detection
"""

import logging
import joblib
import json
import numpy as np
import pandas as pd
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.svm import OneClassSVM
from sklearn.preprocessing import StandardScaler, RobustScaler
from sklearn.feature_selection import SelectKBest, f_classif
from sklearn.model_selection import train_test_split
from sklearn.metrics import precision_score, recall_score, f1_score, roc_auc_score
from tensorflow.keras.models import Model, Sequential, load_model
from tensorflow.keras.layers import Dense, Input, Dropout
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import EarlyStopping
import tensorflow as tf
from config.config import config
from database import db_manager
from feature_extraction import feature_extractor

class AutoEncoder:
    """Autoencoder neural network for anomaly detection"""
    
    def __init__(self, input_dim: int, encoding_dim: int = 32):
        """
        Initialize autoencoder
        
        Args:
            input_dim: Input dimension
            encoding_dim: Encoding dimension
        """
        self.input_dim = input_dim
        self.encoding_dim = encoding_dim
        self.model = None
        self.threshold = None
        self.scaler = StandardScaler()
    
    def build_model(self) -> None:
        """Build autoencoder model"""
        # Input layer
        input_layer = Input(shape=(self.input_dim,))
        
        # Encoder
        encoded = Dense(64, activation='relu')(input_layer)
        encoded = Dropout(0.2)(encoded)
        encoded = Dense(self.encoding_dim, activation='relu')(encoded)
        
        # Decoder
        decoded = Dense(64, activation='relu')(encoded)
        decoded = Dropout(0.2)(decoded)
        decoded = Dense(self.input_dim, activation='linear')(decoded)
        
        # Create model
        self.model = Model(input_layer, decoded)
        self.model.compile(optimizer=Adam(learning_rate=0.001), loss='mse')
    
    def fit(self, X: np.ndarray, validation_split: float = 0.2, epochs: int = 100) -> Dict[str, Any]:
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
