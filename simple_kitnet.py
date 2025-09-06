"""
KitNET Implementation for Anomaly Detection
A simplified implementation of the KitNET algorithm for network anomaly detection
"""

import numpy as np
import logging
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class KitNetConfig:
    """Configuration for KitNET anomaly detector"""
    learning_rate: float = 0.1
    window_size: int = 1000
    threshold: float = 0.7
    feature_count: int = 115


class SimpleKitNet:
    """Simplified KitNET implementation for anomaly detection"""
    
    def __init__(self, config: KitNetConfig = None):
        self.config = config or KitNetConfig()
        self.is_trained = False
        self.feature_means = None
        self.feature_stds = None
        self.baseline_scores = []
        self.training_data = []
        
    def process(self, features: List[float]) -> float:
        """
        Process a feature vector and return anomaly score (RMSE)
        
        Args:
            features: List of numerical features extracted from packet
            
        Returns:
            float: RMSE anomaly score (higher = more anomalous)
        """
        try:
            if not features or len(features) == 0:
                return 0.0
                
            # Convert to numpy array
            feature_array = np.array(features, dtype=float)
            
            # Handle NaN values
            feature_array = np.nan_to_num(feature_array, nan=0.0, posinf=1.0, neginf=-1.0)
            
            if not self.is_trained:
                # Training phase - collect baseline data
                self._collect_training_data(feature_array)
                return 0.0
            else:
                # Detection phase - calculate anomaly score
                return self._calculate_anomaly_score(feature_array)
                
        except Exception as e:
            logger.debug(f"Error in KitNET processing: {e}")
            return 0.0
    
    def _collect_training_data(self, features: np.ndarray):
        """Collect training data during initial learning phase"""
        self.training_data.append(features)
        
        # Start detection after collecting enough samples
        if len(self.training_data) >= self.config.window_size:
            self._finish_training()
    
    def _finish_training(self):
        """Complete training phase and prepare for detection"""
        try:
            if not self.training_data:
                return
                
            # Calculate statistics from training data
            training_matrix = np.array(self.training_data)
            self.feature_means = np.mean(training_matrix, axis=0)
            self.feature_stds = np.std(training_matrix, axis=0)
            
            # Avoid division by zero
            self.feature_stds = np.where(self.feature_stds == 0, 1.0, self.feature_stds)
            
            # Calculate baseline RMSE scores
            for features in self.training_data[-100:]:  # Use last 100 samples
                score = self._calculate_raw_score(features)
                self.baseline_scores.append(score)
            
            self.is_trained = True
            logger.info(f"KitNET training completed with {len(self.training_data)} samples")
            
        except Exception as e:
            logger.error(f"Error finishing KitNET training: {e}")
            self.is_trained = True  # Proceed anyway
    
    def _calculate_anomaly_score(self, features: np.ndarray) -> float:
        """Calculate anomaly score for new features"""
        try:
            # Calculate raw score
            raw_score = self._calculate_raw_score(features)
            
            # Normalize based on baseline
            if self.baseline_scores:
                baseline_mean = np.mean(self.baseline_scores)
                baseline_std = np.std(self.baseline_scores)
                
                if baseline_std > 0:
                    # Standardized anomaly score
                    normalized_score = (raw_score - baseline_mean) / baseline_std
                    return max(0.0, normalized_score)  # Only positive anomalies
                else:
                    return raw_score
            else:
                return raw_score
                
        except Exception as e:
            logger.debug(f"Error calculating anomaly score: {e}")
            return 0.0
    
    def _calculate_raw_score(self, features: np.ndarray) -> float:
        """Calculate raw RMSE score"""
        try:
            if self.feature_means is None or self.feature_stds is None:
                return 0.0
            
            # Ensure same length
            min_len = min(len(features), len(self.feature_means))
            features = features[:min_len]
            means = self.feature_means[:min_len]
            stds = self.feature_stds[:min_len]
            
            # Normalize features
            normalized = (features - means) / stds
            
            # Calculate RMSE
            rmse = np.sqrt(np.mean(normalized ** 2))
            return float(rmse)
            
        except Exception as e:
            logger.debug(f"Error calculating raw score: {e}")
            return 0.0


def create_simple_kitnet(feature_count: int = 115) -> SimpleKitNet:
    """Create a SimpleKitNet instance with specified feature count"""
    config = KitNetConfig(feature_count=feature_count)
    return SimpleKitNet(config)


# For compatibility with existing code
class Kitsune:
    """Compatibility wrapper for SimpleKitNet"""
    
    def __init__(self, n_features: int = 115, **kwargs):
        self.kitnet = create_simple_kitnet(n_features)
    
    def process(self, features: List[float]) -> float:
        return self.kitnet.process(features)


# Main interface function
def get_kitsune_analyzer(feature_count: int = 115) -> SimpleKitNet:
    """Get a KitNET analyzer instance"""
    return create_simple_kitnet(feature_count)
