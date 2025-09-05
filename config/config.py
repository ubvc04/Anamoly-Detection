"""
Configuration Management Module
Handles loading and managing system configuration
"""

import os
import yaml
import logging
from typing import Dict, Any, Optional
from pathlib import Path

class ConfigManager:
    """Manages application configuration"""
    
    def __init__(self, config_path: Optional[str] = None):
        """
        Initialize configuration manager
        
        Args:
            config_path: Path to configuration file
        """
        self.config_path = config_path or self._get_default_config_path()
        self.config = {}
        self.load_config()
        
    def _get_default_config_path(self) -> str:
        """Get default configuration file path"""
        base_dir = Path(__file__).parent.parent
        return str(base_dir / "config" / "config.yaml")
    
    def load_config(self) -> None:
        """Load configuration from file"""
        try:
            with open(self.config_path, 'r', encoding='utf-8') as file:
                self.config = yaml.safe_load(file)
            logging.info(f"Configuration loaded from {self.config_path}")
        except FileNotFoundError:
            logging.error(f"Configuration file not found: {self.config_path}")
            self.config = self._get_default_config()
        except yaml.YAMLError as e:
            logging.error(f"Error parsing configuration file: {e}")
            self.config = self._get_default_config()
    
    def save_config(self) -> None:
        """Save current configuration to file"""
        try:
            os.makedirs(os.path.dirname(self.config_path), exist_ok=True)
            with open(self.config_path, 'w', encoding='utf-8') as file:
                yaml.safe_dump(self.config, file, default_flow_style=False)
            logging.info(f"Configuration saved to {self.config_path}")
        except Exception as e:
            logging.error(f"Error saving configuration: {e}")
    
    def get(self, key: str, default: Any = None) -> Any:
        """
        Get configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'app.port')
            default: Default value if key not found
            
        Returns:
            Configuration value
        """
        keys = key.split('.')
        value = self.config
        
        try:
            for k in keys:
                value = value[k]
            return value
        except (KeyError, TypeError):
            return default
    
    def set(self, key: str, value: Any) -> None:
        """
        Set configuration value using dot notation
        
        Args:
            key: Configuration key (e.g., 'app.port')
            value: Value to set
        """
        keys = key.split('.')
        config = self.config
        
        # Navigate to the parent dictionary
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        # Set the value
        config[keys[-1]] = value
    
    def update(self, updates: Dict[str, Any]) -> None:
        """
        Update multiple configuration values
        
        Args:
            updates: Dictionary of key-value pairs to update
        """
        for key, value in updates.items():
            self.set(key, value)
    
    def _get_default_config(self) -> Dict[str, Any]:
        """Get default configuration if file is not available"""
        return {
            'app': {
                'name': 'Network Anomaly Detector',
                'version': '1.0.0',
                'debug': False,
                'host': '0.0.0.0',
                'port': 5000,
                'secret_key': 'default-secret-key'
            },
            'network': {
                'interfaces': [],
                'capture': {
                    'filter': '',
                    'snaplen': 65535,
                    'promisc': True,
                    'timeout': 1000,
                    'buffer_size': 8192
                }
            },
            'logging': {
                'level': 'INFO',
                'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            }
        }
    
    def get_database_url(self) -> str:
        """Get database connection URL"""
        db_type = self.get('database.type', 'sqlite')
        
        if db_type == 'sqlite':
            db_path = self.get('database.path', 'data/network_anomaly.db')
            # Ensure absolute path
            if not os.path.isabs(db_path):
                base_dir = Path(__file__).parent.parent
                db_path = str(base_dir / db_path)
            return f"sqlite:///{db_path}"
        
        # Add support for other database types if needed
        return f"sqlite:///data/network_anomaly.db"
    
    def get_log_config(self) -> Dict[str, Any]:
        """Get logging configuration"""
        base_dir = Path(__file__).parent.parent
        log_config = {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'default': {
                    'format': self.get('logging.format', 
                                     '%(asctime)s - %(name)s - %(levelname)s - %(message)s')
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'default',
                    'level': self.get('logging.level', 'INFO')
                },
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'filename': str(base_dir / self.get('logging.files.main', 'logs/main.log')),
                    'formatter': 'default',
                    'level': self.get('logging.level', 'INFO'),
                    'maxBytes': self.get('logging.rotation.max_size', 10485760),
                    'backupCount': self.get('logging.rotation.backup_count', 5)
                }
            },
            'root': {
                'level': self.get('logging.level', 'INFO'),
                'handlers': ['console', 'file']
            }
        }
        
        return log_config
    
    def validate_config(self) -> bool:
        """
        Validate configuration settings
        
        Returns:
            True if configuration is valid, False otherwise
        """
        required_keys = [
            'app.name',
            'app.port',
            'network.capture.snaplen',
            'database.type'
        ]
        
        for key in required_keys:
            if self.get(key) is None:
                logging.error(f"Required configuration key missing: {key}")
                return False
        
        # Validate port number
        port = self.get('app.port')
        if not isinstance(port, int) or port < 1 or port > 65535:
            logging.error(f"Invalid port number: {port}")
            return False
        
        return True

# Global configuration instance
config = ConfigManager()

# Convenience functions
def get_config(key: str, default: Any = None) -> Any:
    """Get configuration value"""
    return config.get(key, default)

def set_config(key: str, value: Any) -> None:
    """Set configuration value"""
    config.set(key, value)

def save_config() -> None:
    """Save configuration to file"""
    config.save_config()

def reload_config() -> None:
    """Reload configuration from file"""
    config.load_config()
