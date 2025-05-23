# config.py
import os
import yaml

def load_config(path=None):
    if path is None:
        # Try to find the config file relative to the script location
        script_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        path = os.path.join(script_dir, 'configs', 'settings.yaml')
    
    if not os.path.exists(path):
        raise FileNotFoundError(f"Configuration file not found: {path}")

    try:
        with open(path, 'r') as file:
            config = yaml.safe_load(file)
            if not isinstance(config, dict):
                raise ValueError("Configuration file is not properly formatted as a dictionary.")
            return config
    except yaml.YAMLError as e:
        raise ValueError(f"Error parsing YAML configuration file: {e}")
    except Exception as e:
        raise RuntimeError(f"Unexpected error while loading configuration: {e}")
