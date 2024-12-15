from datetime import datetime
from typing import Any, Optional
import base64
import json

class LogFormatter:
    
    COLORS = {
        'RESET': '\033[0m',
        'RED': '\033[91m',
        'GREEN': '\033[92m',
        'YELLOW': '\033[93m',
        'BLUE': '\033[94m',
        'PURPLE': '\033[95m',
        'CYAN': '\033[96m'
    }
    
    COMPONENTS = {
        'server': COLORS['BLUE'],
        'client': COLORS['GREEN'],
        'server_nonce': COLORS['CYAN'],
        'client_nonce': COLORS['PURPLE'],
        'server_key': COLORS['YELLOW'],
        'client_key': COLORS['GREEN'],
        'e2e': COLORS['BLUE']
    }

    def __init__(self, component: str, use_color: bool = True):
        self.component = component.lower()
        self.use_color = use_color
    
    def format_message(self, message: str, level: str = 'info') -> str:
        timestamp = datetime.now().strftime('%H:%M:%S.%f')[:-3]
        
        if self.use_color and self.component in self.COMPONENTS:
            color = self.COMPONENTS[self.component]
            reset = self.COLORS['RESET']
            return f"{timestamp} {color}[{self.component}]{reset} {message}"
        else:
            return f"{timestamp} [{self.component}] {message}"
    
    def format_data(self, data: Any, data_type: str = '') -> str:
        if isinstance(data, bytes):
            hex_data = data.hex()
            b64_data = base64.b64encode(data).decode()
            return (f"\n  → Hex: {hex_data}"
                   f"\n  → Base64: {b64_data}"
                   f"\n  → Length: {len(data)} bytes")
        elif isinstance(data, (dict, list)):
            return f"\n  → {json.dumps(data, indent=2).replace(chr(10), chr(10) + '  ')}"
        else:
            if data_type:
                return f"\n  → {data_type}: {str(data)}"
            return f"\n  → {str(data)}"
    
    def format_key(self, key_data: str, key_type: str) -> str:
        return (f"\n=== {key_type} ===\n"
                f"{key_data}\n"
                f"{'=' * (len(key_type) + 8)}")

class SystemLogger:
    
    def __init__(self, component: str):
        self.formatter = LogFormatter(component)
    
    def info(self, message: str):
        print(self.formatter.format_message(message))
    
    def error(self, message: str, error: Optional[Exception] = None):
        error_msg = self.formatter.format_message(f"ERROR: {message}", 'error')
        if error:
            error_msg += f"\n  → Exception: {str(error)}"
        print(error_msg)
    
    def data(self, message: str, data: Any, data_type: str = ''):
        print(self.formatter.format_message(f"{message}{self.formatter.format_data(data, data_type)}"))
    
    def key(self, message: str, key_data: str, key_type: str):
        print(self.formatter.format_message(f"{message}{self.formatter.format_key(key_data, key_type)}"))


def create_nonce_logger():
    return {
        'server': SystemLogger('server_nonce'),
        'client': SystemLogger('client_nonce')
    }

def create_key_logger():
    return {
        'server': SystemLogger('server_key'),
        'client': SystemLogger('client_key')
    }

def create_e2e_logger():
    return SystemLogger('e2e')