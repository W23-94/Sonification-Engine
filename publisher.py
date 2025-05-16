import asyncio
import nats
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, rdpcap, raw
import threading
import re
from datetime import datetime
import ctcsound
import time
import socket
import numpy as np
import os
from collections import deque
import math

# Config
suspicious_subject = "suspicious.traffic"
suspicious_stream = "suspicious_stream"

malware_subject = "malware.traffic"
malware_stream = "malware_stream"

exfiltration_subject = "exfiltration.traffic"  
exfiltration_stream = "exfiltration_stream"    

# Default rule files
rules_file = "Converted_Snort_Rules.rules"
malware_rules_file = "malware.rules"
exfiltration_rules_file = "exploit.rules"  

pcap_file = "set3.pcap"

# Constants
CSOUND_SAMPLE_RATE = 44100
MAX_PACKETS_PER_SECOND = 100

# Globals
loop = None
js = None
parsed_rules = []
parsed_malware_rules = []
parsed_exfiltration_rules = []  
cs = None
packet_buffer = []

# Port variables mapping
PORT_VARIABLES = {
    "$SIP_PORTS": "5060,5061",
    "$HTTP_PORTS": "80,443,8080",
    "$FTP_PORTS": "20,21",
    "$SSH_PORTS": "22",
    "$SMTP_PORTS": "25,465,587",
    "$DNS_PORTS": "53",
    "$TELNET_PORTS": "23",
    "$SQL_PORTS": "1433,3306,5432",
    "$RDP_PORTS": "3389",
    "$SMB_PORTS": "139,445"
}

# CSound Orchestra
CSD = '''
<CsoundSynthesizer>
<CsOptions>
-odac -d
</CsOptions>
<CsInstruments>
sr = 44100
ksmps = 32
nchnls = 2
0dbfs = 1

giSine ftgen 1, 0, 16384, 10, 1

instr 100
    kfreq chnget "stream_freq"
    kamp  chnget "stream_amp"
    kmod  chnget "stream_mod"
    kpan  chnget "stream_pan"

    aenv linsegr 0, 0.2, 1, 0.2, 0.7
    amod poscil kamp * kmod * 0.25, kfreq * 1.5, 1
    acar poscil aenv * kamp, kfreq + amod, 1
    afilt moogladder acar, 3500, 0.25

    aL = afilt * (1 - kpan)
    aR = afilt * kpan

    aLrev, aRrev reverbsc aL, aR, 0.65, 15000
    aLmix = 0.9 * aL + 0.1 * aLrev
    aRmix = 0.9 * aR + 0.1 * aRrev

    aLlim = tanh(aLmix * 1.5)
    aRlim = tanh(aRmix * 1.5)

    outs aLlim, aRlim
endin

</CsInstruments>
<CsScore>
f1 0 16384 10 1
i100 0 3600
</CsScore>
</CsoundSynthesizer>
'''

# Rule parsing 
def parse_rule(rule):
    try:
        header, options = rule.split("(", 1)
        parts = header.strip().split()
        action, proto, src, sport, direction, dst, dport = parts[:7]

        msg_match = re.search(r'msg\s*:\s*"([^"]+)"', options)
        msg = msg_match.group(1) if msg_match else "No msg"

        content_match = re.search(r'content:\s*"([^"]+)"', options)
        content = content_match.group(1) if content_match else None

        
        classtype_match = re.search(r'classtype\s*:\s*([^;]+)', options)
        classtype = classtype_match.group(1).strip() if classtype_match else "unknown"

        severity = 3
        if "high" in classtype:
            severity = 5
        elif "medium" in classtype:
            severity = 3
        elif "low" in classtype:
            severity = 1

        
        sport_processed = None if sport == "any" else sport
        dport_processed = None if dport == "any" else dport
        
       
        if sport_processed and sport_processed.startswith('$'):
            if sport_processed in PORT_VARIABLES:
                sport_processed = PORT_VARIABLES[sport_processed]
                
        if dport_processed and dport_processed.startswith('$'):
            if dport_processed in PORT_VARIABLES:
                dport_processed = PORT_VARIABLES[dport_processed]

        return {
            "proto": proto.lower(),
            "sport": sport_processed,
            "dport": dport_processed,
            "direction": direction,
            "msg": msg,
            "content": content,
            "severity": severity
        }
    except Exception as e:
        print(f"[ERROR] Failed to parse rule: {rule} ({e})")
        return None

# Rule matching
def matches_rule_generic(pkt, rule_set):
    if IP not in pkt:
        return None
    if UDP in pkt and DNS in pkt:
        return None  

    proto = None
    sport = dport = None
    payload = bytes(pkt)

    if ICMP in pkt:
        proto = 'icmp'
    elif TCP in pkt:
        proto = 'tcp'
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = 'udp'
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    for rule in rule_set:
        if not rule or rule["proto"] != proto:
            continue

        
        sport_match = rule.get("sport") is None
        dport_match = rule.get("dport") is None
        
        if not sport_match:
            rule_sport = rule["sport"]
            if ":" in rule_sport:
                start, end = map(int, rule_sport.split(":"))
                sport_match = start <= sport <= end
            else:
                sport_match = int(rule_sport) == sport
                
        if not dport_match:
            rule_dport = rule["dport"]
            if ":" in rule_dport:
                start, end = map(int, rule_dport.split(":"))
                dport_match = start <= dport <= end
            else:
                dport_match = int(rule_dport) == dport

        match_forward = sport_match and dport_match
        
       
        sport_match_rev = rule.get("sport") is None
        dport_match_rev = rule.get("dport") is None
        
        if not sport_match_rev:
            rule_sport = rule["sport"]
            if ":" in rule_sport:
                start, end = map(int, rule_sport.split(":"))
                sport_match_rev = start <= dport <= end
            else:
                sport_match_rev = int(rule_sport) == dport
                
        if not dport_match_rev:
            rule_dport = rule["dport"]
            if ":" in rule_dport:
                start, end = map(int, rule_dport.split(":"))
                dport_match_rev = start <= sport <= end
            else:
                dport_match_rev = int(rule_dport) == sport
                
        match_reverse = sport_match_rev and dport_match_rev

        direction = rule.get("direction")
        if direction == "->" and not match_forward:
            continue
        if direction == "<-" and not match_reverse:
            continue
        if direction == "<->" and not (match_forward or match_reverse):
            continue

        if rule.get("content") and rule["content"].encode() not in payload:
            continue

        return rule

    return None


def matches_rule(pkt):
    return matches_rule_generic(pkt, parsed_rules)

def matches_malware_rule(pkt):
    return matches_rule_generic(pkt, parsed_malware_rules)

def matches_exfiltration_rule(pkt):
    return matches_rule_generic(pkt, parsed_exfiltration_rules)


def matches_rule_pcap_generic(pkt, rule_set):
    if IP not in pkt:
        return None
    if UDP in pkt and DNS in pkt:
        return None  

    proto = None
    sport = dport = None
    payload = bytes(pkt)

    if ICMP in pkt:
        proto = 'icmp'
    elif TCP in pkt:
        proto = 'tcp'
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        proto = 'udp'
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    for rule in rule_set:
        if not rule or rule["proto"] != proto:
            continue

        # Handle port ranges
        sport_match = rule.get("sport") is None
        dport_match = rule.get("dport") is None
        
        if not sport_match and sport is not None:
            try:
                rule_sport = rule["sport"]
            
                if ',' in rule_sport:
                    ports = [int(p.strip()) for p in rule_sport.split(',')]
                    sport_match = sport in ports
               
                elif ":" in rule_sport:
                    try:
                        start, end = map(int, rule_sport.split(":"))
                        sport_match = start <= sport <= end
                    except ValueError:
                       
                        continue
                else:
                  
                    clean_sport = re.sub(r'[^\d]', '', rule_sport)
                    if clean_sport:
                        sport_match = int(clean_sport) == sport
            except Exception:
                sport_match = False
                
        if not dport_match and dport is not None:
            try:
                rule_dport = rule["dport"]
               
                if ',' in rule_dport:
                    ports = [int(p.strip()) for p in rule_dport.split(',')]
                    dport_match = dport in ports
          
                elif ":" in rule_dport:
                    try:
                        start, end = map(int, rule_dport.split(":"))
                        dport_match = start <= dport <= end
                    except ValueError:
                      
                        continue
                else:
                    
                    clean_dport = re.sub(r'[^\d]', '', rule_dport)
                    if clean_dport:
                        dport_match = int(clean_dport) == dport
            except Exception:
                dport_match = False

        match_forward = sport_match and dport_match
        
        # Error checking
        sport_match_rev = rule.get("sport") is None
        dport_match_rev = rule.get("dport") is None
        
        if not sport_match_rev and dport is not None:
            try:
                rule_sport = rule["sport"]
                
                if ',' in rule_sport:
                    ports = [int(p.strip()) for p in rule_sport.split(',')]
                    sport_match_rev = dport in ports
                
                elif ":" in rule_sport:
                    try:
                        start, end = map(int, rule_sport.split(":"))
                        sport_match_rev = start <= dport <= end
                    except ValueError:
                        
                        continue
                else:
                    
                    clean_sport = re.sub(r'[^\d]', '', rule_sport)
                    if clean_sport:
                        sport_match_rev = int(clean_sport) == dport
            except Exception:
                sport_match_rev = False
                
        if not dport_match_rev and sport is not None:
            try:
                rule_dport = rule["dport"]
               
                if ',' in rule_dport:
                    ports = [int(p.strip()) for p in rule_dport.split(',')]
                    dport_match_rev = sport in ports
                
                elif ":" in rule_dport:
                    try:
                        start, end = map(int, rule_dport.split(":"))
                        dport_match_rev = start <= sport <= end
                    except ValueError:
                        
                        continue
                else:
                    
                    clean_dport = re.sub(r'[^\d]', '', rule_dport)
                    if clean_dport:
                        dport_match_rev = int(clean_dport) == sport
            except Exception:
                dport_match_rev = False
                
        match_reverse = sport_match_rev and dport_match_rev

        direction = rule.get("direction")
        if direction == "->" and not match_forward:
            continue
        if direction == "<-" and not match_reverse:
            continue
        if direction == "<->" and not (match_forward or match_reverse):
            continue

        if rule.get("content") and rule["content"].encode() not in payload:
            continue

        return rule

    return None


def matches_rule_pcap(pkt):
    return matches_rule_pcap_generic(pkt, parsed_rules)

def matches_malware_rule_pcap(pkt):
    return matches_rule_pcap_generic(pkt, parsed_malware_rules)

def matches_exfiltration_rule_pcap(pkt):
    return matches_rule_pcap_generic(pkt, parsed_exfiltration_rules)


def handle_packet(packet):
    global js, loop, packet_buffer
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        # Check against all rule sets
        suspicious_matched_rule = matches_rule(packet)
        malware_matched_rule = matches_malware_rule(packet)
        exfiltration_matched_rule = matches_exfiltration_rule(packet)
        
        
        matched_rule = None
        if exfiltration_matched_rule:
            matched_rule = exfiltration_matched_rule
        elif malware_matched_rule:
            matched_rule = malware_matched_rule
        else:
            matched_rule = suspicious_matched_rule
            
        packet_buffer.append((packet, matched_rule))
        if len(packet_buffer) > MAX_PACKETS_PER_SECOND * 3:
            packet_buffer = packet_buffer[-MAX_PACKETS_PER_SECOND * 3:]
        
        
        if suspicious_matched_rule:
            print(f"[{timestamp}] [ALERT] [SUSPICIOUS] {suspicious_matched_rule.get('msg')} | {packet.summary()}")
            if js and loop:
                payload = bytes(packet)
                asyncio.run_coroutine_threadsafe(js.publish(suspicious_subject, payload), loop)
        
        
        if malware_matched_rule:
            print(f"[{timestamp}] [ALERT] [MALWARE] {malware_matched_rule.get('msg')} | {packet.summary()}")
            if js and loop:
                payload = bytes(packet)
                asyncio.run_coroutine_threadsafe(js.publish(malware_subject, payload), loop)
        
        
        if exfiltration_matched_rule:
            print(f"[{timestamp}] [ALERT] [EXFILTRATION] {exfiltration_matched_rule.get('msg')} | {packet.summary()}")
            if js and loop:
                payload = bytes(packet)
                asyncio.run_coroutine_threadsafe(js.publish(exfiltration_subject, payload), loop)
                
        # Log non-matching traffic
        if not suspicious_matched_rule and not malware_matched_rule and not exfiltration_matched_rule:
            print(f"[{timestamp}] [INFO] Traffic: {packet.summary()}")
            
    except Exception:
        
        print(f"[{timestamp}] {packet}")

# NATS setup
async def setup_nats():
    global js, loop
    loop = asyncio.get_running_loop()
    nc = await nats.connect("nats://localhost:4222")
    js = nc.jetstream()
    
    # Create streams
    try:
        await js.add_stream(name=suspicious_stream, subjects=[suspicious_subject])
        print(f"Created or connected to stream: {suspicious_stream}")
    except Exception:
        pass
        
    try:
        await js.add_stream(name=malware_stream, subjects=[malware_subject])
        print(f"Created or connected to stream: {malware_stream}")
    except Exception:
        pass
        
    try:
        await js.add_stream(name=exfiltration_stream, subjects=[exfiltration_subject])
        print(f"Created or connected to stream: {exfiltration_stream}")
    except Exception:
        pass
        
    return nc

# Sonification 
def stream_control_loop():
    global packet_buffer, cs
    window = deque(maxlen=MAX_PACKETS_PER_SECOND)
    try:
        while True:
            now = time.time()
            if packet_buffer:
                pkt, rule = packet_buffer.pop(0)
                window.append((pkt, rule, now))
            window = deque((pkt, rule, ts) for pkt, rule, ts in window if now - ts <= 3.0)
            duration = 3.0
            pps = len(window) / duration
            total_bytes = sum(len(bytes(pkt)) for pkt, _, _ in window)
            bps = total_bytes / duration if total_bytes > 0 else 0
            freq = compute_traffic_frequency(pps, bps)
            avg_size = np.mean([len(bytes(pkt)) for pkt, _, _ in window]) if window else 200
            alert_count = sum(1 for _, rule, _ in window if rule is not None)
            alert_level = min(alert_count / 10, 1.0)
            amp = min(0.3 + (pps / MAX_PACKETS_PER_SECOND), 0.8)
            mod = 0.2 + (avg_size / 1500.0)
            pan = 0.3 + (alert_level * 0.4)
            cs.setControlChannel("stream_freq", freq)
            cs.setControlChannel("stream_amp", amp)
            cs.setControlChannel("stream_mod", mod)
            cs.setControlChannel("stream_pan", pan)
            time.sleep(0.005)
    except Exception as e:
        print(f"[ERROR] stream_control_loop: {e}")

def sonification_loop():
    global cs
    cs = ctcsound.Csound()
    cs.compileCsdText(CSD)
    cs.start()
    threading.Thread(target=cs.perform, daemon=True).start()
    stream_control_loop()

def compute_traffic_frequency(pps, bps, max_pps=500, max_bps=5_000_000, min_freq=100.0, max_freq=3000.0):
    norm_pps = min(max(pps / max_pps, 0.0), 1.0)
    norm_bps = min(max(bps / max_bps, 0.0), 1.0)
    traffic_level = math.sqrt(0.4 * norm_pps**2 + 0.6 * norm_bps**2)
    log_min = math.log(min_freq)
    log_max = math.log(max_freq)
    return math.exp(log_min + traffic_level * (log_max - log_min))

def load_rules(path):
    rules = []
    if not os.path.exists(path):
        print(f"Warning: Rules file {path} not found.")
        return rules
    with open(path, 'r') as file:
        for line in file:
            line = line.strip()
            if line.startswith("alert"):
                rule = parse_rule(line)
                if rule:
                    rules.append(rule)
    return rules


async def setup_common():
    global parsed_rules, parsed_malware_rules, parsed_exfiltration_rules
    
    # Load all rule sets
    if rules_file:
        parsed_rules = load_rules(rules_file)
        print(f"Loaded {len(parsed_rules)} suspicious traffic rules")
    else:
        parsed_rules = []
        print("No suspicious traffic rules loaded (skipped by user)")
    
    if malware_rules_file:
        parsed_malware_rules = load_rules(malware_rules_file)
        print(f"Loaded {len(parsed_malware_rules)} malware rules")
    else:
        parsed_malware_rules = []
        print("No malware rules loaded (skipped by user)")
    
    if exfiltration_rules_file:
        parsed_exfiltration_rules = load_rules(exfiltration_rules_file)
        print(f"Loaded {len(parsed_exfiltration_rules)} exfiltration rules")
    else:
        parsed_exfiltration_rules = []
        print("No exfiltration rules loaded (skipped by user)")
    
    if not parsed_rules and not parsed_malware_rules and not parsed_exfiltration_rules:
        print("[WARNING] No rules were loaded. No packets will be forwarded to NATS.")
    
    # Start sonification
    sonification_thread = threading.Thread(target=sonification_loop)
    sonification_thread.daemon = True
    sonification_thread.start()
    
    # Set up NATS
    await setup_nats()
    return sonification_thread

# PCAP replay mode 
async def replay_pcap():
    global js, loop, parsed_rules, parsed_malware_rules, parsed_exfiltration_rules, packet_buffer, pcap_file
    
    
    sonification_thread = await setup_common()
    
    # Load PCAP
    try:
        packets = rdpcap(pcap_file)
        print(f"[{datetime.now()}] Loaded {len(packets)} packets")
    except Exception as e:
        print(f"[ERROR] Failed to load PCAP file: {e}")
        return
    
    # Replay packets
    print(f"[{datetime.now()}] Starting PCAP replay... (Ctrl+C to stop)")
    try:
        if len(packets) < 2:
            print("[ERROR] PCAP file contains too few packets for replay")
            return
            
        
        timestamps = []
        first_time = float(packets[0].time)
        for pkt in packets:
            timestamps.append(float(pkt.time) - first_time)
        
       
        for i, pkt in enumerate(packets):
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            
            try:
                
                suspicious_matched_rule = matches_rule_pcap(pkt)
                malware_matched_rule = matches_malware_rule_pcap(pkt)
                exfiltration_matched_rule = matches_exfiltration_rule_pcap(pkt)
                
               
                matched_rule = None
                if exfiltration_matched_rule:
                    matched_rule = exfiltration_matched_rule
                elif malware_matched_rule:
                    matched_rule = malware_matched_rule
                else:
                    matched_rule = suspicious_matched_rule
                
                
                packet_buffer.append((pkt, matched_rule))
                if len(packet_buffer) > MAX_PACKETS_PER_SECOND * 3:
                    packet_buffer = packet_buffer[-MAX_PACKETS_PER_SECOND * 3:]
                
               
                if suspicious_matched_rule:
                    print(f"[{timestamp}] [ALERT] [SUSPICIOUS] {suspicious_matched_rule.get('msg')} | {pkt.summary()}")
                    if js and loop:
                        raw_bytes = bytes(pkt)
                        await js.publish(suspicious_subject, raw_bytes)
                
               
                if malware_matched_rule:
                    print(f"[{timestamp}] [ALERT] [MALWARE] {malware_matched_rule.get('msg')} | {pkt.summary()}")
                    if js and loop:
                        raw_bytes = bytes(pkt)
                        await js.publish(malware_subject, raw_bytes)
                
                
                if exfiltration_matched_rule:
                    print(f"[{timestamp}] [ALERT] [EXFILTRATION] {exfiltration_matched_rule.get('msg')} | {pkt.summary()}")
                    if js and loop:
                        raw_bytes = bytes(pkt)
                        await js.publish(exfiltration_subject, raw_bytes)
                
                
                if not suspicious_matched_rule and not malware_matched_rule and not exfiltration_matched_rule:
                    print(f"[{timestamp}] [INFO] Traffic: {pkt.summary()}")
                
            except Exception:
               
                print(f"[{timestamp}] {pkt}")
                
            
            if i < len(packets) - 1:
                time_to_wait = max(0, timestamps[i+1] - timestamps[i])
                await asyncio.sleep(time_to_wait)

        print("Replay complete.")
    except KeyboardInterrupt:
        print("Replay interrupted by user.")
    except Exception as e:
        print(f"[ERROR] Replay failed: {e}")
    finally:
     
        pass

# Live monitor mode 
async def live_monitor():
    global js
    
    
    sonification_thread = await setup_common()
    
    # Start packet capture
    print("Starting packet capture on 'en0'... (Ctrl+C to stop)")
    print("[INFO] Packets matching suspicious rules will be published to NATS subject:", suspicious_subject)
    print("[INFO] Packets matching malware rules will be published to NATS subject:", malware_subject)
    print("[INFO] Packets matching exfiltration rules will be published to NATS subject:", exfiltration_subject)
    
    sniff_thread = threading.Thread(target=sniff, kwargs={
        "iface": "en0",
        "prn": handle_packet,
        "store": False
    })
    sniff_thread.daemon = True
    sniff_thread.start()
    
    try:
        while sniff_thread.is_alive() and sonification_thread.is_alive():
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        print("Async loop cancelled")
    except KeyboardInterrupt:
        print("Interrupted by user.")
    finally:
        await js.close()

def list_files_with_extension(extension):
    """List all files with the given extension in the current directory"""
    files = []
    for file in os.listdir('.'):
        if file.endswith(extension):
            files.append(file)
    return files

def list_pcap_files():
    """List all pcap files in the current directory"""
    pcap_files = []
    for file in os.listdir('.'):
        if file.endswith('.pcap') or file.endswith('.pcapng'):
            pcap_files.append(file)
    return pcap_files

def list_rules_files():
    """List all rules files in the current directory"""
    rules_files = []
    for file in os.listdir('.'):
        if file.endswith('.rules'):
            rules_files.append(file)
    return rules_files

def choose_mode():
    print("Select mode:")
    print("1 - Live Monitor")
    print("2 - PCAP Replay")
    choice = input("Enter choice (1 or 2): ").strip()
    return choice

def choose_pcap():
    """Let the user choose a PCAP file from the list of available files"""
    global pcap_file
    
    pcap_files = list_pcap_files()
    
    if not pcap_files:
        print("No PCAP files found in the current directory.")
        return False
    
    print("\nAvailable PCAP files:")
    for i, file in enumerate(pcap_files, 1):
        print(f"{i} - {file}")
    
    try:
        choice = int(input(f"Enter choice (1-{len(pcap_files)}): ").strip())
        if 1 <= choice <= len(pcap_files):
            pcap_file = pcap_files[choice - 1]
            print(f"Selected PCAP file: {pcap_file}")
            return True
        else:
            print("Invalid selection.")
            return False
    except ValueError:
        print("Please enter a number.")
        return False

def choose_rules_file(rule_type="suspicious"):
    """Let the user choose a rules file from the list of available files"""
    global rules_file, malware_rules_file, exfiltration_rules_file
    
    rules_files = list_rules_files()
    
    if not rules_files:
        print(f"No .rules files found in the current directory for {rule_type} rules.")
        return False
    
    print(f"\nAvailable {rule_type} rules files:")
    print("0 - None (Skip this rule type)")
    for i, file in enumerate(rules_files, 1):
        print(f"{i} - {file}")
    
    try:
        choice = int(input(f"Enter choice (0-{len(rules_files)}): ").strip())
        if choice == 0:
            
            selected_file = None
            print(f"Skipping {rule_type} rules.")
        elif 1 <= choice <= len(rules_files):
            selected_file = rules_files[choice - 1]
            print(f"Selected {rule_type} rules file: {selected_file}")
        else:
            print("Invalid selection.")
            return False
            
    
        if rule_type == "suspicious":
            rules_file = selected_file
        elif rule_type == "malware":
            malware_rules_file = selected_file
        elif rule_type == "exfiltration":
            exfiltration_rules_file = selected_file
            
        return True
    except ValueError:
        print("Please enter a number.")
        return False

def setup_rules_files():
    """Let the user choose rule files for each category"""
    print("\n--- Rules File Selection ---")
    
    # Choose suspicious rules file
    print("\nSelect file for SUSPICIOUS traffic rules:")
    if not choose_rules_file("suspicious"):
        return False
        
    # Choose malware rules file
    print("\nSelect file for MALWARE traffic rules:")
    if not choose_rules_file("malware"):
        return False
        
    # Choose exfiltration rules file
    print("\nSelect file for EXFILTRATION traffic rules:")
    if not choose_rules_file("exfiltration"):
        return False
        
    return True


if __name__ == "__main__":
    mode = choose_mode()
    try:
        if mode == "1":
          
            if setup_rules_files():
                asyncio.run(live_monitor())
            else:
                print("Rules file selection failed. Exiting.")
        elif mode == "2":
            
            if choose_pcap() and setup_rules_files():  
                asyncio.run(replay_pcap())
            else:
                print("PCAP or rules file selection failed. Exiting.")
        else:
            print("Invalid selection. Exiting.")
    except KeyboardInterrupt:
        print("Interrupted. Shutting down.")



        