# Network Security Monitoring System

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A comprehensive network security monitoring system that combines real-time traffic analysis, rule-based detection, and audio sonification to provide an immersive security monitoring experience. This system can operate in either live monitoring mode or PCAP replay mode, allowing for both real-time network surveillance and forensic analysis.

## Key Features

- **Multi-category Threat Detection**: Identify suspicious traffic, malware, and data exfiltration in real-time
- **Audio Sonification**: Translate network traffic patterns into audio feedback for intuitive monitoring
- **NATS Message Streaming**: Distribute detected threats via NATS messaging system for scalable processing
- **Rule-based Detection**: Use customizable Snort-compatible rules for flexible threat identification
- **Dual Operation Modes**: Live network monitoring or PCAP file replay for historical analysis
- **Adaptive Sound Alerts**: Sound frequency and patterns adapt to traffic volume and alert severity

## System Components

### Publisher (`publisher.py`)
- Main component that captures network traffic, analyzes packets against rules, and publishes alerts
- Provides sonification of network traffic patterns through Csound
- Supports both live capture and PCAP replay modes

### Consumers
- **Suspicious Traffic Consumer** (`recon_consumer.py`): Receives and processes suspicious traffic alerts
- **Malware Consumer** (`malware_consumer.py`): Dedicated to processing detected malware packets
- **Exfiltration Consumer** (`exploit_consumer.py`): Monitors data exfiltration attempts

## System Architecture

```
 +------------------+
 |  Network Traffic |
 +--------+---------+
          |
          v
 +--------+---------+
 |    publisher.py  |<------+
 +--------+---------+       |
          |                 |
          | NATS Streaming  | Rule Files (.rules)
          |                 |
 +--------v---------+       |
 |                  |       |
 |  NATS Streaming  |-------+
 |    Server        |
 |                  |
 +--------+---------+
          |
          |
 +--------v---------+  +--------+---------+  +--------+---------+
 | recon_consumer.py |  | malware_consumer |  | exploit_consumer |
 |   (suspicious)    |  |      (.py)       |  |      (.py)       |
 +------------------+  +------------------+  +------------------+
```

## Features in Detail

### Audio Sonification

The system translates network traffic characteristics into real-time audio using Csound:
- **Packet Rate**: Affects sound frequency
- **Traffic Volume**: Influences sound amplitude
- **Packet Size**: Controls modulation depth
- **Alert Level**: Adjusts stereo panning
- **Milestone Counts**: Trigger special sound alerts

### Rule-based Detection

- Compatible with Snort rule syntax
- Supports port variables (`$HTTP_PORTS`, `$FTP_PORTS`, etc.)
- Analyzes traffic against three categories of rules:
  - Suspicious traffic rules
  - Malware detection rules
  - Data exfiltration rules

### NATS Messaging

- Uses JetStream for persistent messaging
- Creates separate streams for each alert category
- Enables distributed processing of security alerts

## Requirements

- Python 3.7+
- NATS Server with JetStream enabled
- Scapy
- Csound
- Additional Python packages:
  - `nats-py`
  - `ctcsound`
  - `numpy`

## Installation

1. **Install NATS Server with JetStream**

   ```bash
   # Download and install NATS Server
   curl -sf https://binaries.nats.dev/nats-server/v2.9.17/nats-server-v2.9.17-linux-amd64.tar.gz | tar -xz
   cd nats-server-v2.9.17-linux-amd64
   sudo cp nats-server /usr/local/bin
   ```

2. **Install Python dependencies**

   ```bash
   pip install scapy nats-py ctcsound numpy
   ```

3. **Install Csound**

   ```bash
   # For Ubuntu/Debian
   sudo apt-get install csound

   # For macOS
   brew install csound

   # For Windows
   # Download from https://csound.com/download.html
   ```

4. **Clone this repository**

   ```bash
   git clone https://github.com/yourusername/network-security-monitor.git
   cd network-security-monitor
   ```

## Usage

### Starting the NATS Server

```bash
# Start NATS Server with JetStream enabled
nats-server -js
```

### Running the System

1. **Start the consumers (in separate terminals)**

   ```bash
   # Start suspicious traffic consumer
   python recon_consumer.py

   # Start malware consumer
   python malware_consumer.py

   # Start exfiltration consumer
   python exploit_consumer.py
   ```

2. **Start the publisher**

   ```bash
   python publisher.py
   ```

3. **Follow the interactive prompts to select:**
   - Operating mode (Live Monitor or PCAP Replay)
   - Rules files for each threat category
   - PCAP file (if in replay mode)

### Example Workflows

#### Live Monitoring

```bash
# Terminal 1
nats-server -js

# Terminal 2
python recon_consumer.py

# Terminal 3
python malware_consumer.py

# Terminal 4
python exploit_consumer.py

# Terminal 5
python publisher.py
# Select: 1 (Live Monitor)
# Select rule files when prompted
```

#### PCAP Replay

```bash
# Terminal 1
nats-server -js

# Terminal 2
python recon_consumer.py

# Terminal 3
python malware_consumer.py

# Terminal 4
python exploit_consumer.py

# Terminal 5
python publisher.py
# Select: 2 (PCAP Replay)
# Choose PCAP file when prompted
# Select rule files when prompted
```

## Rule File Format

The system uses a simplified Snort rule format. Example:

```
alert tcp any any -> any 80 (msg:"Suspicious HTTP Traffic"; content:"malicious"; classtype:web-application-attack;)
```

Rule components:
- **Action**: Always `alert` in this system
- **Protocol**: `tcp`, `udp`, or `icmp`
- **Source IP/Port**: IP and port specifications (supports `any` and port variables)
- **Direction**: `->`
- **Destination IP/Port**: IP and port specifications
- **Options**: In parentheses, includes:
  - `msg`: Alert message
  - `content`: Byte pattern to match
  - `classtype`: Severity classification

## Sonification Details

The system uses Csound to create an audio representation of network traffic:

- **Normal Traffic**: Low-frequency ambient sounds that vary based on traffic volume
- **Suspicious Traffic**: Medium-pitched alerts with frequency that varies by packet rate
- **Malware Detection**: Distinctive tone for immediate recognition
- **Data Exfiltration**: High-priority, urgent tones with high frequency

Sound characteristics adapt to:
- Packet rate (packets per second)
- Bytes per second
- Alert frequency
- Average packet size

## Performance Considerations

- Intensive packet analysis may require significant CPU resources
- Csound processing adds additional CPU overhead
- For high-volume networks, consider using on dedicated hardware

## Security and Privacy Considerations

- The system captures and analyzes all network traffic
- Consider legal and privacy implications before deployment
- Only deploy on networks where you have explicit authorization
- The system does not store packet contents, only metadata and alerts

## Advanced Configuration

### Customizing Sound Parameters

Edit the CSD string in `publisher.py` to modify:
- Sample rate
- Instrument design
- Frequency ranges
- Amplitude scaling

### Adding Port Variables

Extend the `PORT_VARIABLES` dictionary in `publisher.py` to add custom port mappings:

```python
PORT_VARIABLES = {
    "$CUSTOM_PORTS": "8000,8001,8002",
    # ... existing mappings
}
```



## Acknowledgments

- Scapy for packet capture and analysis
- NATS.io for the messaging system
- Csound for audio synthesis
- The Snort project for the rule format inspiration
