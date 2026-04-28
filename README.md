# Network Traffic Analyzer

## Overview

 A lightweight network traffic analyzer built using Python and Scapy. It captures live network packets, parses protocol-level information, applies filtering, and displays real-time analytics in a structured terminal dashboard.

The project is designed with a modular architecture, separating packet capture, parsing, analysis, and visualization. It also includes a focused payload inspection tool for deep inspection of specific network flows.

## Features

* Real-time packet capture
* Protocol classification (TCP, UDP, ICMP)
* Service detection (HTTP, HTTPS, DNS, QUIC)
* HTTP request parsing (method and host extraction)
* Packet filtering (by protocol and port)
* Live CLI dashboard
* Packet rate monitoring (packets per second)
* Top sources and destinations tracking
* Active connection and peer tracking
* Logging to file
* Targeted payload dump mode (hex + ASCII)

## Project Structure

```
network_traffic_analyzer/
│
└── src/
    ├── main.py
    ├── sniffer.py
    ├── parser.py
    ├── analyzer.py
    ├── dashboard (inside main.py)
    ├── logger.py
    ├── hostinfo.py
    └── dump.py
```

## File Descriptions

### main.py

Entry point of the application.

Responsibilities:

* Parses CLI arguments (protocol, port filters)
* Initializes Analyzer with configuration
* Starts packet sniffing in a background thread
* Runs the live dashboard loop
* Handles formatted output and logging

This file acts as the coordinator of the entire system.

### sniffer.py

Handles packet capture using Scapy.

Responsibilities:

* Captures packets using `sniff()`
* Passes each packet to the parser
* Sends parsed data to the analyzer

It acts as the bridge between raw network traffic and structured processing.

### parser.py

Responsible for extracting structured data from raw packets.

Responsibilities:

* Identifies protocol (TCP, UDP, ICMP)
* Extracts source and destination IP and ports
* Detects service type (HTTP, HTTPS, DNS, QUIC)
* Parses HTTP payloads (GET/POST and Host)

This module converts raw packets into structured dictionaries used by the analyzer.

### analyzer.py

Core logic of the system.

Responsibilities:

* Applies protocol and port filters
* Maintains protocol and service counters
* Tracks packet rate
* Tracks active connections and peers
* Maintains top sources and destinations
* Stores recent packets for display
* Provides aggregated statistics to the dashboard

It is the central processing unit of the application. 

### hostinfo.py

Provides local system network information.

Responsibilities:

* Retrieves local IP address
* Retrieves MAC address

Used to enrich the dashboard with host-level context.

### logger.py

Handles persistent logging.

Responsibilities:

* Writes packet summaries to a log file
* Ensures UTF-8 encoding support

Used for recording captured traffic without affecting real-time display.

### dump.py

Standalone tool for deep packet inspection.

Responsibilities:

* Filters packets for a specific source-destination pair
* Displays payload in hex and ASCII format
* Shows direction (IN/OUT)
* Detects protocol type (TCP, UDP, QUIC)
* Skips noise packets

This is used for targeted debugging and payload analysis.

## How Components Connect

The system follows a linear data pipeline:

```
Packet → Sniffer → Parser → Analyzer → Dashboard
```

### Flow Explanation

1. Sniffer captures raw packets from the network.
2. Parser extracts structured information from each packet.
3. Analyzer:

   * Filters packets
   * Updates statistics
   * Tracks connections and metrics
4. main.py dashboard:

   * Fetches stats from analyzer
   * Displays formatted output
   * Logs selected data

For deep inspection:

```
Packet → dump.py → Filter by Flow → Payload Display
```

## Usage

### Run main analyzer

```
python main.py
```

### With filters

```
python main.py --protocol tcp
python main.py --port 443
```

### Run payload dump (targeted flow)

```
python dump.py --src <source_ip> --dst <destination_ip>
```

Example:

```
python dump.py --src 10.250.37.2 --dst 172.64.155.209
```

## Output Example

```
====== NetScope ======

Packets/sec: 12.4

TCP: 150   UDP: 30   ICMP: 0
HTTP: 5   HTTPS: 140   QUIC: 28   DNS: 7

====== HOST INFO ======

Local IP: 10.x.x.x
MAC: xx:xx:xx:xx:xx:xx
Active Connections: 12
Unique Peers: 18

Top Destinations:
...

Recent Packets:
[TCP ] 10.x.x.x:12345 → 140.x.x.x:443
```

## Design Decisions

* Scapy is used for low-level packet capture and parsing.
* CLI dashboard chosen for simplicity and real-time performance.
* Modular architecture ensures extensibility.
* Heap-based top-k computation improves performance.
* Separate dump tool avoids clutter in main UI.

## Limitations

* Encrypted traffic (HTTPS/QUIC) cannot be decrypted
* Payload inspection limited to metadata and raw bytes
* No GUI (CLI only)

## Future Improvements

* GUI interface
* Export to CSV/JSON
* Traffic visualization graphs
* DNS decoding enhancements
* Anomaly detection

## Conclusion

The tool provides a structured and efficient way to observe network behavior in real time. It combines packet-level inspection with system-level analytics while maintaining a clean and extensible design.

If you want, I can also generate:

* a shorter version for GitHub landing
* resume bullet points
* or viva questions and answers
