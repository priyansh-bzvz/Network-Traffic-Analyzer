
# NetScope - Network Traffic Analyzer

A real-time network traffic analyzer developed using Python, Scapy, Flask, HTML, CSS, and JavaScript.

## Features

- Live network packet capture
- Source and destination IP addresses
- Source and destination ports
- TCP, UDP, ICMP, and Other protocol statistics
- Real-time dashboard and protocol distribution chart
- Capture duration timer
- Reset statistics
- Excel report export

## Technologies Used

- Python
- Scapy
- Flask
- Npcap
- HTML, CSS, JavaScript
- OpenPyXL

## Installation

1. Install Python and Npcap on Windows.
2. Clone this repository.
3. Create a Python virtual environment.
4. Install dependencies:

```bash
pip install -r requirements.txt
```

5. Run the application:

```bash
python app.py
```

6. Open `http://127.0.0.1:5000` in your browser.

## Note

This application monitors network traffic on the selected interface. It does not automatically identify the website or application associated with each packet.
