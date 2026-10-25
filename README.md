# Network Intrusion Detection System (NIDS)

A Python-based Network Intrusion Detection System built using Suricata and Flask. It collects network events from Suricata's EVE JSON logs and presents them through a real-time monitoring dashboard.

## Features

- Network event monitoring using Suricata
- Custom IDS rule for ICMP Echo Requests
- Flask dashboard with a dark-themed interface
- Event counts, alert severity, event timeline, and top source IP visualizations
- Recent security alerts table
- JSON API for dashboard data
- Automated tests using pytest

## Technology Stack

- Python
- Suricata
- Flask
- Plotly
- Pytest
- JSON

## Project Structure

```text
NIDS-Project/
├── dashboard/
│   ├── __init__.py
│   └── app.py
├── logs/
├── rules/
│   └── local.rules
├── tests/
│   └── test_dashboard.py
├── .gitignore
├── requirements.txt
├── suricata.yaml
└── README.md
```

## Prerequisites

- Python 3.11 or newer
- Suricata installed and configured
- pip

## Installation

1. Clone the repository:

   ```bash
   git clone <YOUR_GITHUB_REPOSITORY_URL>
   cd NIDS-Project
   ```

2. Create and activate a virtual environment:

   macOS/Linux:

   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Configure Suricata to write EVE JSON events to the log path expected by the dashboard. Update the configuration for your own system and network interface.

## Custom Detection Rule

The project includes a local Suricata rule that detects ICMP Echo Requests:

```text
alert icmp any any -> any any (msg:"NIDS Test - ICMP Echo Request"; itype:8; sid:1000001; rev:1;)
```

Detection depends on the traffic being visible to Suricata and the rule being loaded correctly.

## Running the Dashboard

From the project root, activate the virtual environment and run:

```bash
python dashboard/app.py
```

Open the dashboard at:

http://127.0.0.1:5001

The dashboard API is available at:

http://127.0.0.1:5001/api/data

## Running Tests

Run the automated test suite:

```bash
python -m pytest -v
```

## Important Notes

- The dashboard displays events present in the configured Suricata EVE JSON log.
- The dashboard must have access to the log file to display live data.
- Update machine-specific paths and network interface settings before running on another computer.
- Alerts indicate rule matches and do not necessarily confirm a successful intrusion.
- Only monitor networks you own or have explicit permission to test.

## Future Improvements

- Add alert filtering and search
- Add configurable alert notifications
- Improve deployment and cross-platform configuration
- Add integration tests for the dashboard API

## Author

Rishi Sharma
