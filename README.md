# HECForwarder
Splunk HTTP Event Collector Forwarder

This script was created by Claude Sonnet 4

## Usage:

### Install dependencies:
`pip install flask requests`

### Configure by editing `hec_config.json`:
```json
{
  "port": 8088,
  "host": "0.0.0.0",
  "valid_tokens": ["your-token-here"],
  "indexers": [
    {
      "url": "https://your-splunk-server:8088",
      "token": "your-splunk-hec-token",
      "enabled": true
    }
  ]
}
```

### Run the collector:
`bashpython hec_emulator.py`

Send events to `http://localhost:8088/services/collector/event with proper authorization headers`

### Monitoring:

Health check: `GET /services/collector/health`
Statistics: `GET /services/collector/stats`

The system ensures no data loss by persisting all events to disk before acknowledging receipt, and continuously attempts to forward them to available Splunk indexers.
