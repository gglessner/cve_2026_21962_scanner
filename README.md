# CVE-2026-21962 Remote Vulnerability Scanner

A Python-based remote vulnerability scanner for detecting hosts vulnerable to **CVE-2026-21962**, a critical unauthenticated remote vulnerability in Oracle HTTP Server and WebLogic Server Proxy Plug-in.

## Vulnerability Overview

| Attribute | Value |
|-----------|-------|
| **CVE ID** | CVE-2026-21962 |
| **CVSS v3.1** | 10.0 (Critical) |
| **Attack Vector** | Network (HTTP) |
| **Authentication** | None required |
| **Disclosure Date** | January 20, 2026 |

### Affected Products

| Product | Affected Versions |
|---------|-------------------|
| Oracle HTTP Server | 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 |
| WebLogic Proxy Plug-in (Apache) | 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0 |
| WebLogic Proxy Plug-in (IIS) | **12.2.1.4.0 only** |

### Impact

Successful exploitation allows an unauthenticated remote attacker to:
- Read all accessible data
- Create, modify, or delete data
- Pivot to backend WebLogic servers (scope change)

### Architecture

The vulnerability exists in the **proxy plug-in layer**, not WebLogic Server itself:

```
                         VULNERABILITY HERE
                                 |
                                 v
Internet --> [Apache/IIS :80/:443] --> [Proxy Plugin] --> [WebLogic :7001]
                    ^                       ^                    ^
                    |                       |                    |
             Front-end server         mod_wl_ohs.so         Backend server
             (scan these ports)       iisproxy.dll          (not affected)
```

**Important:** This scanner targets the front-end proxy ports (80/443), NOT the WebLogic admin port (7001). Scanning port 7001 directly bypasses the vulnerable proxy component.

| Port | Component | Scan? |
|------|-----------|-------|
| 80/443 | Apache/IIS with WebLogic Proxy Plugin | Yes |
| 7001 | WebLogic Server directly | No (bypasses proxy) |

## Installation

### Requirements

- Python 3.7+
- requests library

### Setup

```bash
# Clone or download the repository
cd CVE-2026-21962

# Install dependencies
pip install -r requirements.txt
```

## Usage

### Basic Scan

```bash
# Scan a single target
python cve_2026_21962_scanner.py -t example.com

# Scan specific port
python cve_2026_21962_scanner.py -t example.com:8080

# Scan HTTPS endpoint
python cve_2026_21962_scanner.py -t https://secure.example.com
```

### Scan Multiple Targets

```bash
# Scan from file
python cve_2026_21962_scanner.py -f targets.txt

# With JSON output
python cve_2026_21962_scanner.py -f targets.txt -o results.json

# With CSV output
python cve_2026_21962_scanner.py -f targets.txt -o results.csv --format csv
```

### Advanced Options

```bash
# Verbose output with 20 threads
python cve_2026_21962_scanner.py -t example.com -v --threads 20

# Quiet mode (only show vulnerable hosts)
python cve_2026_21962_scanner.py -f targets.txt -q

# Custom timeout
python cve_2026_21962_scanner.py -t example.com --timeout 15
```

### Target File Format

Create a text file with one target per line:

```
# targets.txt
example.com
192.168.1.10:8080
https://secure.target.com
http://internal.corp:80

# Comments are ignored
# Note: Scan front-end proxy ports (80/443), not WebLogic port (7001)
```

## Command-Line Options

| Option | Description |
|--------|-------------|
| `-t, --target` | Single target (host, host:port, or URL) |
| `-f, --file` | File containing targets (one per line) |
| `-o, --output` | Output file for results |
| `--format` | Output format: `json` (default) or `csv` |
| `--threads` | Number of concurrent threads (default: 10) |
| `--timeout` | Request timeout in seconds (default: 10) |
| `-v, --verbose` | Verbose output with detailed findings |
| `-q, --quiet` | Quiet mode - only show vulnerable hosts |

### Timeout Behavior

The `--timeout` option controls the main HTTP request timeout. For efficiency, probe requests use optimized timeouts:

| Operation | Timeout |
|-----------|---------|
| Port check | min(--timeout, 5s) |
| Initial fingerprint request | --timeout value |
| Admin path probes | min(--timeout, 5s) |
| Malformed request probes | min(--timeout, 5s) |
| Header variation probes | min(--timeout, 5s) |

This prevents slow hosts from significantly delaying scans while still allowing longer timeouts for the primary fingerprinting request when needed.

## Output

### Console Output

```
================================================================================
  CVE-2026-21962 Remote Vulnerability Scanner
  Oracle HTTP Server / WebLogic Server Proxy Plug-in
  CVSS 10.0 - Critical Unauthenticated Remote Vulnerability
================================================================================

[VULNERABLE] https://target.com:443 (confidence: 85%) [version: 14.1.1.0.0] [APACHE]
[POTENTIAL] http://example.com:80 (confidence: 55%) [version: 12.2.1.4.0]
[SAFE] https://secure.site.com:443
[ERROR] http://offline.host:80 - Port 80 not reachable
```

### Status Codes

| Status | Meaning |
|--------|---------|
| `[VULNERABLE]` | High confidence (70%+) - likely vulnerable |
| `[POTENTIAL]` | Medium confidence (40-69%) - needs investigation |
| `[INVESTIGATE]` | Low confidence (1-39%) - Oracle indicators found |
| `[SAFE]` | No vulnerability indicators detected |
| `[ERROR]` | Scan error (connection failed, etc.) |
| `[TIMEOUT]` | Connection timed out |

### Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No vulnerabilities found |
| 1 | Potentially vulnerable hosts found |
| 2 | Confirmed vulnerable hosts found |

## Detection Methods

The scanner uses multiple techniques to identify vulnerable systems:

### 1. Service Fingerprinting

- HTTP `Server` header analysis
- `X-Powered-By` header detection
- Oracle/WebLogic patterns in response body

### 2. WebLogic Proxy Header Detection

Checks for WebLogic-specific headers:
- `WL-Proxy-Client-IP`
- `WL-Proxy-SSL`
- `X-WebLogic-Request-ClusterInfo`
- `X-WebLogic-KeepAliveSecs`

### 3. Oracle-Specific Headers

- `X-Oracle-DMS-ECID`
- `X-Oracle-DMS-RID`
- `X-ORACLE-BMC-ECID`

### 4. Version Detection

Extracts version strings matching affected versions:
- `12.2.1.4.0` (Apache and IIS)
- `14.1.1.0.0` (Apache only)
- `14.1.2.0.0` (Apache only)

**Note:** The scanner automatically detects the server type (Apache vs IIS) and applies version-specific logic. IIS deployments are only vulnerable if running version 12.2.1.4.0.

### 5. Admin Path Probing

Tests for accessible WebLogic endpoints:
- `/console/` - Admin Console
- `/wls-wsat/` - Web Services
- `/bea_wls_internal/` - Internal paths
- `/_async/` - Async servlet

### 6. Behavioral Analysis

- Malformed path traversal probes
- Header case variation tests
- Request smuggling indicators

## Confidence Scoring

| Finding | Points |
|---------|--------|
| Oracle server indicators | +30 |
| WebLogic proxy headers | +25 |
| Oracle DMS headers | +10 |
| Affected version detected | +30 |
| Admin paths accessible | +15 |
| Anomalous behavior detected | +20 |
| Header variation response | +10 |

**Thresholds:**
- 70%+ = Vulnerable
- 40-69% = Potentially Vulnerable
- 1-39% = Requires Investigation

## JSON Output Example

```json
[
  {
    "host": "target.example.com",
    "port": 443,
    "ssl": true,
    "status": "vulnerable",
    "confidence": 85,
    "server_header": "Oracle-HTTP-Server/14.1.1.0.0",
    "detected_version": "14.1.1.0.0",
    "server_type": "apache",
    "oracle_indicators": ["Server header: Oracle-HTTP-Server/14.1.1.0.0"],
    "weblogic_headers": ["WL-Proxy-Client-IP: 10.0.0.1"],
    "oracle_headers": [],
    "admin_paths_found": ["/console/ (HTTP 302)"],
    "response_anomalies": [],
    "error_message": "",
    "scan_time": "2026-01-22T10:30:00.000000"
  }
]
```

## Remediation

If vulnerable hosts are identified:

1. **Apply Oracle's January 2026 Critical Patch Update immediately**
   - Download: https://www.oracle.com/security-alerts/cpujan2026.html

2. **Temporary mitigations** (if patching is delayed):
   - Restrict network access to affected servers
   - Deploy WAF rules to block malformed requests
   - Enable detailed HTTP logging for forensic analysis
   - Disable WebLogic proxy functionality if not required

## References

- **NVD**: https://nvd.nist.gov/vuln/detail/CVE-2026-21962
- **Oracle Advisory**: https://www.oracle.com/security-alerts/cpujan2026.html
- **Oracle Verbose Advisory**: https://www.oracle.com/security-alerts/cpujan2026verbose.html

## Additional Documentation

**[CVE-2026-21962_Research.md](CVE-2026-21962_Research.md)** - Detailed vulnerability research:
- Complete technical analysis
- CVSS vector breakdown
- Proof-of-concept status
- Historical timeline
- Detection methodology
- Remediation guidance

**[CHEAT-SHEET.md](CHEAT-SHEET.md)** - Detection indicator reference:
- All server headers and their meanings
- WebLogic proxy headers explained
- Admin paths and their risk levels
- Path traversal probes and responses
- Response anomalies interpretation
- Version string patterns

## Legal Disclaimer

This tool is provided for **authorized security testing only**. 

- Only scan systems you own or have explicit written permission to test
- Unauthorized scanning may violate computer crime laws
- The author is not responsible for misuse of this tool

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

## Author

**Garland Glessner**  
Email: gglessner@gmail.com

## Contributing

Contributions are welcome. Please submit pull requests or open issues for:
- Bug reports
- Detection improvements
- New features
- Documentation updates
