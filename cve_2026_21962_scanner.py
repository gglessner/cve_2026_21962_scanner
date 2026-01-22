#!/usr/bin/env python3
"""
CVE-2026-21962 Remote Vulnerability Scanner
============================================
Detects hosts vulnerable to CVE-2026-21962 - Critical unauthenticated remote
vulnerability in Oracle HTTP Server and WebLogic Server Proxy Plug-in.

Affected versions:
  - Oracle HTTP Server: 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0
  - WebLogic Server Proxy Plug-in for Apache: 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0
  - WebLogic Server Proxy Plug-in for IIS: 12.2.1.4.0

CVSS v3.1 Score: 10.0 (Critical)
Attack Vector: Network (HTTP), No authentication required

Author: Garland Glessner <gglessner@gmail.com>
Copyright (C) 2026 Garland Glessner

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
"""

import argparse
import concurrent.futures
import csv
import json
import re
import socket
import ssl
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime
from typing import List, Optional, Dict, Tuple
from urllib.parse import urlparse

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] requests library required: pip install requests")
    sys.exit(1)

# Suppress SSL warnings for self-signed certs
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# CVE References
CVE_REFERENCES = {
    "nvd": "https://nvd.nist.gov/vuln/detail/CVE-2026-21962",
    "oracle_cpu": "https://www.oracle.com/security-alerts/cpujan2026.html",
    "oracle_verbose": "https://www.oracle.com/security-alerts/cpujan2026verbose.html",
}

# Affected version patterns
# Note: IIS plugin is ONLY affected in 12.2.1.4.0
AFFECTED_VERSIONS_ALL = [
    "12.2.1.4.0",
    "14.1.1.0.0", 
    "14.1.2.0.0"
]

AFFECTED_VERSIONS_IIS_ONLY = [
    "12.2.1.4.0"
]

# Detection patterns for Oracle HTTP Server / WebLogic Proxy
ORACLE_SERVER_PATTERNS = [
    r"Oracle-HTTP-Server",
    r"Oracle HTTP Server",
    r"Oracle-Application-Server",
    r"Oracle-Fusion-Middleware",
    r"WebLogic Server",
    r"WebLogic",
    r"mod_wl",
    r"mod_wl_ohs",
    r"mod_wl_24",
    r"WL-Proxy",
]

# IIS-specific detection patterns
IIS_SERVER_PATTERNS = [
    r"Microsoft-IIS",
    r"IIS/\d+",
    r"ASP\.NET",
]

VERSION_PATTERNS = [
    r"(\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2}\.\d{1,2})",  # e.g., 14.1.1.0.0
    r"version[:\s]+(\d+\.\d+\.\d+\.\d+\.\d+)",
    r"Oracle-HTTP-Server/(\d+\.\d+\.\d+\.\d+\.\d+)",
    r"Oracle-HTTP-Server/(\d+\.\d+\.\d+)",
    r"WebLogic[:\s/]+(\d+\.\d+\.\d+)",
    r"mod_wl[_/](\d+)",
]

# WebLogic proxy-specific headers (presence indicates WebLogic proxy)
WEBLOGIC_PLUGIN_HEADERS = [
    "WL-Proxy-Client-IP",
    "WL-Proxy-SSL", 
    "WL-Proxy-Client-Keysize",
    "WL-Proxy-Client-Secretkeysize",
    "X-WebLogic-Request-ClusterInfo",
    "X-WebLogic-KeepAliveSecs",
    "X-WebLogic-Force-JVMID",
    "Proxy-Client-ID",
]

# Additional Oracle-specific headers to check
ORACLE_SPECIFIC_HEADERS = [
    "X-Oracle-DMS-ECID",
    "X-Oracle-DMS-RID", 
    "X-ORACLE-DMS-ECID",
    "X-ORACLE-BMC-ECID",
]


@dataclass
class ScanResult:
    """Holds scan result for a single target."""
    host: str
    port: int
    ssl: bool
    status: str  # "vulnerable", "potentially_vulnerable", "not_vulnerable", "error", "timeout"
    confidence: int  # 0-100
    server_header: str = ""
    detected_version: str = ""
    server_type: str = ""  # "apache", "iis", "unknown"
    oracle_indicators: List[str] = field(default_factory=list)
    weblogic_headers: List[str] = field(default_factory=list)
    oracle_headers: List[str] = field(default_factory=list)
    response_anomalies: List[str] = field(default_factory=list)
    admin_paths_found: List[str] = field(default_factory=list)
    error_message: str = ""
    scan_time: str = ""

    def to_dict(self) -> Dict:
        return asdict(self)


class CVE2026_21962_Scanner:
    """Scanner for CVE-2026-21962 vulnerability detection."""
    
    def __init__(self, timeout: int = 10, retries: int = 2, user_agent: str = None):
        self.timeout = timeout
        self.retries = retries
        self.user_agent = user_agent or "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        """Create requests session with retry logic."""
        session = requests.Session()
        retry = Retry(
            total=self.retries,
            backoff_factor=0.5,
            status_forcelist=[502, 503, 504]
        )
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        return session
    
    def _get_base_headers(self) -> Dict[str, str]:
        """Return base HTTP headers for requests."""
        return {
            "User-Agent": self.user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "close",
        }
    
    def check_port(self, host: str, port: int) -> bool:
        """Quick TCP port check using configured timeout."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(min(self.timeout, 5))  # Use configured timeout, max 5s for port check
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False
    
    def _extract_version(self, text: str) -> Optional[str]:
        """Extract version number from text."""
        for pattern in VERSION_PATTERNS:
            match = re.search(pattern, text, re.IGNORECASE)
            if match:
                version = match.group(1)
                # Normalize to x.x.x.x.x format if needed
                parts = version.split(".")
                if len(parts) >= 3:
                    return version
        return None
    
    def _check_oracle_indicators(self, response: requests.Response) -> Tuple[List[str], str]:
        """Check response for Oracle HTTP Server / WebLogic indicators."""
        indicators = []
        server_header = ""
        
        # Check Server header
        server = response.headers.get("Server", "")
        if server:
            server_header = server
            for pattern in ORACLE_SERVER_PATTERNS:
                if re.search(pattern, server, re.IGNORECASE):
                    indicators.append(f"Server header: {server}")
                    break
        
        # Check X-Powered-By
        powered_by = response.headers.get("X-Powered-By", "")
        if powered_by:
            for pattern in ORACLE_SERVER_PATTERNS:
                if re.search(pattern, powered_by, re.IGNORECASE):
                    indicators.append(f"X-Powered-By: {powered_by}")
                    break
        
        # Check response body for Oracle references
        if response.text:
            body_lower = response.text.lower()
            if "oracle" in body_lower and ("weblogic" in body_lower or "http server" in body_lower):
                indicators.append("Oracle/WebLogic reference in response body")
            if "mod_wl" in body_lower:
                indicators.append("mod_wl (WebLogic module) reference in body")
        
        return indicators, server_header
    
    def _check_weblogic_headers(self, response: requests.Response) -> List[str]:
        """Check for WebLogic proxy-specific headers."""
        found = []
        for header in WEBLOGIC_PLUGIN_HEADERS:
            if header in response.headers:
                found.append(f"{header}: {response.headers[header]}")
        return found
    
    def _check_oracle_headers(self, response: requests.Response) -> List[str]:
        """Check for Oracle-specific headers (DMS, BMC, etc.)."""
        found = []
        for header in ORACLE_SPECIFIC_HEADERS:
            if header in response.headers:
                found.append(f"{header}: {response.headers[header]}")
        return found
    
    def _detect_server_type(self, response: requests.Response) -> str:
        """Detect if server is Apache or IIS based."""
        server = response.headers.get("Server", "").lower()
        
        # Check for IIS
        for pattern in IIS_SERVER_PATTERNS:
            if re.search(pattern, server, re.IGNORECASE):
                return "iis"
        
        # Check for Apache
        if "apache" in server or "httpd" in server:
            return "apache"
        
        # Check for Oracle HTTP Server (Apache-based)
        if "oracle" in server:
            return "apache"  # Oracle HTTP Server is Apache-based
        
        return "unknown"
    
    def _probe_admin_paths(self, url: str) -> List[str]:
        """
        Probe for WebLogic admin and management paths.
        These endpoints are commonly exposed and help confirm WebLogic presence.
        Uses shorter timeout for faster scanning.
        """
        admin_paths = [
            "/console/",                    # WebLogic Admin Console
            "/console/login/LoginForm.jsp", # Console login page
            "/wls-wsat/",                   # WLS-WSAT (Web Services Atomic Transactions)
            "/bea_wls_internal/",           # Internal BEA/WebLogic path
            "/_async/",                     # Async servlet path
            "/wls-cat/",                    # WebLogic CAT
            "/uddiexplorer/",               # UDDI Explorer
            "/console/css/login.css",       # Console CSS (version leak)
        ]
        
        found_paths = []
        base_url = url.rstrip("/")
        probe_timeout = min(self.timeout, 5)  # Shorter timeout for path probes
        
        for path in admin_paths:
            try:
                resp = self.session.get(
                    f"{base_url}{path}",
                    headers=self._get_base_headers(),
                    timeout=probe_timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # Path exists if we get 200, 302 (redirect to login), or 401/403 (auth required)
                if resp.status_code in [200, 301, 302, 401, 403]:
                    found_paths.append(f"{path} (HTTP {resp.status_code})")
                    
            except Exception:
                pass
        
        return found_paths
    
    def _probe_malformed_request(self, url: str) -> Tuple[bool, str]:
        """
        Send malformed request to detect vulnerable behavior.
        Vulnerable systems may respond differently to path traversal attempts
        or malformed headers that the proxy plug-in mishandles.
        """
        anomalies = []
        vulnerable_behavior = False
        
        test_paths = [
            # Path normalization probes
            "/?test=..%2e..%2f",
            "/..;/",                        # Semicolon path parameter bypass
            "/%2e%2e/",                     # URL-encoded traversal
            "/%252e%252e/",                 # Double-encoded traversal
            "/..%00/",                      # Null byte injection
            # WebLogic-specific paths
            "/weblogic/",
            "/_wl_proxy/",
            "/bea_wls_internal/",
            # Request smuggling probes
            "/",                            # With malformed headers (below)
        ]
        
        malformed_headers = {
            **self._get_base_headers(),
            "Transfer-Encoding": "chunked, chunked",  # Duplicate TE header value
            "X-Forwarded-For": "127.0.0.1" * 50,  # Long header value
        }
        
        base_url = url.rstrip("/")
        
        probe_timeout = min(self.timeout, 5)  # Shorter timeout for probes
        
        for path in test_paths:
            try:
                resp = self.session.get(
                    f"{base_url}{path}",
                    headers=malformed_headers,
                    timeout=probe_timeout,
                    verify=False,
                    allow_redirects=False
                )
                
                # Check for error responses that leak plugin info
                if resp.status_code in [400, 500, 502, 503]:
                    body = resp.text.lower()
                    if any(kw in body for kw in ["weblogic", "mod_wl", "oracle", "plugin"]):
                        anomalies.append(f"Plugin error leak on {path} (status {resp.status_code})")
                        vulnerable_behavior = True
                
                # Check for inconsistent behavior suggesting proxy issues
                if resp.status_code == 200 and ".." in path:
                    anomalies.append(f"Path traversal not blocked: {path}")
                    vulnerable_behavior = True
                    
            except Exception:
                pass
        
        return vulnerable_behavior, "; ".join(anomalies) if anomalies else ""
    
    def _probe_header_case_variation(self, url: str) -> Tuple[bool, str]:
        """
        Check for header case variations between requests.
        Oracle WebLogic Proxy Plug-in may alter header casing in specific ways.
        """
        probe_timeout = min(self.timeout, 5)  # Shorter timeout for probes
        
        try:
            # Standard request
            resp1 = self.session.get(
                url,
                headers=self._get_base_headers(),
                timeout=probe_timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Request with varied header casing
            varied_headers = {
                "user-agent": self.user_agent,
                "ACCEPT": "text/html,*/*",
                "accept-LANGUAGE": "en-US",
            }
            resp2 = self.session.get(
                url,
                headers=varied_headers,
                timeout=probe_timeout,
                verify=False,
                allow_redirects=False
            )
            
            # Compare response headers for case normalization patterns
            h1_keys = set(k.lower() for k in resp1.headers.keys())
            h2_keys = set(k.lower() for k in resp2.headers.keys())
            
            # Check for WL-specific headers appearing
            for h in WEBLOGIC_PLUGIN_HEADERS:
                if h.lower() in h1_keys or h.lower() in h2_keys:
                    return True, f"WebLogic header detected: {h}"
            
            # Check for header count differences (proxy adding headers)
            if abs(len(resp1.headers) - len(resp2.headers)) > 2:
                return True, "Header count variation detected (proxy behavior)"
                
        except Exception:
            pass
        
        return False, ""
    
    def scan_target(self, host: str, port: int = None, use_ssl: bool = None) -> ScanResult:
        """
        Scan a single target for CVE-2026-21962 vulnerability.
        
        Args:
            host: Target hostname or IP
            port: Target port (default: 80 for HTTP, 443 for HTTPS)
            use_ssl: Force SSL/TLS (auto-detect if None)
        """
        scan_start = datetime.now().isoformat()
        
        # Auto-detect port and SSL
        if port is None:
            port = 443 if use_ssl else 80
        if use_ssl is None:
            use_ssl = port == 443
        
        scheme = "https" if use_ssl else "http"
        url = f"{scheme}://{host}:{port}"
        
        result = ScanResult(
            host=host,
            port=port,
            ssl=use_ssl,
            status="not_vulnerable",
            confidence=0,
            scan_time=scan_start
        )
        
        # Port check
        if not self.check_port(host, port):
            result.status = "error"
            result.error_message = f"Port {port} not reachable"
            return result
        
        try:
            # Initial request to gather fingerprint
            response = self.session.get(
                url,
                headers=self._get_base_headers(),
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )
            
            # Detect server type (Apache vs IIS)
            server_type = self._detect_server_type(response)
            result.server_type = server_type
            
            # Check Oracle indicators
            oracle_indicators, server_header = self._check_oracle_indicators(response)
            result.oracle_indicators = oracle_indicators
            result.server_header = server_header
            
            # Check WebLogic-specific headers
            wl_headers = self._check_weblogic_headers(response)
            result.weblogic_headers = wl_headers
            
            # Check Oracle-specific headers (DMS, etc.)
            oracle_headers = self._check_oracle_headers(response)
            result.oracle_headers = oracle_headers
            
            # Extract version if present
            all_text = server_header + " " + response.text[:5000]
            detected_version = self._extract_version(all_text)
            if detected_version:
                result.detected_version = detected_version
            
            # Calculate base confidence from fingerprinting
            confidence = 0
            
            if oracle_indicators:
                confidence += 30
            if wl_headers:
                confidence += 25
            if oracle_headers:
                confidence += 10  # Additional Oracle header presence
            
            if detected_version:
                # Determine which version list to use based on server type
                # IIS plugin is ONLY affected in 12.2.1.4.0
                if server_type == "iis":
                    affected_versions = AFFECTED_VERSIONS_IIS_ONLY
                else:
                    affected_versions = AFFECTED_VERSIONS_ALL
                
                # Check if detected version is in affected list
                version_matched = False
                for affected in affected_versions:
                    if affected in detected_version or detected_version in affected:
                        confidence += 30
                        version_matched = True
                        break
                
                if not version_matched:
                    # Version detected but not in affected list
                    if server_type == "iis" and detected_version in ["14.1.1.0.0", "14.1.2.0.0"]:
                        # IIS with non-vulnerable version
                        confidence += 5  # Lower confidence - version not affected on IIS
                        result.response_anomalies.append(
                            f"Note: IIS plugin v{detected_version} is NOT affected (only 12.2.1.4.0)"
                        )
                    else:
                        confidence += 10  # Unknown version
            
            # Probe for admin paths (helps confirm WebLogic presence)
            if confidence >= 15:
                admin_paths = self._probe_admin_paths(url)
                result.admin_paths_found = admin_paths
                if admin_paths:
                    confidence += 15  # WebLogic admin paths accessible
            
            # Probe for vulnerable behavior
            if confidence >= 20:  # Only probe if we have some Oracle indicators
                vuln_behavior, anomaly_msg = self._probe_malformed_request(url)
                if vuln_behavior:
                    confidence += 20
                    result.response_anomalies.append(anomaly_msg)
                
                header_vuln, header_msg = self._probe_header_case_variation(url)
                if header_vuln:
                    confidence += 10
                    result.response_anomalies.append(header_msg)
            
            # Determine final status
            result.confidence = min(confidence, 100)
            
            if confidence >= 70:
                result.status = "vulnerable"
            elif confidence >= 40:
                result.status = "potentially_vulnerable"
            elif confidence > 0:
                result.status = "requires_investigation"
            else:
                result.status = "not_vulnerable"
                
        except requests.exceptions.Timeout:
            result.status = "timeout"
            result.error_message = "Connection timed out"
        except requests.exceptions.SSLError as e:
            result.status = "error"
            error_str = str(e)
            # Extract meaningful part of SSL error
            if "CERTIFICATE_VERIFY_FAILED" in error_str:
                result.error_message = "SSL certificate verification failed"
            elif "WRONG_VERSION_NUMBER" in error_str:
                result.error_message = "SSL wrong version (try HTTP instead of HTTPS)"
            else:
                result.error_message = f"SSL error: {error_str[:200]}"
        except requests.exceptions.ConnectionError as e:
            result.status = "error"
            error_str = str(e)
            # Extract meaningful connection error info
            if "Connection refused" in error_str or "actively refused" in error_str:
                result.error_message = "Connection refused (port closed or filtered)"
            elif "No route to host" in error_str:
                result.error_message = "No route to host (network unreachable)"
            elif "Name or service not known" in error_str or "getaddrinfo failed" in error_str:
                result.error_message = "DNS resolution failed (host not found)"
            elif "Connection reset" in error_str:
                result.error_message = "Connection reset by peer"
            elif "timed out" in error_str.lower():
                result.error_message = "Connection timed out"
            else:
                result.error_message = f"Connection error: {error_str[:200]}"
        except Exception as e:
            result.status = "error"
            result.error_message = f"Unexpected error: {str(e)[:200]}"
        
        return result


def parse_targets(target_input: str) -> List[Tuple[str, int, bool]]:
    """
    Parse target input into list of (host, port, ssl) tuples.
    Supports: hostname, hostname:port, http://host, https://host:port, CIDR (basic)
    """
    targets = []
    
    for line in target_input.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        
        # Handle URL format
        if line.startswith("http://") or line.startswith("https://"):
            parsed = urlparse(line)
            host = parsed.hostname
            ssl = parsed.scheme == "https"
            port = parsed.port or (443 if ssl else 80)
            targets.append((host, port, ssl))
        elif ":" in line and not line.count(":") > 1:  # host:port (not IPv6)
            host, port_str = line.rsplit(":", 1)
            try:
                port = int(port_str)
                ssl = port == 443
                targets.append((host, port, ssl))
            except ValueError:
                targets.append((line, 80, False))
                targets.append((line, 443, True))
        else:
            # Plain hostname - scan both ports
            targets.append((line, 80, False))
            targets.append((line, 443, True))
    
    return targets


def print_banner():
    """Print scanner banner."""
    banner = """
================================================================================
  CVE-2026-21962 Remote Vulnerability Scanner
  Oracle HTTP Server / WebLogic Server Proxy Plug-in
  CVSS 10.0 - Critical Unauthenticated Remote Vulnerability
================================================================================
  Affected Versions:
    - Oracle HTTP Server: 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0
    - WebLogic Proxy Plug-in (Apache): 12.2.1.4.0, 14.1.1.0.0, 14.1.2.0.0
    - WebLogic Proxy Plug-in (IIS): 12.2.1.4.0 ONLY
  
  References:
    - NVD: https://nvd.nist.gov/vuln/detail/CVE-2026-21962
    - Oracle CPU: https://www.oracle.com/security-alerts/cpujan2026.html
  
  [!] For authorized security testing only
================================================================================
"""
    print(banner)


def print_result(result: ScanResult, verbose: bool = False):
    """Print scan result to console."""
    status_symbols = {
        "vulnerable": "[VULNERABLE]",
        "potentially_vulnerable": "[POTENTIAL]",
        "requires_investigation": "[INVESTIGATE]",
        "not_vulnerable": "[SAFE]",
        "error": "[ERROR]",
        "timeout": "[TIMEOUT]",
    }
    
    symbol = status_symbols.get(result.status, "[?]")
    scheme = "https" if result.ssl else "http"
    
    base_msg = f"{symbol} {scheme}://{result.host}:{result.port}"
    
    if result.status in ["vulnerable", "potentially_vulnerable"]:
        base_msg += f" (confidence: {result.confidence}%)"
        if result.detected_version:
            base_msg += f" [version: {result.detected_version}]"
        if result.server_type and result.server_type != "unknown":
            base_msg += f" [{result.server_type.upper()}]"
    elif result.status == "error":
        base_msg += f" - {result.error_message}"
    
    print(base_msg)
    
    # Always show full detection evidence for vulnerable/potential hosts
    if result.status in ["vulnerable", "potentially_vulnerable", "requires_investigation"]:
        if result.server_header:
            print(f"    Server: {result.server_header}")
        if result.oracle_indicators:
            for indicator in result.oracle_indicators:
                print(f"    [+] {indicator}")
        if result.weblogic_headers:
            for header in result.weblogic_headers:
                print(f"    [+] WebLogic Header: {header}")
        if result.oracle_headers:
            for header in result.oracle_headers:
                print(f"    [+] Oracle Header: {header}")
        if result.admin_paths_found:
            for path in result.admin_paths_found:
                print(f"    [+] Admin Path: {path}")
        if result.response_anomalies:
            for anomaly in result.response_anomalies:
                print(f"    [!] Anomaly: {anomaly}")
    
    # Verbose mode shows additional context
    if verbose and result.status in ["vulnerable", "potentially_vulnerable", "requires_investigation"]:
        if result.server_type:
            print(f"    Server Type: {result.server_type}")


def save_results(results: List[ScanResult], output_file: str, format: str = "json"):
    """Save results to file."""
    if format == "json":
        with open(output_file, "w") as f:
            json.dump([r.to_dict() for r in results], f, indent=2)
    elif format == "csv":
        with open(output_file, "w", newline="") as f:
            if results:
                writer = csv.DictWriter(f, fieldnames=results[0].to_dict().keys())
                writer.writeheader()
                for r in results:
                    row = r.to_dict()
                    # Convert lists to strings for CSV
                    for k, v in row.items():
                        if isinstance(v, list):
                            row[k] = "; ".join(v)
                    writer.writerow(row)
    print(f"\n[+] Results saved to: {output_file}")


def main():
    parser = argparse.ArgumentParser(
        description="CVE-2026-21962 Remote Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s -t example.com
  %(prog)s -t example.com:8080
  %(prog)s -t https://example.com
  %(prog)s -f targets.txt -o results.json
  %(prog)s -t 192.168.1.1 -v --threads 20
        """
    )
    
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-t", "--target", help="Single target (host, host:port, or URL)")
    target_group.add_argument("-f", "--file", help="File containing targets (one per line)")
    
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("--format", choices=["json", "csv"], default="json",
                        help="Output format (default: json)")
    parser.add_argument("--threads", type=int, default=10,
                        help="Number of concurrent threads (default: 10)")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout in seconds (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Verbose output")
    parser.add_argument("-q", "--quiet", action="store_true",
                        help="Quiet mode - only show vulnerable hosts")
    
    args = parser.parse_args()
    
    if not args.quiet:
        print_banner()
    
    # Parse targets
    if args.target:
        target_input = args.target
    else:
        with open(args.file, "r") as f:
            target_input = f.read()
    
    targets = parse_targets(target_input)
    
    if not targets:
        print("[!] No valid targets specified")
        sys.exit(1)
    
    if not args.quiet:
        print(f"[*] Scanning {len(targets)} target(s) with {args.threads} threads...\n")
    
    # Initialize scanner
    scanner = CVE2026_21962_Scanner(timeout=args.timeout)
    
    # Scan targets
    results = []
    vulnerable_count = 0
    potential_count = 0
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
        future_to_target = {
            executor.submit(scanner.scan_target, host, port, ssl): (host, port, ssl)
            for host, port, ssl in targets
        }
        
        for future in concurrent.futures.as_completed(future_to_target):
            result = future.result()
            results.append(result)
            
            if result.status == "vulnerable":
                vulnerable_count += 1
            elif result.status == "potentially_vulnerable":
                potential_count += 1
            
            if not args.quiet or result.status in ["vulnerable", "potentially_vulnerable"]:
                print_result(result, verbose=args.verbose)
    
    # Summary
    if not args.quiet:
        print("\n" + "=" * 60)
        print(f"Scan Complete: {len(results)} targets scanned")
        print(f"  Vulnerable: {vulnerable_count}")
        print(f"  Potentially Vulnerable: {potential_count}")
        print(f"  Safe/Other: {len(results) - vulnerable_count - potential_count}")
    
    # Save results
    if args.output:
        save_results(results, args.output, args.format)
    
    # Exit code based on findings
    if vulnerable_count > 0:
        sys.exit(2)
    elif potential_count > 0:
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
