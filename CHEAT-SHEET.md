# CVE-2026-21962 Detection Cheat Sheet

A complete reference of all indicators detected by the scanner and what each means.

---

## Table of Contents

1. [Server Headers](#server-headers)
2. [WebLogic Proxy Headers](#weblogic-proxy-headers)
3. [Oracle-Specific Headers](#oracle-specific-headers)
4. [Admin Paths](#admin-paths)
5. [Path Traversal Probes](#path-traversal-probes)
6. [Response Anomalies](#response-anomalies)
7. [Version Strings](#version-strings)

---

## Server Headers

These appear in the HTTP `Server` response header and indicate Oracle/WebLogic presence.

| Pattern | Meaning | Risk Level |
|---------|---------|------------|
| `Oracle-HTTP-Server` | Oracle HTTP Server (OHS) is in use | High - directly affected |
| `Oracle-HTTP-Server/14.1.1.0.0` | OHS with version - check against affected list | Critical if version matches |
| `Oracle-Application-Server` | Older Oracle Application Server | Medium - may have proxy plugin |
| `Oracle-Fusion-Middleware` | Oracle Fusion Middleware stack | High - likely has OHS |
| `WebLogic Server` | Direct WebLogic exposure (unusual) | Medium - check if behind proxy |
| `mod_wl` | Apache with WebLogic module loaded | High - proxy plugin present |
| `mod_wl_ohs` | Oracle HTTP Server WebLogic module | Critical - vulnerable component |
| `mod_wl_24` | WebLogic module for Apache 2.4 | Critical - vulnerable component |

### What It Means

If you see any of these, the target is running Oracle HTTP Server or has the WebLogic Proxy Plugin installed. This is the vulnerable component for CVE-2026-21962.

---

## WebLogic Proxy Headers

These headers are added by the WebLogic Proxy Plugin when forwarding requests. Their presence confirms the proxy plugin is active.

| Header | Purpose | What It Tells You |
|--------|---------|-------------------|
| `WL-Proxy-Client-IP` | Forwards client's real IP to WebLogic | Proxy plugin is actively forwarding requests |
| `WL-Proxy-SSL` | Indicates if client connection used SSL | Proxy is handling SSL termination |
| `WL-Proxy-Client-Keysize` | SSL key size from client connection | SSL proxy configuration active |
| `WL-Proxy-Client-Secretkeysize` | Secret key size for SSL | Detailed SSL proxy info |
| `X-WebLogic-Request-ClusterInfo` | Cluster routing information | WebLogic cluster behind proxy |
| `X-WebLogic-KeepAliveSecs` | Keep-alive timeout setting | Proxy connection pooling active |
| `X-WebLogic-Force-JVMID` | Forces routing to specific JVM | Sticky session configuration |
| `Proxy-Client-ID` | Client identifier for proxy | Proxy tracking enabled |

### What It Means

These headers confirm the WebLogic Proxy Plugin is installed and actively processing requests. The plugin itself is the vulnerable component - if you see these headers, the system is likely affected.

---

## Oracle-Specific Headers

These headers indicate Oracle middleware components are in use.

| Header | Purpose | What It Tells You |
|--------|---------|-------------------|
| `X-Oracle-DMS-ECID` | Dynamic Monitoring Service Execution Context ID | Oracle DMS is enabled (Fusion Middleware) |
| `X-Oracle-DMS-RID` | DMS Request ID | Request tracing active |
| `X-ORACLE-DMS-ECID` | Alternate casing of DMS ECID | Same as above |
| `X-ORACLE-BMC-ECID` | Oracle Cloud BMC context ID | Oracle Cloud infrastructure |

### What It Means

These indicate Oracle Fusion Middleware is in use, which typically includes Oracle HTTP Server. Strong indicator of potential vulnerability.

---

## Admin Paths

These paths are probed to confirm WebLogic presence and exposure level.

### `/console/`

**WebLogic Administration Console**

| Response | Meaning |
|----------|---------|
| HTTP 200 | Console accessible without auth (CRITICAL!) |
| HTTP 302 | Redirects to login page (console exists) |
| HTTP 401 | Auth required (console exists) |
| HTTP 403 | Access forbidden (console exists but blocked) |
| HTTP 404 | Console not at this path |

**Risk:** If accessible, attackers can attempt to log in. Many WebLogic exploits target the console.

---

### `/console/login/LoginForm.jsp`

**Direct Console Login Page**

| Response | Meaning |
|----------|---------|
| HTTP 200 | Login page directly accessible |
| HTTP 302 | Redirect (session handling) |
| HTTP 404 | Console not deployed |

**Risk:** Confirms WebLogic console deployment.

---

### `/wls-wsat/`

**Web Services Atomic Transactions (WS-AT)**

| Response | Meaning |
|----------|---------|
| HTTP 200 | WLS-WSAT service exposed |
| HTTP 404 | Service not deployed |
| HTTP 500 | Service exists but erroring |

**Risk:** CRITICAL - This endpoint has been the target of multiple severe WebLogic CVEs (CVE-2017-10271, CVE-2019-2725). If accessible, the server may be vulnerable to other exploits.

---

### `/bea_wls_internal/`

**BEA/WebLogic Internal Servlet**

| Response | Meaning |
|----------|---------|
| HTTP 200 | Internal servlet accessible |
| HTTP 403 | Exists but blocked |
| HTTP 404 | Not present |

**Risk:** This is an internal WebLogic path that should NOT be externally accessible. If reachable, indicates misconfiguration and potential for exploitation.

**History:** "BEA" is from BEA Systems, the company that created WebLogic before Oracle acquired it in 2008. This path remains for backward compatibility.

---

### `/_async/`

**Async Response Servlet**

| Response | Meaning |
|----------|---------|
| HTTP 200 | Async servlet accessible |
| HTTP 404 | Not deployed |

**Risk:** The async servlet has been targeted by deserialization exploits. If accessible, indicates attack surface.

---

### `/wls-cat/`

**WebLogic CAT (Component Architecture Tool)**

| Response | Meaning |
|----------|---------|
| HTTP 200 | CAT exposed |
| HTTP 404 | Not deployed |

**Risk:** Development/debugging tool that should not be exposed in production.

---

### `/uddiexplorer/`

**UDDI Explorer**

| Response | Meaning |
|----------|---------|
| HTTP 200 | UDDI Explorer accessible |
| HTTP 404 | Not deployed |

**Risk:** UDDI (Universal Description, Discovery and Integration) explorer can leak service information. Should not be externally accessible.

---

### `/console/css/login.css`

**Console Static Resources**

| Response | Meaning |
|----------|---------|
| HTTP 200 | Console static files accessible |
| HTTP 404 | Console not deployed |

**Risk:** Accessing static resources can reveal WebLogic version through CSS/JS file contents or modification dates.

---

## Path Traversal Probes

These probes test how the proxy handles potentially malicious paths.

### `/?test=..%2e..%2f`

**Mixed-Encoding Path Traversal**

- `%2e` = `.` (URL encoded)
- `%2f` = `/` (URL encoded)
- Tests if proxy normalizes mixed encoding

| Response | Meaning |
|----------|---------|
| HTTP 400 | Properly blocked (good) |
| HTTP 200 | Not blocked - potential vulnerability |
| HTTP 500 | Causes error - proxy mishandles it |

---

### `/..;/`

**Semicolon Path Parameter Bypass**

WebLogic/Tomcat treat `;` as a path parameter delimiter. This can bypass path restrictions.

| Response | Meaning |
|----------|---------|
| HTTP 400 | Properly rejected |
| HTTP 200 | Bypass may be possible |
| HTTP 500 | Triggers error in proxy |

**History:** This technique has been used in multiple Java web server exploits.

---

### `/%2e%2e/`

**URL-Encoded Directory Traversal**

Simple `../` encoded as `%2e%2e/`

| Response | Meaning |
|----------|---------|
| HTTP 400/403 | Properly blocked |
| HTTP 200 | Path normalization issue |

---

### `/%252e%252e/`

**Double-Encoded Traversal**

`%25` = `%` (encoded), so `%252e` becomes `%2e` after first decode, then `.` after second.

| Response | Meaning |
|----------|---------|
| HTTP 400 | Blocked (good) |
| HTTP 200 | Double-decode vulnerability |

**Risk:** If this returns 200, the proxy is double-decoding paths which can lead to serious bypasses.

---

### `/..%00/`

**Null Byte Injection**

`%00` is a null byte that can terminate strings in C-based parsers.

| Response | Meaning |
|----------|---------|
| HTTP 400 | Properly rejected |
| HTTP 200 | Null byte not handled |

**Risk:** Can potentially truncate paths and bypass restrictions.

---

### `/weblogic/`

**WebLogic Default Path**

| Response | Meaning |
|----------|---------|
| HTTP 200/302 | WebLogic application context |
| HTTP 404 | No default mapping |

---

### `/_wl_proxy/`

**WebLogic Proxy Internal Path**

| Response | Meaning |
|----------|---------|
| HTTP 200 | Proxy internal path exposed |
| HTTP 404 | Path not mapped |

**Risk:** Internal proxy paths should not be accessible externally.

---

## Response Anomalies

These are behavioral issues detected during probing.

### `Plugin error leak on <path> (status 500)`

**Meaning:** When sending a malformed request to `<path>`, the server returned a 500 error that contained identifiable WebLogic/Oracle text in the response body.

**Risk:** Information disclosure - error messages reveal software stack. Also indicates the proxy is not properly handling malformed input.

**Example error text that triggers this:**
- "WebLogic Server"
- "mod_wl"
- "oracle"
- "plugin"

---

### `Path traversal not blocked: <path>`

**Meaning:** A path containing traversal sequences (`..`) returned HTTP 200 instead of being blocked.

**Risk:** HIGH - The proxy is not properly normalizing or blocking path traversal attempts. This is a strong indicator of the vulnerability.

---

### `WebLogic header detected: <header>`

**Meaning:** During header variation testing, a WebLogic-specific header appeared in the response.

**Risk:** Confirms WebLogic proxy presence through behavioral testing.

---

### `Header count variation detected (proxy behavior)`

**Meaning:** When sending requests with different header casing, the response had significantly different headers - indicating a proxy is modifying requests.

**Risk:** Medium - Confirms proxy presence through behavioral fingerprinting.

---

### `Note: IIS plugin v<version> is NOT affected (only 12.2.1.4.0)`

**Meaning:** The target is running Microsoft IIS with the WebLogic Proxy Plugin, but the detected version is 14.1.1.0.0 or 14.1.2.0.0 which are NOT affected on IIS.

**Risk:** Low for CVE-2026-21962 specifically (IIS only vulnerable in 12.2.1.4.0), but still indicates WebLogic infrastructure that may have other vulnerabilities.

---

## Version Strings

### Affected Versions

| Version | Apache/OHS | IIS |
|---------|------------|-----|
| `12.2.1.4.0` | VULNERABLE | VULNERABLE |
| `14.1.1.0.0` | VULNERABLE | Not affected |
| `14.1.2.0.0` | VULNERABLE | Not affected |

### Version Detection Patterns

The scanner looks for these patterns:

```
Oracle-HTTP-Server/14.1.1.0.0
WebLogic Server 14.1.1.0.0
version: 12.2.1.4.0
mod_wl_24
```

### Version in File Paths

Sometimes versions appear in static resource paths:
```
/console/css/14.1.1.0.0/login.css
/wls/14.1/...
```

---

## Quick Reference Card

### Critical Findings (Likely Vulnerable)

| Finding | Why Critical |
|---------|--------------|
| Affected version detected | Direct version match |
| `WL-Proxy-*` headers present | Confirms vulnerable component |
| Path traversal not blocked | Behavioral vulnerability indicator |
| Plugin error leak | Mishandling of malformed requests |
| `/wls-wsat/` accessible | Known exploit target, indicates WebLogic exposure |

### High-Risk Findings

| Finding | Why High Risk |
|---------|---------------|
| Oracle-HTTP-Server header | Running affected software |
| `/console/` accessible | Admin interface exposed |
| `/bea_wls_internal/` accessible | Internal paths exposed |
| Double-encoded path accepted | Path normalization issues |

### Medium-Risk Findings

| Finding | Why Medium Risk |
|---------|-----------------|
| Oracle DMS headers | Confirms Oracle Middleware |
| `/_async/` accessible | Historical exploit target |
| Header variation detected | Confirms proxy presence |

---

## Remediation Priority

1. **IMMEDIATE:** Apply Oracle January 2026 CPU patch
2. **HIGH:** Block external access to admin paths (`/console/`, `/wls-wsat/`, etc.)
3. **HIGH:** Restrict access to Oracle HTTP Server from untrusted networks
4. **MEDIUM:** Review proxy plugin configuration
5. **MEDIUM:** Enable detailed logging for forensics
