# Security Scan Report for http://www.sgbit.edu.in/
_UTC: 20250923-171135_

## [High] Certificate: Certificate retrieval failed
**Detection**:
Could not retrieve certificate: [Errno 11001] getaddrinfo failed
**Exploitation (PoC)**:
TLS handshake to fetch certificate failed (see detection).
**Remediation**:
Fix TLS endpoint / ensure certificate is correctly installed.
**Evidence**
`````
{
  "error": "[Errno 11001] getaddrinfo failed"
}
`````

## [Medium] Headers: Header fetch failed
**Detection**:
Failed to fetch headers from https://http://www.sgbit.edu.in/: <urlopen error [Errno 11001] getaddrinfo failed>
**Exploitation (PoC)**:
N/A
**Remediation**:
Ensure the target is reachable and scheme/host are correct.
