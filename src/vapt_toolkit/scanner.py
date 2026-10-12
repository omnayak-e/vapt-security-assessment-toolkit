import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from .models import Finding

COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 139: "NetBIOS", 143: "IMAP",
    443: "HTTPS", 445: "SMB", 3306: "MySQL", 5432: "PostgreSQL",
    8080: "HTTP-alt", 8443: "HTTPS-alt",
}

def parse_ports(value: str) -> list[int]:
    ports = []
    for part in value.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            a, b = part.split("-", 1)
            start, end = int(a), int(b)
            if start > end:
                raise ValueError("Port range start must be <= end")
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    if not ports or any(p < 1 or p > 65535 for p in ports):
        raise ValueError("Provide ports in the range 1-65535")
    return sorted(set(ports))

def check_port(host: str, port: int, timeout: float = 0.5) -> dict:
    result = {"host": host, "port": port, "state": "closed_or_filtered",
              "service_hint": COMMON_PORTS.get(port, "unknown")}
    try:
        with socket.create_connection((host, port), timeout=timeout):
            result["state"] = "open"
    except (OSError, TimeoutError):
        pass
    return result

def scan_tcp(host: str, ports: list[int], timeout: float = 0.5, workers: int = 16) -> list[dict]:
    if not host or any(c.isspace() for c in host):
        raise ValueError("Host must be a non-empty hostname or IP without spaces")
    if not 0.05 <= timeout <= 5:
        raise ValueError("Timeout must be between 0.05 and 5 seconds")
    if not 1 <= workers <= 64:
        raise ValueError("Workers must be between 1 and 64")
    results = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [pool.submit(check_port, host, p, timeout) for p in ports]
        for future in as_completed(futures):
            results.append(future.result())
    return sorted(results, key=lambda item: item["port"])

def ports_to_findings(results: list[dict]) -> list[Finding]:
    findings = []
    for item in results:
        if item["state"] == "open":
            port = item["port"]
            severity = "medium" if port in (21, 23, 445, 3389) else "info"
            findings.append(Finding(
                title=f"Open TCP port {port}",
                severity=severity,
                asset=f'{item["host"]}:{port}',
                description=f'TCP port {port} is accepting connections. Open ports are not inherently vulnerabilities; confirm that the service is required and appropriately protected.',
                evidence=f'Successful TCP connect; service hint: {item["service_hint"]}.',
                remediation="Confirm business need, restrict exposure with host/network firewall rules, and keep the service securely configured.",
                category="Network exposure",
                verified=True,
            ))
    return findings
