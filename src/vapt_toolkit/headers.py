import requests
from .models import Finding

SECURITY_HEADERS = {
    "Content-Security-Policy": ("medium", "Define an appropriate Content Security Policy to reduce the impact of content injection."),
    "X-Content-Type-Options": ("low", "Set X-Content-Type-Options: nosniff."),
    "Referrer-Policy": ("low", "Set a Referrer-Policy appropriate to the application's privacy requirements."),
    "Strict-Transport-Security": ("medium", "For HTTPS deployments, configure HSTS after validating subdomain and preload implications."),
    "Permissions-Policy": ("info", "Explicitly limit browser features that the application does not need."),
}

def review_headers(url: str, timeout: float = 4.0) -> tuple[dict, list[Finding]]:
    if not url.startswith(("http://", "https://")):
        raise ValueError("URL must start with http:// or https://")
    response = requests.get(url, timeout=timeout, allow_redirects=True)
    headers = {k.lower(): v for k, v in response.headers.items()}
    findings = []
    for header, (severity, fix) in SECURITY_HEADERS.items():
        if header.lower() not in headers:
            findings.append(Finding(
                title=f"Missing {header}",
                severity=severity,
                asset=response.url,
                description=f"The HTTP response did not include {header}. Applicability depends on the application and deployment context.",
                evidence=f"HTTP {response.status_code}; header absent from final response.",
                remediation=fix,
                category="HTTP security headers",
                verified=True,
            ))
    metadata = {"requested_url": url, "final_url": response.url,
                "status_code": response.status_code,
                "headers": dict(response.headers)}
    return metadata, findings
