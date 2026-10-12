# VAPT Security Assessment Toolkit

> **Portfolio project by Om Nayak** · M.Sc. Cyber Security · Amity University Rajasthan  
> **Focus:** authorised vulnerability assessment, evidence handling, risk communication, and remediation planning.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?logo=python&logoColor=white)
![Testing](https://img.shields.io/badge/testing-pytest-0A9EDC)
![License](https://img.shields.io/badge/license-MIT-green)
![Use](https://img.shields.io/badge/use-authorised%20labs-blue)

## 1. Project overview

The VAPT Security Assessment Toolkit is an educational, command-line project that demonstrates how a small security assessment can be conducted and documented using repeatable steps. It focuses on two deliberately bounded checks:

1. **TCP exposure review** — attempt TCP connections to explicitly specified ports on one explicitly specified host.
2. **HTTP security-header review** — request a specified HTTP(S) URL and report selected recommended security headers that are absent from the final response.

Results are normalised into a finding model and exported as JSON and Markdown. This helps keep raw observations, risk interpretation, and remediation advice separate.

This is a portfolio-scale starter toolkit, not a replacement for professional scanners such as Nmap, Nessus, OpenVAS, or Burp Suite. It does not exploit vulnerabilities, brute-force credentials, evade monitoring, persist on systems, or perform broad network discovery.

## 2. Problem statement

Security assessments often produce raw technical output that is difficult to compare, review, or communicate. A repeatable assessment process should:
- keep the target and scope explicit;
- record what was actually observed;
- avoid describing every open port as a vulnerability;
- distinguish tool observations from analyst conclusions;
- provide remediation that an owner can act on; and
- produce report files that can be reviewed later.

This project demonstrates these principles with a small, auditable codebase.

## 3. Objectives

### Technical objectives
- Parse and validate user-supplied TCP ports and ranges.
- Perform low-impact TCP connect checks with a bounded timeout and worker count.
- Review a small set of common HTTP response security headers.
- Represent findings consistently using a Python data model.
- Export structured JSON and human-readable Markdown.

### Learning objectives
- Understand the difference between asset exposure and confirmed vulnerability.
- Practise repeatable evidence capture and risk-oriented reporting.
- Learn how CLI tools, modules, tests, and CI fit together in a security project.
- Reinforce the importance of authorisation, scope, and limitations.

## 4. Scope and limitations

### Included
- One target host per TCP scan invocation.
- User-supplied ports and ranges, with validation.
- TCP connection-state observations: `open` or `closed_or_filtered`.
- HTTP(S) response status and header inspection.
- JSON and Markdown reports.
- Unit tests for port parsing, finding wording, and report generation.

### Not included
- Exploitation or payload delivery.
- UDP scanning, OS fingerprinting, service-version probing, or network-wide sweeps.
- Credentialed scanning, authenticated application testing, or authenticated vulnerability checks.
- CVE correlation, CVSS calculation, or automatic claims that a finding is exploitable.
- Automated crawling or testing of every application route.

A port reported as `closed_or_filtered` is intentionally ambiguous: a connection failure alone cannot reliably distinguish a closed port from a firewall drop, routing issue, or other connectivity problem.

## 5. Architecture

```text
CLI arguments
   |
   +--> Input validation (target, ports, timeout, workers)
   |
   +--> TCP scanner -----------+
   |                           |
   +--> HTTP header review ----+--> Finding / Assessment data models
                                       |
                                       v
                              Report generation
                                /           \
                             JSON           Markdown
```

### Main modules

| Module | Responsibility |
|---|---|
| `scanner.py` | Port parsing, TCP connect checks, and exposure observations |
| `headers.py` | HTTP(S) request and security-header review |
| `models.py` | Consistent finding and assessment structures |
| `reporting.py` | JSON and Markdown report creation |
| `cli.py` | User-facing command-line interface |

## 6. Methodology

### Phase 1 — Define scope
Choose a target that you own or are explicitly authorised to assess. Record the target, permitted ports, time window, and any operational restrictions before running checks.

### Phase 2 — Validate inputs
The port parser accepts comma-separated ports and ranges, such as `22,80,443,8000-8002`. It rejects out-of-range values and reversed ranges. Timeout and worker values are bounded to reduce accidental excessive load.

### Phase 3 — Collect observations
The TCP check attempts a connection to each requested port and records whether a connection succeeded. It does not send exploit payloads or attempt authentication. The header review performs an HTTP(S) GET request and inspects the final response after redirects.

### Phase 4 — Interpret findings
An open port is recorded as an exposure observation, not automatically a vulnerability. The report explains that service necessity and network exposure must be reviewed in context. Missing headers are also review items: their severity and applicability depend on application type, deployment architecture, and browser-facing behaviour.

### Phase 5 — Generate reports
The assessment model records the target, timestamp, tool name, findings, and notes. Reports are written in two formats:
- **JSON** for later parsing or integration.
- **Markdown** for readable review, pull requests, or report attachments.

### Phase 6 — Validate and remediate
Manually verify the observation, confirm asset ownership and business need, apply an appropriate fix, and retest. Do not mark a weakness as fixed until the result has been checked again.

## 7. Technology stack

- **Python 3.10+** — application logic and CLI.
- **Requests** — HTTP(S) response retrieval.
- **pytest** — automated tests.
- **GitHub Actions** — repeatable test execution on pushes and pull requests.
- **JSON / Markdown** — machine-readable and human-readable reporting.

## 8. Installation

```bash
git clone https://github.com/YOUR-USERNAME/vapt-security-assessment-toolkit.git
cd vapt-security-assessment-toolkit

python -m venv .venv
# Windows PowerShell:
# .venv\Scripts\Activate.ps1
# macOS / Linux:
source .venv/bin/activate

python -m pip install --upgrade pip
pip install -r requirements.txt
pip install pytest
pip install -e .
```

If you do not install the package in editable mode, you can run the CLI with `PYTHONPATH=src` (or set `PYTHONPATH=src` in your shell).

## 9. Usage

### TCP exposure check

Use a lab host or localhost. This example checks only the specified ports:

```bash
vapt-toolkit scan --target 127.0.0.1 --ports 22,80,443,8080 --output reports/generated/local-scan
```

A range can be supplied:

```bash
vapt-toolkit scan --target 127.0.0.1 --ports 8000-8010 --timeout 0.4 --output reports/generated/local-range
```

Options:
- `--target`: one authorised host name or IP address.
- `--ports`: comma-separated ports and/or ranges.
- `--timeout`: TCP connection timeout in seconds, bounded by the implementation.
- `--output`: output path prefix; `.json` and `.md` are added automatically.

### HTTP security-header review

Start a local HTTP test server or use an approved test URL:

```bash
vapt-toolkit headers --url http://127.0.0.1:8000 --output reports/generated/header-review
```

Only assess sites for which you have permission. Avoid submitting sensitive data through test forms; this check sends a GET request.

### Running as a Python module

```bash
python -m vapt_toolkit.cli scan --target 127.0.0.1 --ports 80,443
```

## 10. Report interpretation

Each finding contains:
- `title` — concise name for the observation;
- `severity` — a preliminary prioritisation label, not a formal CVSS score;
- `asset` — the host, URL, or host/port associated with the observation;
- `description` — context and limitations;
- `evidence` — what the tool actually observed;
- `remediation` — recommended next action;
- `category` — the class of check; and
- `verified` — whether the tool observed the stated condition, not whether a human confirmed exploitability.

Severity labels should be reviewed before they are used in a stakeholder report. This project does not calculate CVSS.

## 11. Testing and quality

Run tests:

```bash
pytest -q
```

The included tests cover:
- valid port parsing and ranges;
- invalid port rejection;
- cautious interpretation of open ports; and
- JSON/Markdown report creation.

The GitHub Actions workflow runs the test suite on supported Python versions. CI success shows that automated tests pass; it does not prove the tool is free of defects or suitable for production use.

## 12. Security and ethical use

- Obtain written authorisation and define scope.
- Use localhost, intentionally vulnerable training environments, or assets you control.
- Do not use this toolkit to scan unrelated systems.
- Keep reports and logs free of secrets and private data.
- Review [`docs/ETHICS_AND_SCOPE.md`](docs/ETHICS_AND_SCOPE.md) before testing.

## 13. Future improvements

- Add CSV output and report templates.
- Add authenticated checks only for approved lab applications.
- Add asset metadata and manual CVSS fields without pretending scores are automatic.
- Add a configuration file and report redaction.
- Add integration tests using a local test HTTP server.
- Add a dashboard after the CLI and reporting contracts are stable.

## 14. Author

**Om Nayak**  
M.Sc. Cyber Security · Amity Institute of Information Technology, Amity University Rajasthan

This project is an educational portfolio implementation. Sample results are not evidence of a real client engagement.
