import pytest
from vapt_toolkit.scanner import parse_ports, ports_to_findings

def test_parse_ports_and_ranges():
    assert parse_ports("80,443,8000-8002") == [80,443,8000,8001,8002]

def test_invalid_port_rejected():
    with pytest.raises(ValueError):
        parse_ports("0,70000")

def test_open_port_is_reported_as_exposure_not_vulnerability():
    findings = ports_to_findings([{"host":"127.0.0.1","port":8080,"state":"open","service_hint":"HTTP-alt"}])
    assert len(findings) == 1
    assert "not inherently vulnerabilities" in findings[0].description
