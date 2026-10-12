from vapt_toolkit.models import Assessment, Finding
from vapt_toolkit.reporting import write_reports

def test_report_files_created(tmp_path):
    a = Assessment.create("127.0.0.1", [Finding("Example", "low", "127.0.0.1:80", "desc", "evidence", "fix")])
    jp, mp = write_reports(a, str(tmp_path / "out"))
    assert jp.exists() and mp.exists()
    assert "Example" in mp.read_text()
