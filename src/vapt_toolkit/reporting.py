import json
from pathlib import Path

def write_reports(assessment, output_prefix: str):
    prefix = Path(output_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    data = assessment.to_dict()
    json_path = prefix.with_suffix(".json")
    md_path = prefix.with_suffix(".md")
    json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    lines = [
        "# VAPT Assessment Report", "",
        f"- **Target:** `{data['target']}`",
        f"- **Started:** {data['started_at']}",
        f"- **Tool:** {data['tool']}", "",
        "> This report is a technical aid. Validate findings and confirm scope before sharing.", "",
        "## Executive summary", "",
        f"Total findings: **{len(data['findings'])}**.", "",
        "## Findings", ""
    ]
    if not data["findings"]:
        lines.append("No findings were recorded by the selected checks.")
    for idx, f in enumerate(data["findings"], 1):
        lines += [
            f"### {idx}. {f['title']}", "",
            f"- **Severity:** {f['severity']}",
            f"- **Asset:** `{f['asset']}`",
            f"- **Category:** {f['category']}",
            f"- **Verified by tool:** {f['verified']}", "",
            f"**Description:** {f['description']}", "",
            f"**Evidence:** {f['evidence']}", "",
            f"**Remediation:** {f['remediation']}", ""
        ]
    lines += ["## Notes", ""] + [f"- {n}" for n in data["notes"]]
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path, md_path
