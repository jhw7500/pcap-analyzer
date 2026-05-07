from typing import Any

from analyzer.casefile_schema import CasefileV1


def validate_casefile(payload: dict[str, Any]) -> CasefileV1:
    return CasefileV1.model_validate(payload)


def render_casefile_text(casefile: CasefileV1) -> str:
    lines = [
        "Ping Timeout Casefile",
        f"schema_version: {casefile.schema_version}",
        f"generator_version: {casefile.generator_version}",
        f"analysis_id: {casefile.analysis_id}",
        f"incident_id: {casefile.incident_id}",
        "",
        f"window: {casefile.incident_window.start_ts} ~ {casefile.incident_window.end_ts}",
        f"trigger: {casefile.incident_window.trigger_reason}",
        f"confidence: {casefile.summary.confidence}",
        "",
        f"ping pairs={len(casefile.ping.pairs)}, losses={len(casefile.ping.losses)}",
    ]
    if casefile.summary.next_checks:
        lines.append("next_checks:")
        for item in casefile.summary.next_checks:
            lines.append(f"- {item}")
    return "\n".join(lines)


def render_casefile_html(casefile: CasefileV1) -> str:
    text = render_casefile_text(casefile).replace("\n", "<br>")
    return f"<html><body><h1>Casefile</h1><div>{text}</div></body></html>"
