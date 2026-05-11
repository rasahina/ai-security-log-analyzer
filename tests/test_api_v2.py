import json

import pytest

from api_v2 import AnalyzeV2Request, analyze_v2, health


SAMPLE_LOG = """
2026-05-01T10:00:00+00:00 10.0.0.4 GET /login 401
2026-05-01T10:00:05+00:00 10.0.0.4 GET /login 401
2026-05-01T10:00:10+00:00 10.0.0.4 GET /login 403
2026-05-01T10:00:15+00:00 10.0.0.4 GET /login 401
2026-05-01T10:00:20+00:00 10.0.0.4 GET /login 403
"""


def _sample_log_text() -> str:
    return SAMPLE_LOG


@pytest.fixture(scope="module")
def analyze_v2_response():
    response = analyze_v2(
        AnalyzeV2Request(log=_sample_log_text())
    )

    assert response.status_code == 200
    return response


def test_health_ok():
    assert health() == {"status": "ok"}


def test_analyze_v2_returns_detection_report(analyze_v2_response):
    report = json.loads(analyze_v2_response.body)

    assert report["schema_version"] == "v2_minimal_0.1"
    assert "ip_reports" in report
    assert isinstance(report["ip_reports"], list)
    assert report["ip_reports"]


def test_detection_report_minimal_contract(analyze_v2_response):
    report = json.loads(analyze_v2_response.body)

    assert report["schema_version"] == "v2_minimal_0.1"
    assert "generated_at" in report

    ip_report = report["ip_reports"][0]
    assert {
        "source_ip",
        "overall_score",
        "risk_level",
        "attack_count",
        "findings",
    } <= set(ip_report)

    findings = [
        finding
        for item in report["ip_reports"]
        for finding in item.get("findings", [])
    ]

    assert findings

    finding = findings[0]
    assert {
        "finding_id",
        "finding_type",
        "attack_type",
        "source_ip",
        "score",
        "time_range",
    } <= set(finding)
