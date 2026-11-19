import json

from assignment.monitoring import MonitoringAlert


def test_monitoring_alerts():
    monitor = MonitoringAlert()

    monitor.total_requests = 10
    monitor.blocked_requests = 7
    monitor.rate_limit_hits = 6
    monitor.judge_checks = 10
    monitor.judge_fails = 4

    alerts = monitor.check_metrics()

    assert len(alerts) == 3

    metrics = {alert.metric for alert in alerts}

    assert "block_rate" in metrics
    assert "rate_limit_hits" in metrics
    assert "judge_fail_rate" in metrics

    assert monitor.snapshot()["block_rate"] == 0.7
    assert monitor.snapshot()["judge_fail_rate"] == 0.4

    # Rechecking must not duplicate alerts.
    assert len(monitor.check_metrics()) == 3


def test_monitoring_export(tmp_path):
    monitor = MonitoringAlert()

    monitor.total_requests = 4
    monitor.blocked_requests = 3

    output = tmp_path / "metrics.json"
    monitor.export_json(str(output))

    assert output.exists()

    data = json.loads(output.read_text(encoding="utf-8"))

    assert data["total_requests"] == 4
    assert data["blocked_requests"] == 3
    assert data["block_rate"] == 0.75

    assert any(
        alert["metric"] == "block_rate"
        for alert in data["alerts"]
    )


def test_monitoring_zero_requests():
    monitor = MonitoringAlert()

    assert monitor.check_metrics() == []

    snapshot = monitor.snapshot()

    assert snapshot["block_rate"] == 0.0
    assert snapshot["judge_fail_rate"] == 0.0
