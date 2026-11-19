from assignment.pipeline import (
    build_production_plugins,
    build_observability,
)
from assignment.rate_limiter import RateLimitPlugin
from assignment.audit_log import AuditLogPlugin
from assignment.monitoring import MonitoringAlert

from guardrails.input_guardrails import InputGuardrailPlugin
from guardrails.output_guardrails import OutputGuardrailPlugin


def test_production_plugin_order():
    plugins = build_production_plugins(
        max_requests=3,
        window_seconds=60,
    )

    assert len(plugins) == 3
    assert isinstance(plugins[0], RateLimitPlugin)
    assert isinstance(plugins[1], InputGuardrailPlugin)
    assert isinstance(plugins[2], OutputGuardrailPlugin)

    assert plugins[0].max_requests == 3
    assert plugins[0].window_seconds == 60


def test_observability_instances():
    audit, monitor = build_observability()

    assert isinstance(audit, AuditLogPlugin)
    assert isinstance(monitor, MonitoringAlert)


def test_invalid_rate_limit_config():
    import pytest

    with pytest.raises(ValueError):
        build_production_plugins(max_requests=0)

    with pytest.raises(ValueError):
        build_production_plugins(window_seconds=0)
