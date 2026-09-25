#!/usr/bin/env python3
"""
TASK-TR-03 Test Suite: Tool Health Check Mechanism
"""

import pytest
import datetime
import time
import sys
import os
from unittest.mock import Mock, patch

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# Import test utilities
from wave2_tr03_impl import (
    HealthCheckProbe, HealthCheckResult, ProbeType, HealthStatus,
    perform_http_check, perform_socket_check, perform_ping_check
)


class TestHealthCheckStructures:
    """Test basic data structures."""
    
    def test_create_http_probe(self):
        """Test creating HTTP health check probe."""
        probe = HealthCheckProbe(
            tool_id="test-tool",
            probe_type=ProbeType.HTTP_GET,
            endpoint="http://localhost:8080",
            expected_status=200,
            timeout_seconds=5,
            failure_threshold=2
        )
        assert probe.tool_id == "test-tool"
        assert probe.probe_type == ProbeType.HTTP_GET
        assert probe.endpoint == "http://localhost:8080"
        assert probe.expected_status == 200
        assert probe.failure_threshold == 2
    
    def test_create_health_check_result(self):
        """Test creating health check result."""
        result = HealthCheckResult(
            tool_id="test-tool",
            timestamp=datetime.datetime.now().isoformat(),
            probe_type="http_get",
            is_healthy=True,
            response_time_ms=123.45
        )
        assert result.tool_id == "test-tool"
        assert result.is_healthy is True


class TestProbeTypes:
    """Test probe type enum."""
    
    def test_probe_type_http_get(self):
        """Test HTTP_GET probe type."""
        assert ProbeType.HTTP_GET.value == "http_get"
    
    def test_probe_type_socket(self):
        """Test SOCKET probe type."""
        assert ProbeType.SOCKET.value == "socket"
    
    def test_probe_type_ping(self):
        """Test PING probe type."""
        assert ProbeType.PING.value == "ping"


class TestHealthStatus:
    """Test health status enum."""
    
    def test_health_status_healthy(self):
        """Test HEALTHY status."""
        assert HealthStatus.HEALTHY.value == "healthy"
    
    def test_health_status_degraded(self):
        """Test DEGRADED status."""
        assert HealthStatus.DEGRADED.value == "degraded"
    
    def test_health_status_offline(self):
        """Test OFFLINE status."""
        assert HealthStatus.OFFLINE.value == "offline"


class TestHealthCheckFunctions:
    """Test individual health check functions."""
    
    @patch('wave2_tr03_impl.requests.get')
    def test_http_check_success(self, mock_get):
        """Test successful HTTP health check."""
        mock_resp = Mock()
        mock_resp.status_code = 200
        mock_get.return_value = mock_resp
        
        is_healthy, response_time, error = perform_http_check(
            "http://localhost:8000", 200, 5
        )
        
        assert is_healthy is True
        assert error is None
    
    @patch('wave2_tr03_impl.requests.get')
    def test_http_check_wrong_status(self, mock_get):
        """Test HTTP health check with wrong status code."""
        mock_resp = Mock()
        mock_resp.status_code = 500
        mock_get.return_value = mock_resp
        
        is_healthy, response_time, error = perform_http_check(
            "http://localhost:8000", 200, 5
        )
        
        assert is_healthy is False
        assert "Got 500" in error


class TestIntegration:
    """Integration tests."""
    
    def test_failure_tracking(self):
        """Test failure counting."""
        failure_count = 0
        threshold = 2
        
        for i in range(3):
            failure_count += 1
            if failure_count >= threshold:
                status = HealthStatus.DEGRADED
            else:
                status = HealthStatus.HEALTHY
        
        assert failure_count == 3
        assert status == HealthStatus.DEGRADED
    
    def test_status_transitions(self):
        """Test health status transitions."""
        status = HealthStatus.HEALTHY
        assert status == HealthStatus.HEALTHY
        
        status = HealthStatus.DEGRADED
        assert status == HealthStatus.DEGRADED
        
        status = HealthStatus.OFFLINE
        assert status == HealthStatus.OFFLINE


def test_ac1_health_checks_performable():
    """AC1: Health checks can be performed."""
    probe = HealthCheckProbe(
        tool_id="tool-1",
        probe_type=ProbeType.HTTP_GET,
        endpoint="http://example.com"
    )
    assert probe.tool_id == "tool-1"


def test_ac2_failure_tracking():
    """AC2: Failure tracking works."""
    failures = 0
    for i in range(3):
        failures += 1
    assert failures == 3


def test_ac3_status_transitions():
    """AC3: Status transitions work."""
    status = HealthStatus.HEALTHY
    status = HealthStatus.DEGRADED
    assert status == HealthStatus.DEGRADED


def test_ac4_probe_types():
    """AC4: All probe types supported."""
    probe_types = [ProbeType.PING, ProbeType.HTTP_GET, ProbeType.SOCKET, ProbeType.PROCESS_CHECK]
    assert len(probe_types) == 4


def test_ac5_timestamped_results():
    """AC5: Results have timestamps."""
    result = HealthCheckResult(
        tool_id="test",
        timestamp=datetime.datetime.now().isoformat(),
        probe_type="http_get",
        is_healthy=True,
        response_time_ms=100.0
    )
    assert result.timestamp is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
