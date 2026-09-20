#!/usr/bin/env python3
"""
Test suite for TASK-TR-01: Tool Registry Data Structures
Verifies all data structures can be instantiated and validated correctly.
"""

import pytest
import uuid
import re
from kali_mcp_server import (
    HealthStatus,
    ParameterType,
    Parameter,
    Capability,
    Tool,
)


class TestHealthStatus:
    """Test HealthStatus enum."""

    def test_has_three_values(self):
        """Verify HealthStatus has exactly 3 values."""
        values = [e.value for e in HealthStatus]
        assert len(values) == 3
        assert "healthy" in values
        assert "degraded" in values
        assert "offline" in values

    def test_healthy_status(self):
        """Test HEALTHY status."""
        assert HealthStatus.HEALTHY.value == "healthy"

    def test_degraded_status(self):
        """Test DEGRADED status."""
        assert HealthStatus.DEGRADED.value == "degraded"

    def test_offline_status(self):
        """Test OFFLINE status."""
        assert HealthStatus.OFFLINE.value == "offline"


class TestParameterType:
    """Test ParameterType enum."""

    def test_has_five_types(self):
        """Verify ParameterType has 5 types."""
        types = [e.value for e in ParameterType]
        assert len(types) == 5

    def test_parameter_types(self):
        """Test all parameter types exist."""
        assert ParameterType.STRING.value == "string"
        assert ParameterType.INTEGER.value == "integer"
        assert ParameterType.BOOLEAN.value == "boolean"
        assert ParameterType.ENUM.value == "enum"
        assert ParameterType.FILE_PATH.value == "file_path"


class TestParameter:
    """Test Parameter dataclass."""

    def test_create_string_parameter(self):
        """Test creating a STRING parameter."""
        param = Parameter(
            name="depth",
            param_type=ParameterType.STRING,
            description="Scan depth level",
            required=True,
        )
        assert param.name == "depth"
        assert param.param_type == ParameterType.STRING
        assert param.description == "Scan depth level"
        assert param.required is True

    def test_create_integer_parameter(self):
        """Test creating an INTEGER parameter."""
        param = Parameter(
            name="timeout",
            param_type=ParameterType.INTEGER,
            description="Timeout in seconds",
            required=False,
        )
        assert param.name == "timeout"
        assert param.param_type == ParameterType.INTEGER
        assert param.required is False

    def test_create_boolean_parameter(self):
        """Test creating a BOOLEAN parameter."""
        param = Parameter(
            name="verbose",
            param_type=ParameterType.BOOLEAN,
            description="Enable verbose output",
            required=False,
        )
        assert param.name == "verbose"
        assert param.param_type == ParameterType.BOOLEAN

    def test_create_enum_parameter(self):
        """Test creating an ENUM parameter."""
        param = Parameter(
            name="depth",
            param_type=ParameterType.ENUM,
            description="Scan depth",
            required=True,
            allowed_values=["stealth", "light", "deep", "aggressive"],
        )
        assert param.name == "depth"
        assert param.param_type == ParameterType.ENUM
        assert param.allowed_values == ["stealth", "light", "deep", "aggressive"]

    def test_create_file_path_parameter(self):
        """Test creating a FILE_PATH parameter."""
        param = Parameter(
            name="wordlist",
            param_type=ParameterType.FILE_PATH,
            description="Path to wordlist file",
            required=False,
        )
        assert param.name == "wordlist"
        assert param.param_type == ParameterType.FILE_PATH

    def test_parameter_with_validation_regex(self):
        """Test parameter with regex validation."""
        param = Parameter(
            name="ip",
            param_type=ParameterType.STRING,
            description="Target IP address",
            required=True,
            validation_regex=r"^(\d{1,3}\.){3}\d{1,3}$",
        )
        assert param.validation_regex == r"^(\d{1,3}\.){3}\d{1,3}$"

    def test_validate_required_string_parameter(self):
        """Test validation of required STRING parameter."""
        param = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            description="Target URL",
            required=True,
        )
        
        # Valid value
        is_valid, error = param.validate("https://example.com")
        assert is_valid is True
        assert error is None

        # Missing required value
        is_valid, error = param.validate(None)
        assert is_valid is False
        assert "required" in error.lower()

        # Wrong type
        is_valid, error = param.validate(123)
        assert is_valid is False
        assert "STRING" in error

    def test_validate_string_with_regex(self):
        """Test validation of STRING parameter with regex."""
        param = Parameter(
            name="ip",
            param_type=ParameterType.STRING,
            description="IP address",
            required=False,
            validation_regex=r"^(\d{1,3}\.){3}\d{1,3}$",
        )

        # Valid IP
        is_valid, error = param.validate("192.168.1.1")
        assert is_valid is True

        # Invalid IP
        is_valid, error = param.validate("999.999.999.999")
        assert is_valid is False
        assert "does not match pattern" in error

    def test_validate_integer_parameter(self):
        """Test validation of INTEGER parameter."""
        param = Parameter(
            name="threads",
            param_type=ParameterType.INTEGER,
            description="Number of threads",
            required=False,
        )

        # Valid integer
        is_valid, error = param.validate(10)
        assert is_valid is True

        # Invalid: string
        is_valid, error = param.validate("10")
        assert is_valid is False

        # Invalid: boolean (bool is subclass of int in Python)
        is_valid, error = param.validate(True)
        assert is_valid is False

    def test_validate_boolean_parameter(self):
        """Test validation of BOOLEAN parameter."""
        param = Parameter(
            name="verbose",
            param_type=ParameterType.BOOLEAN,
            description="Verbose mode",
            required=False,
        )

        # Valid boolean
        is_valid, error = param.validate(True)
        assert is_valid is True

        is_valid, error = param.validate(False)
        assert is_valid is True

        # Invalid: string
        is_valid, error = param.validate("true")
        assert is_valid is False

    def test_validate_enum_parameter(self):
        """Test validation of ENUM parameter."""
        param = Parameter(
            name="depth",
            param_type=ParameterType.ENUM,
            description="Depth level",
            required=False,
            allowed_values=["stealth", "light", "deep", "aggressive"],
        )

        # Valid value
        is_valid, error = param.validate("deep")
        assert is_valid is True

        # Invalid value
        is_valid, error = param.validate("extreme")
        assert is_valid is False
        assert "one of" in error.lower()

    def test_validate_file_path_parameter(self):
        """Test validation of FILE_PATH parameter."""
        import tempfile
        import os

        param = Parameter(
            name="wordlist",
            param_type=ParameterType.FILE_PATH,
            description="Wordlist file",
            required=False,
        )

        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as f:
            temp_path = f.name

        try:
            # Valid: existing file
            is_valid, error = param.validate(temp_path)
            assert is_valid is True

            # Invalid: non-existent file
            is_valid, error = param.validate("/nonexistent/path/file.txt")
            assert is_valid is False
            assert "non-existent" in error.lower()
        finally:
            os.unlink(temp_path)


class TestCapability:
    """Test Capability dataclass."""

    def test_create_capability_with_defaults(self):
        """Test creating a Capability with default values."""
        cap = Capability(
            name="Port Scanning",
            description="Scan target for open ports",
            category="RECON",
        )
        assert cap.name == "Port Scanning"
        assert cap.description == "Scan target for open ports"
        assert cap.category == "RECON"
        assert cap.evidence_potential == 0.5
        assert cap.preconditions == []
        assert len(cap.id) > 0  # UUID generated

    def test_create_capability_with_custom_values(self):
        """Test creating a Capability with custom values."""
        cap = Capability(
            id="custom-id-123",
            name="SQLi Detection",
            description="Detect SQL injection vulnerabilities",
            category="SCAN",
            evidence_potential=0.85,
            preconditions=["PORT_SCAN", "TECH_DETECT"],
        )
        assert cap.id == "custom-id-123"
        assert cap.name == "SQLi Detection"
        assert cap.evidence_potential == 0.85
        assert len(cap.preconditions) == 2

    def test_evidence_potential_validation(self):
        """Test that evidence_potential is validated."""
        # Valid range
        cap = Capability(name="Test", evidence_potential=0.0)
        assert cap.evidence_potential == 0.0

        cap = Capability(name="Test", evidence_potential=1.0)
        assert cap.evidence_potential == 1.0

        cap = Capability(name="Test", evidence_potential=0.75)
        assert cap.evidence_potential == 0.75

        # Invalid: too high
        with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
            Capability(name="Test", evidence_potential=1.5)

        # Invalid: too low
        with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
            Capability(name="Test", evidence_potential=-0.1)

    def test_capability_uuid_generation(self):
        """Test that each Capability gets a unique UUID."""
        cap1 = Capability(name="Test1")
        cap2 = Capability(name="Test2")
        assert cap1.id != cap2.id


class TestTool:
    """Test Tool dataclass."""

    def test_create_tool_with_minimal_config(self):
        """Test creating a Tool with minimal required configuration."""
        cap = Capability(name="Basic Scan")
        tool = Tool(
            name="TestScanner",
            category="SCANNER",
            capabilities=[cap],
        )
        assert tool.name == "TestScanner"
        assert tool.category == "SCANNER"
        assert len(tool.capabilities) == 1
        assert tool.health_status == HealthStatus.HEALTHY
        assert tool.timeout_seconds == 300
        assert tool.version == "1.0.0"

    def test_create_tool_with_full_config(self):
        """Test creating a Tool with full configuration."""
        cap1 = Capability(name="Recon", category="RECON")
        cap2 = Capability(name="Scan", category="SCAN")
        
        param1 = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            description="Target URL",
            required=True,
        )
        param2 = Parameter(
            name="depth",
            param_type=ParameterType.ENUM,
            description="Scan depth",
            required=False,
            allowed_values=["light", "deep"],
        )

        tool = Tool(
            name="AdvancedScanner",
            category="SCANNER",
            capabilities=[cap1, cap2],
            required_params=[param1],
            optional_params=[param2],
            timeout_seconds=600,
            rate_limit_delay_ms=500,
            max_concurrent_instances=5,
            health_status=HealthStatus.HEALTHY,
            version="2.5.1",
            requires_root=True,
            supported_platforms=["linux", "macos"],
        )
        assert tool.name == "AdvancedScanner"
        assert len(tool.capabilities) == 2
        assert len(tool.required_params) == 1
        assert len(tool.optional_params) == 1
        assert tool.timeout_seconds == 600
        assert tool.requires_root is True

    def test_tool_requires_at_least_one_capability(self):
        """Test that Tool requires at least one capability."""
        with pytest.raises(ValueError, match="at least 1 capability"):
            Tool(name="BadTool", capabilities=[])

    def test_tool_requires_name(self):
        """Test that Tool requires a name."""
        cap = Capability(name="Test")
        with pytest.raises(ValueError, match="name must not be empty"):
            Tool(name="", capabilities=[cap])

    def test_get_all_parameters(self):
        """Test getting all parameters (required + optional)."""
        param1 = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            required=True,
        )
        param2 = Parameter(
            name="depth",
            param_type=ParameterType.STRING,
            required=False,
        )
        param3 = Parameter(
            name="threads",
            param_type=ParameterType.INTEGER,
            required=False,
        )

        cap = Capability(name="Test")
        tool = Tool(
            name="TestTool",
            capabilities=[cap],
            required_params=[param1],
            optional_params=[param2, param3],
        )

        all_params = tool.get_all_parameters()
        assert len(all_params) == 3
        assert param1 in all_params
        assert param2 in all_params
        assert param3 in all_params

    def test_validate_parameters_success(self):
        """Test successful parameter validation."""
        param1 = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            required=True,
        )
        param2 = Parameter(
            name="threads",
            param_type=ParameterType.INTEGER,
            required=False,
        )

        cap = Capability(name="Test")
        tool = Tool(
            name="TestTool",
            capabilities=[cap],
            required_params=[param1],
            optional_params=[param2],
        )

        # Valid parameters
        is_valid, errors = tool.validate_parameters({
            "target": "https://example.com",
            "threads": 10,
        })
        assert is_valid is True
        assert len(errors) == 0

    def test_validate_parameters_missing_required(self):
        """Test validation fails when required parameter is missing."""
        param1 = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            required=True,
        )

        cap = Capability(name="Test")
        tool = Tool(
            name="TestTool",
            capabilities=[cap],
            required_params=[param1],
        )

        # Missing required parameter
        is_valid, errors = tool.validate_parameters({})
        assert is_valid is False
        assert len(errors) == 1
        assert "required" in errors[0].lower()

    def test_validate_parameters_unknown_parameter(self):
        """Test validation fails for unknown parameters."""
        param1 = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            required=True,
        )

        cap = Capability(name="Test")
        tool = Tool(
            name="TestTool",
            capabilities=[cap],
            required_params=[param1],
        )

        # Unknown parameter
        is_valid, errors = tool.validate_parameters({
            "target": "https://example.com",
            "unknown_param": "value",
        })
        assert is_valid is False
        assert any("unknown" in err.lower() for err in errors)

    def test_validate_parameters_invalid_type(self):
        """Test validation fails for invalid parameter types."""
        param1 = Parameter(
            name="threads",
            param_type=ParameterType.INTEGER,
            required=True,
        )

        cap = Capability(name="Test")
        tool = Tool(
            name="TestTool",
            capabilities=[cap],
            required_params=[param1],
        )

        # Wrong type
        is_valid, errors = tool.validate_parameters({
            "threads": "not_a_number",
        })
        assert is_valid is False
        assert len(errors) > 0

    def test_tool_uuid_generation(self):
        """Test that each Tool gets a unique UUID."""
        cap = Capability(name="Test")
        tool1 = Tool(name="Tool1", capabilities=[cap])
        tool2 = Tool(name="Tool2", capabilities=[cap])
        assert tool1.id != tool2.id

    def test_tool_health_status_default(self):
        """Test that Tool defaults to HEALTHY status."""
        cap = Capability(name="Test")
        tool = Tool(name="TestTool", capabilities=[cap])
        assert tool.health_status == HealthStatus.HEALTHY

    def test_tool_multiple_capabilities(self):
        """Test Tool with multiple capabilities."""
        caps = [
            Capability(name="Recon", category="RECON"),
            Capability(name="Scan", category="SCAN"),
            Capability(name="Exploit", category="EXPLOIT"),
        ]
        tool = Tool(name="MultiCap", capabilities=caps)
        assert len(tool.capabilities) == 3


class TestIntegration:
    """Integration tests across all structures."""

    def test_complete_tool_workflow(self):
        """Test a complete tool definition workflow."""
        # Create capabilities
        recon_cap = Capability(
            name="Reconnaissance",
            description="Passive information gathering",
            category="RECON",
            evidence_potential=0.3,
        )
        scan_cap = Capability(
            name="Vulnerability Scanning",
            description="Active vulnerability detection",
            category="SCAN",
            evidence_potential=0.8,
            preconditions=[recon_cap.id],
        )

        # Create parameters
        target_param = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            description="Target URL or IP",
            required=True,
            validation_regex=r"^[a-zA-Z0-9.\-_:/]+$",
        )
        depth_param = Parameter(
            name="depth",
            param_type=ParameterType.ENUM,
            description="Scan depth",
            required=False,
            allowed_values=["stealth", "light", "deep", "aggressive"],
        )
        threads_param = Parameter(
            name="threads",
            param_type=ParameterType.INTEGER,
            description="Number of threads",
            required=False,
        )

        # Create tool
        tool = Tool(
            name="IntegratedScanner",
            category="SCANNER",
            capabilities=[recon_cap, scan_cap],
            required_params=[target_param],
            optional_params=[depth_param, threads_param],
            timeout_seconds=1200,
            version="3.0.0",
            supported_platforms=["linux", "macos", "windows"],
        )

        # Verify tool structure
        assert tool.name == "IntegratedScanner"
        assert len(tool.capabilities) == 2
        assert len(tool.required_params) == 1
        assert len(tool.optional_params) == 2

        # Test parameter validation
        is_valid, errors = tool.validate_parameters({
            "target": "https://example.com",
            "depth": "deep",
            "threads": 20,
        })
        assert is_valid is True
        assert len(errors) == 0

    def test_tool_serialization_compatible(self):
        """Test that structures can be serialized to dictionaries."""
        from dataclasses import asdict

        cap = Capability(
            name="Test",
            description="Test capability",
            category="SCAN",
        )
        param = Parameter(
            name="target",
            param_type=ParameterType.STRING,
            description="Target",
            required=True,
        )
        tool = Tool(
            name="TestTool",
            categories="SCANNER",
            capabilities=[cap],
            required_params=[param],
        )

        # Should be serializable to dict (for JSON output, etc.)
        try:
            tool_dict = asdict(tool)
            assert tool_dict["name"] == "TestTool"
            assert len(tool_dict["capabilities"]) == 1
        except Exception as e:
            pytest.fail(f"Tool should be serializable to dict: {e}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
