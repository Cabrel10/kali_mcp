#!/usr/bin/env python3
"""
Test suite for TASK-CE-01: Capability Engine Data Structures

Tests the instantiation and validation of:
- TargetType enum
- ObjectiveType enum
- QueryConstraints dataclass
- ExecutionCost dataclass
- CapabilityQuery dataclass
- CapabilityMatch dataclass

All structures should be instantiable with test data and properly validate
their constraints (scores in [0.0, 1.0], non-negative costs, etc.)
"""

import pytest
import uuid
from kali_mcp_server import (
    TargetType,
    ObjectiveType,
    QueryConstraints,
    ExecutionCost,
    CapabilityQuery,
    CapabilityMatch,
)


class TestTargetTypeEnum:
    """Test TargetType enum values."""
    
    def test_target_type_web_app(self):
        """Verify WEB_APP target type exists and has correct value."""
        assert TargetType.WEB_APP == "web_app"
        assert TargetType.WEB_APP.value == "web_app"
    
    def test_target_type_api(self):
        """Verify API target type exists."""
        assert TargetType.API == "api"
    
    def test_target_type_network(self):
        """Verify NETWORK target type exists."""
        assert TargetType.NETWORK == "network"
    
    def test_target_type_cloud_infrastructure(self):
        """Verify CLOUD_INFRASTRUCTURE target type exists."""
        assert TargetType.CLOUD_INFRASTRUCTURE == "cloud_infrastructure"
    
    def test_target_type_container(self):
        """Verify CONTAINER target type exists."""
        assert TargetType.CONTAINER == "container"
    
    def test_target_type_saas_platform(self):
        """Verify SAAS_PLATFORM target type exists."""
        assert TargetType.SAAS_PLATFORM == "saas_platform"
    
    def test_target_type_hardware(self):
        """Verify HARDWARE target type exists."""
        assert TargetType.HARDWARE == "hardware"
    
    def test_target_type_all_values(self):
        """Verify all required TargetType values exist."""
        required_values = [
            "web_app", "api", "network", "cloud_infrastructure", "container",
            "saas_platform", "hardware", "internal_network", "binary", "database",
            "message_queue", "cache", "load_balancer", "waf", "mobile_app"
        ]
        actual_values = [t.value for t in TargetType]
        for required in required_values:
            assert required in actual_values, f"Missing TargetType: {required}"


class TestObjectiveTypeEnum:
    """Test ObjectiveType enum values."""
    
    def test_objective_type_recon(self):
        """Verify RECON objective type exists."""
        assert ObjectiveType.RECON == "recon"
    
    def test_objective_type_vulnerability_assessment(self):
        """Verify VULNERABILITY_ASSESSMENT objective type exists."""
        assert ObjectiveType.VULNERABILITY_ASSESSMENT == "vulnerability_assessment"
    
    def test_objective_type_exploit_verification(self):
        """Verify EXPLOIT_VERIFICATION objective type exists."""
        assert ObjectiveType.EXPLOIT_VERIFICATION == "exploit_verification"
    
    def test_objective_type_all_values(self):
        """Verify all required ObjectiveType values exist."""
        required_values = [
            "recon", "vulnerability_assessment", "configuration_audit",
            "exploit_verification", "compliance_audit", "proof_of_concept",
            "privilege_escalation", "lateral_movement", "persistence",
            "data_exfiltration", "threat_modeling"
        ]
        actual_values = [o.value for o in ObjectiveType]
        for required in required_values:
            assert required in actual_values, f"Missing ObjectiveType: {required}"


class TestQueryConstraints:
    """Test QueryConstraints dataclass instantiation and validation."""
    
    def test_instantiate_with_defaults(self):
        """Verify QueryConstraints instantiates with default values."""
        constraints = QueryConstraints()
        assert constraints.max_execution_time_seconds == 3600
        assert constraints.budget_spent_usd == 0.0
        assert constraints.budget_available_usd == 10000.0
        assert constraints.critical_path_only == False
        assert constraints.parallel_capable == True
        assert constraints.preconditions_satisfied == []
    
    def test_instantiate_with_custom_values(self):
        """Verify QueryConstraints accepts custom values."""
        constraints = QueryConstraints(
            max_execution_time_seconds=7200,
            budget_spent_usd=100.0,
            budget_available_usd=900.0,
            critical_path_only=True,
            parallel_capable=False,
            preconditions_satisfied=["RECON_COMPLETE", "BASELINE_ESTABLISHED"]
        )
        assert constraints.max_execution_time_seconds == 7200
        assert constraints.budget_spent_usd == 100.0
        assert constraints.budget_available_usd == 900.0
        assert constraints.critical_path_only == True
        assert constraints.parallel_capable == False
        assert len(constraints.preconditions_satisfied) == 2
    
    def test_rejects_negative_execution_time(self):
        """Verify QueryConstraints rejects negative execution time."""
        with pytest.raises(ValueError, match="max_execution_time_seconds cannot be negative"):
            QueryConstraints(max_execution_time_seconds=-1)
    
    def test_rejects_negative_budget_spent(self):
        """Verify QueryConstraints rejects negative budget spent."""
        with pytest.raises(ValueError, match="budget_spent_usd cannot be negative"):
            QueryConstraints(budget_spent_usd=-100.0)
    
    def test_rejects_negative_budget_available(self):
        """Verify QueryConstraints rejects negative budget available."""
        with pytest.raises(ValueError, match="budget_available_usd cannot be negative"):
            QueryConstraints(budget_available_usd=-100.0)


class TestExecutionCost:
    """Test ExecutionCost dataclass instantiation and validation."""
    
    def test_instantiate_with_defaults(self):
        """Verify ExecutionCost instantiates with default values."""
        cost = ExecutionCost()
        assert cost.cpu_percent == 10.0
        assert cost.memory_mb == 100
        assert cost.network_requests == 10
        assert cost.api_calls_remaining == 1000
        assert cost.rate_limit_reset_seconds == 0
    
    def test_instantiate_with_custom_values(self):
        """Verify ExecutionCost accepts custom values."""
        cost = ExecutionCost(
            cpu_percent=75.5,
            memory_mb=512,
            network_requests=1000,
            api_calls_remaining=500,
            rate_limit_reset_seconds=120
        )
        assert cost.cpu_percent == 75.5
        assert cost.memory_mb == 512
        assert cost.network_requests == 1000
        assert cost.api_calls_remaining == 500
        assert cost.rate_limit_reset_seconds == 120
    
    def test_rejects_cpu_percent_below_zero(self):
        """Verify ExecutionCost rejects cpu_percent < 0."""
        with pytest.raises(ValueError, match="cpu_percent must be between 0 and 100"):
            ExecutionCost(cpu_percent=-1.0)
    
    def test_rejects_cpu_percent_above_100(self):
        """Verify ExecutionCost rejects cpu_percent > 100."""
        with pytest.raises(ValueError, match="cpu_percent must be between 0 and 100"):
            ExecutionCost(cpu_percent=101.0)
    
    def test_accepts_cpu_percent_boundary_0(self):
        """Verify ExecutionCost accepts cpu_percent = 0."""
        cost = ExecutionCost(cpu_percent=0.0)
        assert cost.cpu_percent == 0.0
    
    def test_accepts_cpu_percent_boundary_100(self):
        """Verify ExecutionCost accepts cpu_percent = 100."""
        cost = ExecutionCost(cpu_percent=100.0)
        assert cost.cpu_percent == 100.0
    
    def test_rejects_negative_memory(self):
        """Verify ExecutionCost rejects negative memory."""
        with pytest.raises(ValueError, match="memory_mb cannot be negative"):
            ExecutionCost(memory_mb=-1)
    
    def test_rejects_negative_network_requests(self):
        """Verify ExecutionCost rejects negative network requests."""
        with pytest.raises(ValueError, match="network_requests cannot be negative"):
            ExecutionCost(network_requests=-1)
    
    def test_rejects_negative_api_calls(self):
        """Verify ExecutionCost rejects negative API calls remaining."""
        with pytest.raises(ValueError, match="api_calls_remaining cannot be negative"):
            ExecutionCost(api_calls_remaining=-1)
    
    def test_rejects_negative_rate_limit_reset(self):
        """Verify ExecutionCost rejects negative rate limit reset seconds."""
        with pytest.raises(ValueError, match="rate_limit_reset_seconds cannot be negative"):
            ExecutionCost(rate_limit_reset_seconds=-1)


class TestCapabilityQuery:
    """Test CapabilityQuery dataclass instantiation and validation."""
    
    def test_instantiate_minimal(self):
        """Verify CapabilityQuery instantiates with only required target_type."""
        query = CapabilityQuery(target_type=TargetType.WEB_APP)
        assert query.target_type == TargetType.WEB_APP
        assert query.detected_tech_stack == []
        assert query.objective == ObjectiveType.VULNERABILITY_ASSESSMENT
        assert isinstance(query.constraints, QueryConstraints)
        assert query.evidence_requirements == {}
        # session_id should be auto-generated UUID string
        assert isinstance(query.session_id, str)
        assert len(query.session_id) > 0
    
    def test_instantiate_with_tech_stack(self):
        """Verify CapabilityQuery accepts detected tech stack."""
        query = CapabilityQuery(
            target_type=TargetType.WEB_APP,
            detected_tech_stack=["Java", "Spring", "Tomcat"]
        )
        assert query.detected_tech_stack == ["Java", "Spring", "Tomcat"]
    
    def test_instantiate_with_objective(self):
        """Verify CapabilityQuery accepts different objectives."""
        query = CapabilityQuery(
            target_type=TargetType.API,
            objective=ObjectiveType.EXPLOIT_VERIFICATION
        )
        assert query.objective == ObjectiveType.EXPLOIT_VERIFICATION
    
    def test_instantiate_with_constraints(self):
        """Verify CapabilityQuery accepts custom constraints."""
        constraints = QueryConstraints(max_execution_time_seconds=7200)
        query = CapabilityQuery(
            target_type=TargetType.NETWORK,
            constraints=constraints
        )
        assert query.constraints.max_execution_time_seconds == 7200
    
    def test_instantiate_with_evidence_requirements(self):
        """Verify CapabilityQuery accepts evidence requirements."""
        query = CapabilityQuery(
            target_type=TargetType.WEB_APP,
            evidence_requirements={"proof_of_concept": 0.8, "vulnerability_class": 0.5}
        )
        assert query.evidence_requirements["proof_of_concept"] == 0.8
        assert query.evidence_requirements["vulnerability_class"] == 0.5
    
    def test_rejects_invalid_target_type(self):
        """Verify CapabilityQuery rejects invalid target type."""
        with pytest.raises(ValueError, match="target_type must be TargetType"):
            CapabilityQuery(target_type="invalid_type")
    
    def test_rejects_invalid_objective(self):
        """Verify CapabilityQuery rejects invalid objective type."""
        query_obj = CapabilityQuery(target_type=TargetType.WEB_APP)
        # Manually override to test post_init validation
        query_obj.objective = "invalid_objective"
        with pytest.raises(ValueError, match="objective must be ObjectiveType"):
            CapabilityQuery(
                target_type=TargetType.WEB_APP,
                objective="invalid_objective"
            )
    
    def test_rejects_evidence_requirement_above_1(self):
        """Verify CapabilityQuery rejects evidence requirement > 1.0."""
        with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
            CapabilityQuery(
                target_type=TargetType.WEB_APP,
                evidence_requirements={"test": 1.5}
            )
    
    def test_rejects_evidence_requirement_below_0(self):
        """Verify CapabilityQuery rejects evidence requirement < 0.0."""
        with pytest.raises(ValueError, match="must be between 0.0 and 1.0"):
            CapabilityQuery(
                target_type=TargetType.WEB_APP,
                evidence_requirements={"test": -0.1}
            )
    
    def test_accepts_evidence_requirement_boundaries(self):
        """Verify CapabilityQuery accepts evidence requirements at boundaries."""
        query = CapabilityQuery(
            target_type=TargetType.WEB_APP,
            evidence_requirements={"test_0": 0.0, "test_1": 1.0}
        )
        assert query.evidence_requirements["test_0"] == 0.0
        assert query.evidence_requirements["test_1"] == 1.0
    
    def test_session_id_uniqueness(self):
        """Verify CapabilityQuery generates unique session IDs."""
        query1 = CapabilityQuery(target_type=TargetType.WEB_APP)
        query2 = CapabilityQuery(target_type=TargetType.WEB_APP)
        assert query1.session_id != query2.session_id


class TestCapabilityMatch:
    """Test CapabilityMatch dataclass instantiation and validation."""
    
    def test_instantiate_minimal(self):
        """Verify CapabilityMatch instantiates with only required tool_name."""
        match = CapabilityMatch(tool_name="nuclei")
        assert match.tool_name == "nuclei"
        assert isinstance(match.tool_id, str)
        assert match.matching_capabilities == []
        assert match.relevance_score == 0.0
        assert match.evidence_potential == 0.0
        assert match.compatibility == []
        assert match.last_run_seconds_ago is None
        assert match.success_rate == 0.5
        assert isinstance(match.estimated_cost, ExecutionCost)
    
    def test_instantiate_with_all_fields(self):
        """Verify CapabilityMatch accepts all fields."""
        cost = ExecutionCost(cpu_percent=50.0, memory_mb=256)
        match = CapabilityMatch(
            tool_id="abc123-def456",
            tool_name="nuclei",
            matching_capabilities=["XSS_DETECTION", "SQLI_DETECTION"],
            relevance_score=0.95,
            evidence_potential=0.85,
            compatibility=["Java", "Spring"],
            last_run_seconds_ago=300,
            success_rate=0.88,
            estimated_cost=cost
        )
        assert match.tool_id == "abc123-def456"
        assert match.tool_name == "nuclei"
        assert len(match.matching_capabilities) == 2
        assert match.relevance_score == 0.95
        assert match.evidence_potential == 0.85
        assert len(match.compatibility) == 2
        assert match.last_run_seconds_ago == 300
        assert match.success_rate == 0.88
        assert match.estimated_cost.cpu_percent == 50.0
    
    def test_rejects_relevance_score_above_1(self):
        """Verify CapabilityMatch rejects relevance_score > 1.0."""
        with pytest.raises(ValueError, match="relevance_score must be between 0.0 and 1.0"):
            CapabilityMatch(tool_name="nuclei", relevance_score=1.5)
    
    def test_rejects_relevance_score_below_0(self):
        """Verify CapabilityMatch rejects relevance_score < 0.0."""
        with pytest.raises(ValueError, match="relevance_score must be between 0.0 and 1.0"):
            CapabilityMatch(tool_name="nuclei", relevance_score=-0.1)
    
    def test_rejects_evidence_potential_above_1(self):
        """Verify CapabilityMatch rejects evidence_potential > 1.0."""
        with pytest.raises(ValueError, match="evidence_potential must be between 0.0 and 1.0"):
            CapabilityMatch(tool_name="nuclei", evidence_potential=1.5)
    
    def test_rejects_evidence_potential_below_0(self):
        """Verify CapabilityMatch rejects evidence_potential < 0.0."""
        with pytest.raises(ValueError, match="evidence_potential must be between 0.0 and 1.0"):
            CapabilityMatch(tool_name="nuclei", evidence_potential=-0.1)
    
    def test_rejects_success_rate_above_1(self):
        """Verify CapabilityMatch rejects success_rate > 1.0."""
        with pytest.raises(ValueError, match="success_rate must be between 0.0 and 1.0"):
            CapabilityMatch(tool_name="nuclei", success_rate=1.5)
    
    def test_rejects_success_rate_below_0(self):
        """Verify CapabilityMatch rejects success_rate < 0.0."""
        with pytest.raises(ValueError, match="success_rate must be between 0.0 and 1.0"):
            CapabilityMatch(tool_name="nuclei", success_rate=-0.1)
    
    def test_accepts_score_boundaries(self):
        """Verify CapabilityMatch accepts scores at 0.0 and 1.0 boundaries."""
        match = CapabilityMatch(
            tool_name="nuclei",
            relevance_score=0.0,
            evidence_potential=1.0,
            success_rate=0.0
        )
        assert match.relevance_score == 0.0
        assert match.evidence_potential == 1.0
        assert match.success_rate == 0.0
    
    def test_rejects_empty_tool_name(self):
        """Verify CapabilityMatch rejects empty tool_name."""
        with pytest.raises(ValueError, match="tool_name must not be empty"):
            CapabilityMatch(tool_name="")


class TestIntegration:
    """Integration tests combining multiple structures."""
    
    def test_capability_query_with_multiple_targets(self):
        """Verify CapabilityQuery works with different target types."""
        targets = [
            TargetType.WEB_APP,
            TargetType.API,
            TargetType.NETWORK,
            TargetType.CLOUD_INFRASTRUCTURE,
            TargetType.CONTAINER,
        ]
        for target in targets:
            query = CapabilityQuery(target_type=target)
            assert query.target_type == target
    
    def test_capability_query_with_multiple_objectives(self):
        """Verify CapabilityQuery works with different objectives."""
        objectives = [
            ObjectiveType.RECON,
            ObjectiveType.VULNERABILITY_ASSESSMENT,
            ObjectiveType.EXPLOIT_VERIFICATION,
            ObjectiveType.COMPLIANCE_AUDIT,
            ObjectiveType.PRIVILEGE_ESCALATION,
        ]
        for objective in objectives:
            query = CapabilityQuery(
                target_type=TargetType.WEB_APP,
                objective=objective
            )
            assert query.objective == objective
    
    def test_create_realistic_capability_query(self):
        """Verify realistic CapabilityQuery for web app vulnerability assessment."""
        query = CapabilityQuery(
            target_type=TargetType.WEB_APP,
            detected_tech_stack=["Java", "Spring", "Tomcat", "MySQL"],
            objective=ObjectiveType.VULNERABILITY_ASSESSMENT,
            constraints=QueryConstraints(
                max_execution_time_seconds=3600,
                budget_spent_usd=50.0,
                budget_available_usd=950.0,
                critical_path_only=False,
                parallel_capable=True
            ),
            evidence_requirements={
                "vulnerability_class": 0.8,
                "proof_of_concept": 0.6,
                "affected_versions": 0.7
            }
        )
        assert query.target_type == TargetType.WEB_APP
        assert "Java" in query.detected_tech_stack
        assert query.objective == ObjectiveType.VULNERABILITY_ASSESSMENT
        assert query.constraints.max_execution_time_seconds == 3600
        assert len(query.evidence_requirements) == 3
    
    def test_create_realistic_capability_matches(self):
        """Verify creation of realistic CapabilityMatch results."""
        matches = [
            CapabilityMatch(
                tool_id="tool-nuclei-001",
                tool_name="nuclei",
                matching_capabilities=["XSS_DETECTION", "SQLI_DETECTION", "SSRF_DETECTION"],
                relevance_score=0.95,
                evidence_potential=0.85,
                compatibility=["Java", "Spring", "MySQL"],
                last_run_seconds_ago=None,
                success_rate=0.92,
                estimated_cost=ExecutionCost(
                    cpu_percent=25.0,
                    memory_mb=256,
                    network_requests=500,
                    api_calls_remaining=5000
                )
            ),
            CapabilityMatch(
                tool_id="tool-sqlmap-001",
                tool_name="sqlmap",
                matching_capabilities=["SQLI_DETECTION"],
                relevance_score=0.88,
                evidence_potential=0.95,
                compatibility=["MySQL", "PostgreSQL"],
                last_run_seconds_ago=600,
                success_rate=0.85,
                estimated_cost=ExecutionCost(
                    cpu_percent=15.0,
                    memory_mb=128,
                    network_requests=1000,
                    api_calls_remaining=10000
                )
            ),
            CapabilityMatch(
                tool_id="tool-hydra-001",
                tool_name="hydra",
                matching_capabilities=["CREDENTIAL_CRACKING"],
                relevance_score=0.45,
                evidence_potential=0.75,
                compatibility=["HTTP", "HTTPS"],
                last_run_seconds_ago=None,
                success_rate=0.60,
                estimated_cost=ExecutionCost(
                    cpu_percent=80.0,
                    memory_mb=512,
                    network_requests=100000,
                    api_calls_remaining=100000
                )
            ),
        ]
        
        # Verify matches are sorted by relevance (should be: nuclei, sqlmap, hydra)
        assert matches[0].relevance_score == 0.95
        assert matches[1].relevance_score == 0.88
        assert matches[2].relevance_score == 0.45
        
        # Verify all matches have valid scores
        for match in matches:
            assert 0.0 <= match.relevance_score <= 1.0
            assert 0.0 <= match.evidence_potential <= 1.0
            assert 0.0 <= match.success_rate <= 1.0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
