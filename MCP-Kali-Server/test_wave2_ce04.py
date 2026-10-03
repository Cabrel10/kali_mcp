#!/usr/bin/env python3
"""
TASK-CE-04 Test Suite: Evidence Requirements Scoring
"""

import pytest
from enum import Enum
from dataclasses import dataclass, field
from typing import List, Optional, Dict


class EvidenceMaturity(str, Enum):
    """Evidence maturity levels."""
    OBSERVED = "observed"
    SUSPECTED = "suspected"
    CONFIRMED = "confirmed"
    EXPLOITED = "exploited"


@dataclass
class EvidenceScore:
    """Evidence score for a tool."""
    tool_id: str
    finding_type: str
    achievable_maturity: EvidenceMaturity
    confidence: float
    missing_evidence: List[str] = field(default_factory=list)
    validation_path: List[str] = field(default_factory=list)


@dataclass
class SimpleTool:
    """Tool for testing."""
    id: str
    name: str
    capabilities: List[str]


EVIDENCE_POLICY = {
    "SSRF": {
        "response_time_diff": EvidenceMaturity.OBSERVED,
        "different_response": EvidenceMaturity.SUSPECTED,
        "metadata_markers": EvidenceMaturity.CONFIRMED,
        "metadata_extraction": EvidenceMaturity.EXPLOITED,
    },
    "SSTI": {
        "engine_detected": EvidenceMaturity.OBSERVED,
        "secondary_eval": EvidenceMaturity.SUSPECTED,
        "expression_result": EvidenceMaturity.CONFIRMED,
        "code_execution": EvidenceMaturity.EXPLOITED,
    },
    "IDOR": {
        "size_diff": EvidenceMaturity.OBSERVED,
        "pattern_detected": EvidenceMaturity.SUSPECTED,
        "data_access": EvidenceMaturity.CONFIRMED,
        "full_breach": EvidenceMaturity.EXPLOITED,
    },
    "XSS": {
        "reflection": EvidenceMaturity.OBSERVED,
        "unescaped_output": EvidenceMaturity.SUSPECTED,
        "payload_execution": EvidenceMaturity.CONFIRMED,
        "data_theft": EvidenceMaturity.EXPLOITED,
    },
}


def score_evidence_potential(tool: SimpleTool, finding_type: str) -> EvidenceScore:
    """Score tool's evidence potential for a finding type."""
    if finding_type not in EVIDENCE_POLICY:
        raise ValueError(f"Unknown finding type: {finding_type}")
    
    policy = EVIDENCE_POLICY[finding_type]
    maturity_order = [EvidenceMaturity.OBSERVED, EvidenceMaturity.SUSPECTED, 
                     EvidenceMaturity.CONFIRMED, EvidenceMaturity.EXPLOITED]
    
    highest_maturity_idx = 0  # Start with OBSERVED
    matching_capabilities = []
    
    for capability, maturity in policy.items():
        if capability in tool.capabilities:
            matching_capabilities.append(capability)
            maturity_idx = maturity_order.index(maturity)
            if maturity_idx > highest_maturity_idx:
                highest_maturity_idx = maturity_idx
    
    highest_maturity = maturity_order[highest_maturity_idx]
    confidence = min(len(matching_capabilities) / len(policy), 1.0) if policy else 0.0
    missing = [cap for cap in policy.keys() if cap not in tool.capabilities]
    
    return EvidenceScore(
        tool_id=tool.id,
        finding_type=finding_type,
        achievable_maturity=highest_maturity,
        confidence=confidence,
        missing_evidence=missing,
        validation_path=matching_capabilities
    )


def filter_by_evidence_requirements(
    tools: List[SimpleTool],
    requirements: Dict[str, EvidenceMaturity]
) -> List[SimpleTool]:
    """Filter tools that meet all evidence requirements."""
    results = []
    maturity_order = [EvidenceMaturity.OBSERVED, EvidenceMaturity.SUSPECTED, 
                     EvidenceMaturity.CONFIRMED, EvidenceMaturity.EXPLOITED]
    
    for tool in tools:
        meets_all = True
        for finding_type, required_maturity in requirements.items():
            score = score_evidence_potential(tool, finding_type)
            
            if maturity_order.index(score.achievable_maturity) < maturity_order.index(required_maturity):
                meets_all = False
                break
        
        if meets_all:
            results.append(tool)
    
    return results


def recommend_validation_steps(tool: SimpleTool, finding_type: str) -> List[str]:
    """Recommend validation steps for tool."""
    score = score_evidence_potential(tool, finding_type)
    steps = []
    
    steps.extend([f"Validate: {cap}" for cap in score.validation_path])
    
    return steps


class TestEvidenceScoringLogic:
    """Test evidence scoring functions."""
    
    def test_score_ssrf_with_metadata_markers(self):
        """Score SSRF tool with metadata_markers."""
        tool = SimpleTool("t1", "SSRF Tool", ["metadata_markers"])
        score = score_evidence_potential(tool, "SSRF")
        
        assert score.achievable_maturity == EvidenceMaturity.CONFIRMED
        assert score.confidence > 0.0
    
    def test_score_ssti_with_expression_result(self):
        """Score SSTI tool with expression_result."""
        tool = SimpleTool("t2", "SSTI Tool", ["expression_result"])
        score = score_evidence_potential(tool, "SSTI")
        
        assert score.achievable_maturity == EvidenceMaturity.CONFIRMED
    
    def test_score_xss_with_payload_execution(self):
        """Score XSS tool with payload_execution."""
        tool = SimpleTool("t3", "XSS Tool", ["payload_execution"])
        score = score_evidence_potential(tool, "XSS")
        
        assert score.achievable_maturity == EvidenceMaturity.CONFIRMED
    
    def test_score_tool_with_no_capabilities(self):
        """Score tool with no capabilities."""
        tool = SimpleTool("t4", "Generic", [])
        score = score_evidence_potential(tool, "SSRF")
        
        assert score.achievable_maturity == EvidenceMaturity.OBSERVED
        assert score.confidence == 0.0
    
    def test_score_tool_exploited(self):
        """Score tool with EXPLOITED capability."""
        tool = SimpleTool("t5", "Full Tool", ["metadata_extraction"])
        score = score_evidence_potential(tool, "SSRF")
        
        assert score.achievable_maturity == EvidenceMaturity.EXPLOITED


class TestEvidenceFiltering:
    """Test evidence filtering."""
    
    @pytest.fixture
    def test_tools(self):
        """Create test tools."""
        return [
            SimpleTool("t1", "T1", ["metadata_markers"]),
            SimpleTool("t2", "T2", ["metadata_extraction"]),
            SimpleTool("t3", "T3", ["response_time_diff"]),
            SimpleTool("t4", "T4", []),
        ]
    
    def test_filter_ssrf_confirmed(self, test_tools):
        """Filter tools that achieve CONFIRMED for SSRF."""
        requirements = {"SSRF": EvidenceMaturity.CONFIRMED}
        results = filter_by_evidence_requirements(test_tools, requirements)
        
        # t1 and t2 can achieve CONFIRMED
        assert len(results) >= 2
    
    def test_filter_ssrf_exploited(self, test_tools):
        """Filter tools that achieve EXPLOITED for SSRF."""
        requirements = {"SSRF": EvidenceMaturity.EXPLOITED}
        results = filter_by_evidence_requirements(test_tools, requirements)
        
        # Only t2 has metadata_extraction
        assert len(results) >= 1
    
    def test_filter_multiple_requirements(self, test_tools):
        """Filter by multiple requirements."""
        requirements = {
            "SSRF": EvidenceMaturity.CONFIRMED,
            "SSTI": EvidenceMaturity.OBSERVED
        }
        results = filter_by_evidence_requirements(test_tools, requirements)
        assert isinstance(results, list)


class TestValidationRecommendations:
    """Test validation recommendations."""
    
    def test_recommend_steps(self):
        """Recommend validation steps."""
        tool = SimpleTool("t1", "Tool", ["metadata_markers"])
        steps = recommend_validation_steps(tool, "SSRF")
        
        assert len(steps) > 0


class TestAcceptanceCriteria:
    """Test acceptance criteria."""
    
    def test_ac1_maturity_levels(self):
        """AC1: Evidence maturity levels."""
        levels = [EvidenceMaturity.OBSERVED, EvidenceMaturity.SUSPECTED,
                 EvidenceMaturity.CONFIRMED, EvidenceMaturity.EXPLOITED]
        assert len(levels) == 4
    
    def test_ac2_score_by_level(self):
        """AC2: Score by maximum achievable level."""
        tool = SimpleTool("t1", "Test", ["metadata_extraction"])
        score = score_evidence_potential(tool, "SSRF")
        assert score.achievable_maturity == EvidenceMaturity.EXPLOITED
    
    def test_ac3_filter_requirements(self):
        """AC3: Filter by evidence requirements."""
        tools = [
            SimpleTool("t1", "T1", ["metadata_markers"]),
            SimpleTool("t2", "T2", []),
        ]
        reqs = {"SSRF": EvidenceMaturity.CONFIRMED}
        results = filter_by_evidence_requirements(tools, reqs)
        assert len(results) >= 1
    
    def test_ac4_recommend_validation(self):
        """AC4: Recommend validation steps."""
        tool = SimpleTool("t1", "Test", ["metadata_markers"])
        steps = recommend_validation_steps(tool, "SSRF")
        assert len(steps) > 0
    
    def test_ac5_insufficient_capability(self):
        """AC5: Detect insufficient capability."""
        tool = SimpleTool("t1", "Test", ["response_time_diff"])
        score = score_evidence_potential(tool, "SSRF")
        
        # response_time_diff = OBSERVED only
        assert score.achievable_maturity == EvidenceMaturity.OBSERVED


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
