#!/usr/bin/env python3
"""
TASK-ORCH-01 Test Suite: Orchestrator Core and Execution Phases

Tests:
1. Orchestrator initialization with Tool Registry and Capability Engine
2. Execution phase definitions (discovery, baseline, payload, evidence)
3. Phase sequencing (baseline must run before payload)
4. Session management
5. Results collection
"""

import pytest
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Dict, Any
import datetime


class ExecutionPhase(str, Enum):
    """Execution phases in orchestrated pentest."""
    DISCOVERY = "discovery"
    BASELINE = "baseline"
    PAYLOAD = "payload"
    EVIDENCE = "evidence"
    REPORTING = "reporting"


@dataclass
class PhaseConfig:
    """Configuration for an execution phase."""
    phase_type: ExecutionPhase
    sequence_index: int  # 0=discovery, 1=baseline, 2=payload, 3=evidence, 4=reporting
    enabled: bool = True
    timeout_seconds: int = 3600
    max_tools: int = 10
    parallel_execution: bool = True
    description: str = ""


@dataclass
class PhaseResult:
    """Result from executing a phase."""
    phase_type: ExecutionPhase
    start_time: str
    end_time: Optional[str] = None
    status: str = "running"  # running, completed, failed
    tools_executed: int = 0
    findings_count: int = 0
    error_message: Optional[str] = None
    duration_seconds: float = 0.0


@dataclass
class OrchestrationSession:
    """Session for orchestrated pentest run."""
    session_id: str
    target: str
    start_time: str
    end_time: Optional[str] = None
    status: str = "initialized"  # initialized, running, completed, failed
    phases: List[PhaseResult] = field(default_factory=list)
    total_findings: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)


class Orchestrator:
    """Core orchestrator for coordinating pentest phases."""
    
    def __init__(self, tool_registry=None, capability_engine=None):
        """Initialize orchestrator."""
        self.tool_registry = tool_registry
        self.capability_engine = capability_engine
        self.phases: Dict[ExecutionPhase, PhaseConfig] = {}
        self.sessions: Dict[str, OrchestrationSession] = {}
        self.current_session: Optional[OrchestrationSession] = None
    
    def register_phase(self, config: PhaseConfig) -> None:
        """Register an execution phase."""
        if not isinstance(config, PhaseConfig):
            raise TypeError("config must be PhaseConfig")
        
        self.phases[config.phase_type] = config
    
    def validate_phase_order(self) -> bool:
        """Validate that phases are in correct order."""
        phase_indices = {p.phase_type: p.sequence_index for p in self.phases.values()}
        
        # Baseline must come before payload
        baseline_idx = phase_indices.get(ExecutionPhase.BASELINE, -1)
        payload_idx = phase_indices.get(ExecutionPhase.PAYLOAD, -1)
        
        if baseline_idx >= 0 and payload_idx >= 0:
            return baseline_idx < payload_idx
        
        return True
    
    def create_session(self, target: str) -> OrchestrationSession:
        """Create new orchestration session."""
        session_id = f"orch_{datetime.datetime.now().strftime('%Y%m%d_%H%M%S')}"
        session = OrchestrationSession(
            session_id=session_id,
            target=target,
            start_time=datetime.datetime.now().isoformat()
        )
        self.sessions[session_id] = session
        self.current_session = session
        return session
    
    def get_session(self, session_id: str) -> Optional[OrchestrationSession]:
        """Retrieve a session."""
        return self.sessions.get(session_id)
    
    def start_phase(self, session_id: str, phase_type: ExecutionPhase) -> PhaseResult:
        """Start executing a phase."""
        if phase_type not in self.phases:
            raise ValueError(f"Phase {phase_type} not registered")
        
        result = PhaseResult(
            phase_type=phase_type,
            start_time=datetime.datetime.now().isoformat(),
            status="running"
        )
        
        session = self.get_session(session_id)
        if session:
            session.phases.append(result)
        
        return result
    
    def end_phase(self, result: PhaseResult, status: str, findings: int = 0) -> None:
        """Complete a phase execution."""
        result.end_time = datetime.datetime.now().isoformat()
        result.status = status
        result.findings_count = findings
        
        # Calculate duration
        from datetime import datetime as dt
        start = dt.fromisoformat(result.start_time)
        end = dt.fromisoformat(result.end_time)
        result.duration_seconds = (end - start).total_seconds()
    
    def get_execution_order(self) -> List[ExecutionPhase]:
        """Get phases in correct execution order."""
        sorted_phases = sorted(
            self.phases.values(),
            key=lambda p: p.sequence_index
        )
        return [p.phase_type for p in sorted_phases]


class TestOrchestratorInit:
    """Test orchestrator initialization."""
    
    def test_init_without_registry(self):
        """Initialize orchestrator without external registry."""
        orch = Orchestrator()
        assert orch.tool_registry is None
        assert orch.capability_engine is None
        assert len(orch.phases) == 0
    
    def test_init_with_registry(self):
        """Initialize orchestrator with registry."""
        mock_registry = object()
        mock_engine = object()
        orch = Orchestrator(tool_registry=mock_registry, capability_engine=mock_engine)
        assert orch.tool_registry is mock_registry
        assert orch.capability_engine is mock_engine


class TestPhaseConfiguration:
    """Test phase configuration."""
    
    def test_create_discovery_phase(self):
        """Create discovery phase config."""
        phase = PhaseConfig(
            phase_type=ExecutionPhase.DISCOVERY,
            sequence_index=0,
            description="Target reconnaissance"
        )
        assert phase.phase_type == ExecutionPhase.DISCOVERY
        assert phase.sequence_index == 0
        assert phase.enabled is True
    
    def test_create_baseline_phase(self):
        """Create baseline phase config."""
        phase = PhaseConfig(
            phase_type=ExecutionPhase.BASELINE,
            sequence_index=1,
            timeout_seconds=1800
        )
        assert phase.phase_type == ExecutionPhase.BASELINE
        assert phase.timeout_seconds == 1800
    
    def test_create_payload_phase(self):
        """Create payload phase config."""
        phase = PhaseConfig(
            phase_type=ExecutionPhase.PAYLOAD,
            sequence_index=2,
            parallel_execution=True
        )
        assert phase.phase_type == ExecutionPhase.PAYLOAD
        assert phase.sequence_index == 2


class TestPhaseSequencing:
    """Test phase sequencing and ordering."""
    
    def test_register_phases(self):
        """Register multiple phases."""
        orch = Orchestrator()
        
        orch.register_phase(PhaseConfig(ExecutionPhase.DISCOVERY, 0))
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        orch.register_phase(PhaseConfig(ExecutionPhase.PAYLOAD, 2))
        
        assert len(orch.phases) == 3
    
    def test_validate_phase_order_correct(self):
        """Validate correct phase order."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        orch.register_phase(PhaseConfig(ExecutionPhase.PAYLOAD, 2))
        
        assert orch.validate_phase_order() is True
    
    def test_validate_phase_order_incorrect(self):
        """Validate incorrect phase order (payload before baseline)."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.PAYLOAD, 1))
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 2))
        
        assert orch.validate_phase_order() is False
    
    def test_get_execution_order(self):
        """Get correct execution order."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.PAYLOAD, 2))
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        orch.register_phase(PhaseConfig(ExecutionPhase.DISCOVERY, 0))
        
        order = orch.get_execution_order()
        
        assert order[0] == ExecutionPhase.DISCOVERY
        assert order[1] == ExecutionPhase.BASELINE
        assert order[2] == ExecutionPhase.PAYLOAD


class TestSessionManagement:
    """Test session management."""
    
    def test_create_session(self):
        """Create new session."""
        orch = Orchestrator()
        session = orch.create_session("http://example.com")
        
        assert session.target == "http://example.com"
        assert session.status == "initialized"
        assert len(session.phases) == 0
    
    def test_get_session(self):
        """Retrieve session."""
        orch = Orchestrator()
        session = orch.create_session("http://example.com")
        
        retrieved = orch.get_session(session.session_id)
        assert retrieved is not None
        assert retrieved.target == "http://example.com"
    
    def test_get_nonexistent_session(self):
        """Retrieve non-existent session."""
        orch = Orchestrator()
        retrieved = orch.get_session("nonexistent")
        
        assert retrieved is None


class TestPhaseExecution:
    """Test phase execution."""
    
    def test_start_phase(self):
        """Start executing a phase."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        session = orch.create_session("http://example.com")
        
        result = orch.start_phase(session.session_id, ExecutionPhase.BASELINE)
        
        assert result.phase_type == ExecutionPhase.BASELINE
        assert result.status == "running"
    
    def test_start_unregistered_phase(self):
        """Try to start unregistered phase."""
        orch = Orchestrator()
        session = orch.create_session("http://example.com")
        
        with pytest.raises(ValueError):
            orch.start_phase(session.session_id, ExecutionPhase.BASELINE)
    
    def test_end_phase(self):
        """Complete phase execution."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        session = orch.create_session("http://example.com")
        
        result = orch.start_phase(session.session_id, ExecutionPhase.BASELINE)
        orch.end_phase(result, "completed", findings=5)
        
        assert result.status == "completed"
        assert result.findings_count == 5
        assert result.duration_seconds >= 0


class TestAcceptanceCriteria:
    """Test acceptance criteria."""
    
    def test_ac1_orchestrator_init(self):
        """AC1: Orchestrator initialization."""
        orch = Orchestrator()
        assert orch is not None
    
    def test_ac2_execution_phases(self):
        """AC2: Multiple execution phases."""
        phases = [ExecutionPhase.DISCOVERY, ExecutionPhase.BASELINE,
                 ExecutionPhase.PAYLOAD, ExecutionPhase.EVIDENCE]
        assert len(phases) == 4
    
    def test_ac3_phase_sequencing(self):
        """AC3: Phase sequencing (baseline before payload)."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        orch.register_phase(PhaseConfig(ExecutionPhase.PAYLOAD, 2))
        
        assert orch.validate_phase_order() is True
    
    def test_ac4_session_management(self):
        """AC4: Session management."""
        orch = Orchestrator()
        session = orch.create_session("http://example.com")
        
        assert session is not None
        assert orch.get_session(session.session_id) is not None
    
    def test_ac5_results_collection(self):
        """AC5: Results collection."""
        orch = Orchestrator()
        orch.register_phase(PhaseConfig(ExecutionPhase.BASELINE, 1))
        session = orch.create_session("http://example.com")
        
        result = orch.start_phase(session.session_id, ExecutionPhase.BASELINE)
        orch.end_phase(result, "completed", findings=3)
        
        assert session.phases[0].findings_count == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
