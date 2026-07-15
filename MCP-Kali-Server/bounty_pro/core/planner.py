"""
Autonomous Planner - Intelligent Tool Orchestration Engine
==========================================================
The brain of the pentest engine. Implements:
- Goal decomposition into sub-tasks
- Automatic tool selection based on Knowledge Graph state
- Evidence-driven validation before promoting findings
- Adaptive strategy based on results (refutation-first approach)
- Kill chain tracking with automated progression

Flow:
  Objective -> Decompose -> Plan -> Execute -> Extract -> Graph -> Decide -> Next
"""

import time
import json
import uuid
import asyncio
from typing import Dict, Any, Optional, List, Set, Tuple, Callable
from dataclasses import dataclass, field
from enum import Enum
from collections import defaultdict

from .knowledge_graph import (
    KnowledgeGraph, EntityExtractor, Entity, EntityType,
    RelationType, VulnState, VulnEvidence, EVIDENCE_SCORES
)
from .capability_graph import CapabilityGraph, ToolCapability, ToolCategory


# ============================================================================
# PLANNER DATA TYPES
# ============================================================================

class TaskState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"
    BLOCKED = "blocked"


class ObjectiveType(Enum):
    FULL_PENTEST = "full_pentest"
    FIND_RCE = "find_rce"
    FIND_SQLI = "find_sqli"
    FIND_XSS = "find_xss"
    FIND_IDOR = "find_idor"
    FIND_SSRF = "find_ssrf"
    FIND_AUTH_BYPASS = "find_auth_bypass"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    DATA_EXFILTRATION = "data_exfiltration"
    LATERAL_MOVEMENT = "lateral_movement"
    RECON_ONLY = "recon_only"
    API_AUDIT = "api_audit"
    CLOUD_AUDIT = "cloud_audit"
    AD_AUDIT = "ad_audit"
    MOBILE_AUDIT = "mobile_audit"
    CUSTOM = "custom"


class KillChainPhase(Enum):
    RECONNAISSANCE = "reconnaissance"
    WEAPONIZATION = "weaponization"
    DELIVERY = "delivery"
    EXPLOITATION = "exploitation"
    INSTALLATION = "installation"
    COMMAND_CONTROL = "command_and_control"
    ACTIONS = "actions_on_objectives"


@dataclass
class PlanTask:
    """A single task in the execution plan"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    tool: str = ""
    action: str = ""
    target: str = ""
    parameters: Dict[str, Any] = field(default_factory=dict)
    state: TaskState = TaskState.PENDING
    depends_on: List[str] = field(default_factory=list)
    result: Dict[str, Any] = field(default_factory=dict)
    entities_produced: List[str] = field(default_factory=list)
    started_at: float = 0
    completed_at: float = 0
    error: str = ""
    priority: int = 5
    kill_chain_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE
    
    def to_dict(self) -> Dict:
        return {
            "id": self.id,
            "tool": self.tool,
            "action": self.action,
            "target": self.target,
            "state": self.state.value,
            "priority": self.priority,
            "phase": self.kill_chain_phase.value,
            "error": self.error,
            "entities_produced": len(self.entities_produced),
            "duration": (self.completed_at - self.started_at) if self.completed_at else 0
        }


@dataclass
class ExecutionPlan:
    """A complete execution plan with ordered tasks"""
    id: str = field(default_factory=lambda: str(uuid.uuid4())[:8])
    objective: ObjectiveType = ObjectiveType.FULL_PENTEST
    target: str = ""
    tasks: List[PlanTask] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    current_phase: KillChainPhase = KillChainPhase.RECONNAISSANCE
    completed: bool = False
    adaptations: int = 0  # How many times the plan was adapted
    
    def get_next_tasks(self) -> List[PlanTask]:
        """Get tasks ready to execute (dependencies met)"""
        completed_ids = {t.id for t in self.tasks if t.state == TaskState.COMPLETED}
        ready = []
        for task in self.tasks:
            if task.state == TaskState.PENDING:
                deps_met = all(d in completed_ids for d in task.depends_on)
                if deps_met:
                    ready.append(task)
        return sorted(ready, key=lambda x: x.priority, reverse=True)
    
    def get_progress(self) -> Dict:
        """Get plan execution progress"""
        total = len(self.tasks)
        completed = sum(1 for t in self.tasks if t.state == TaskState.COMPLETED)
        failed = sum(1 for t in self.tasks if t.state == TaskState.FAILED)
        running = sum(1 for t in self.tasks if t.state == TaskState.RUNNING)
        return {
            "total_tasks": total,
            "completed": completed,
            "failed": failed,
            "running": running,
            "pending": total - completed - failed - running,
            "progress_pct": int((completed / total) * 100) if total > 0 else 0,
            "current_phase": self.current_phase.value,
            "adaptations": self.adaptations
        }


# ============================================================================
# OBJECTIVE DECOMPOSITION TEMPLATES
# ============================================================================

OBJECTIVE_TEMPLATES: Dict[ObjectiveType, List[Dict]] = {
    ObjectiveType.FULL_PENTEST: [
        # Phase 1: Reconnaissance
        {"tool": "subfinder", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "nmap", "phase": KillChainPhase.RECONNAISSANCE, "priority": 10},
        {"tool": "httpx", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "katana", "phase": KillChainPhase.RECONNAISSANCE, "priority": 8},
        # Phase 2: Scanning
        {"tool": "nuclei", "phase": KillChainPhase.WEAPONIZATION, "priority": 9},
        {"tool": "ffuf", "phase": KillChainPhase.WEAPONIZATION, "priority": 7},
        # Phase 3: Exploitation (dynamic, based on findings)
    ],
    ObjectiveType.FIND_RCE: [
        {"tool": "nmap", "phase": KillChainPhase.RECONNAISSANCE, "priority": 10},
        {"tool": "nuclei", "phase": KillChainPhase.WEAPONIZATION, "priority": 9, 
         "params": {"templates": "rce,command-injection"}},
        {"tool": "commix", "phase": KillChainPhase.EXPLOITATION, "priority": 9},
        {"tool": "sqlmap", "phase": KillChainPhase.EXPLOITATION, "priority": 8,
         "params": {"os_shell": True}},
    ],
    ObjectiveType.FIND_SQLI: [
        {"tool": "katana", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "ffuf", "phase": KillChainPhase.RECONNAISSANCE, "priority": 8,
         "params": {"type": "parameters"}},
        {"tool": "sqlmap", "phase": KillChainPhase.EXPLOITATION, "priority": 10},
    ],
    ObjectiveType.API_AUDIT: [
        {"tool": "katana", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "graphql_introspection", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "ffuf", "phase": KillChainPhase.WEAPONIZATION, "priority": 8},
        {"tool": "nuclei", "phase": KillChainPhase.WEAPONIZATION, "priority": 8,
         "params": {"templates": "api,graphql,idor"}},
    ],
    ObjectiveType.CLOUD_AUDIT: [
        {"tool": "cloud_enum", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "scout_suite", "phase": KillChainPhase.WEAPONIZATION, "priority": 8},
        {"tool": "pacu", "phase": KillChainPhase.EXPLOITATION, "priority": 8},
    ],
    ObjectiveType.AD_AUDIT: [
        {"tool": "nmap", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9,
         "params": {"ports": "88,135,389,445,636"}},
        {"tool": "bloodhound", "phase": KillChainPhase.RECONNAISSANCE, "priority": 9},
        {"tool": "certipy", "phase": KillChainPhase.EXPLOITATION, "priority": 8},
        {"tool": "netexec", "phase": KillChainPhase.EXPLOITATION, "priority": 8},
    ],
}


# ============================================================================
# AUTONOMOUS PLANNER
# ============================================================================

class AutonomousPlanner:
    """
    Intelligent planner that:
    1. Decomposes objectives into tasks
    2. Selects tools based on discovered entities
    3. Validates findings with refutation-first approach
    4. Adapts strategy based on results
    5. Tracks kill chain progression
    """
    
    def __init__(self, knowledge_graph: KnowledgeGraph, 
                 capability_graph: CapabilityGraph,
                 execute_fn: Callable = None):
        self.kg = knowledge_graph
        self.cg = capability_graph
        self.execute_fn = execute_fn  # async function to execute tools
        self.current_plan: Optional[ExecutionPlan] = None
        self.execution_history: List[Dict] = []
        self.used_tools: Set[str] = set()
        self.max_iterations = 50
        self.max_task_retries = 3
        self.stealth_mode = False
        self.min_stealth_level = 1
    
    def create_plan(self, objective: ObjectiveType, target: str,
                    scope: Dict = None) -> ExecutionPlan:
        """Create an execution plan for an objective"""
        plan = ExecutionPlan(
            objective=objective,
            target=target
        )
        
        # Get template for this objective
        template = OBJECTIVE_TEMPLATES.get(objective, OBJECTIVE_TEMPLATES[ObjectiveType.FULL_PENTEST])
        
        prev_task_id = None
        for step in template:
            task = PlanTask(
                tool=step["tool"],
                action=step.get("action", "scan"),
                target=target,
                parameters=step.get("params", {}),
                priority=step.get("priority", 5),
                kill_chain_phase=step["phase"],
                depends_on=[prev_task_id] if prev_task_id else []
            )
            plan.tasks.append(task)
            prev_task_id = task.id
        
        self.current_plan = plan
        return plan
    
    def adapt_plan(self, new_entities: List[Entity]) -> List[PlanTask]:
        """
        Adapt the current plan based on newly discovered entities.
        This is the key intelligence: choosing what to do next based on findings.
        """
        if not self.current_plan:
            return []
        
        new_tasks = []
        self.current_plan.adaptations += 1
        
        for entity in new_entities:
            # Technology-based adaptation
            if entity.type == EntityType.TECHNOLOGY:
                tech_name = entity.name.lower()
                tools = self.cg.get_tools_for_technology(tech_name)
                for tool_name in tools:
                    if tool_name not in self.used_tools:
                        cap = self.cg.capabilities.get(tool_name)
                        if cap and (not self.stealth_mode or cap.stealth_level >= self.min_stealth_level):
                            task = PlanTask(
                                tool=tool_name,
                                action="scan",
                                target=entity.data.get("url", self.current_plan.target),
                                parameters={"technology": tech_name},
                                priority=cap.priority,
                                kill_chain_phase=self._phase_for_category(cap.category)
                            )
                            new_tasks.append(task)
            
            # Vulnerability-based adaptation (need validation)
            elif entity.type == EntityType.VULNERABILITY:
                validation_tasks = self._create_validation_tasks(entity)
                new_tasks.extend(validation_tasks)
            
            # Credential-based adaptation
            elif entity.type == EntityType.CREDENTIAL:
                # Try to use credentials
                task = PlanTask(
                    tool="browser_login",
                    action="authenticate",
                    target=self.current_plan.target,
                    parameters={"credential": entity.name},
                    priority=8,
                    kill_chain_phase=KillChainPhase.EXPLOITATION
                )
                new_tasks.append(task)
            
            # Endpoint-based adaptation
            elif entity.type == EntityType.ENDPOINT:
                url = entity.name
                # If it's an API endpoint, test it
                if any(x in url.lower() for x in ['/api/', '/graphql', '/v1/', '/v2/']):
                    task = PlanTask(
                        tool="ffuf",
                        action="parameter_fuzz",
                        target=url,
                        parameters={"type": "api_params"},
                        priority=7,
                        kill_chain_phase=KillChainPhase.WEAPONIZATION
                    )
                    new_tasks.append(task)
            
            # JWT found
            elif entity.type == EntityType.JWT:
                task = PlanTask(
                    tool="jwt_tool",
                    action="analyze",
                    target=entity.data.get("full_token", ""),
                    priority=8,
                    kill_chain_phase=KillChainPhase.EXPLOITATION
                )
                new_tasks.append(task)
            
            # S3 Bucket found
            elif entity.type == EntityType.S3_BUCKET:
                task = PlanTask(
                    tool="cloud_enum",
                    action="s3_test",
                    target=entity.name,
                    parameters={"test_write": True, "test_list": True},
                    priority=8,
                    kill_chain_phase=KillChainPhase.EXPLOITATION
                )
                new_tasks.append(task)
        
        # Add new tasks to plan
        for task in new_tasks:
            if not self._task_exists(task.tool, task.target):
                self.current_plan.tasks.append(task)
        
        return new_tasks
    
    def _create_validation_tasks(self, vuln_entity: Entity) -> List[PlanTask]:
        """
        Create validation tasks for a suspected vulnerability.
        Implements the refutation-first approach.
        """
        tasks = []
        vuln_name = vuln_entity.name.lower()
        vuln_data = vuln_entity.data
        target = vuln_data.get("url", self.current_plan.target if self.current_plan else "")
        
        if "sql" in vuln_name:
            # SQLi validation chain
            tasks.append(PlanTask(
                tool="sqlmap",
                action="verify_sqli",
                target=target,
                parameters={
                    "parameter": vuln_data.get("parameter", ""),
                    "technique": "B",  # Boolean first (less noisy)
                    "level": 3,
                    "risk": 2
                },
                priority=9,
                kill_chain_phase=KillChainPhase.EXPLOITATION
            ))
            tasks.append(PlanTask(
                tool="sqlmap",
                action="verify_sqli_time",
                target=target,
                parameters={
                    "parameter": vuln_data.get("parameter", ""),
                    "technique": "T",  # Time-based
                },
                priority=8,
                kill_chain_phase=KillChainPhase.EXPLOITATION
            ))
        
        elif "xss" in vuln_name:
            # XSS validation - need browser verification
            tasks.append(PlanTask(
                tool="browser_exploit",
                action="verify_xss",
                target=target,
                parameters={
                    "payload": vuln_data.get("payload", ""),
                    "context": vuln_data.get("context", "reflected")
                },
                priority=8,
                kill_chain_phase=KillChainPhase.EXPLOITATION
            ))
        
        elif "idor" in vuln_name:
            # IDOR validation - need multi-user verification
            tasks.append(PlanTask(
                tool="browser_exploit",
                action="verify_idor",
                target=target,
                parameters={
                    "test_ids": ["1", "2", "999", str(uuid.uuid4())[:8]],
                    "compare_responses": True
                },
                priority=8,
                kill_chain_phase=KillChainPhase.EXPLOITATION
            ))
        
        elif "ssrf" in vuln_name:
            # SSRF validation
            tasks.append(PlanTask(
                tool="ssrf_verify",
                action="callback_test",
                target=target,
                parameters={
                    "callback_url": "dns_canary",
                    "payloads": ["169.254.169.254", "localhost", "127.0.0.1"]
                },
                priority=9,
                kill_chain_phase=KillChainPhase.EXPLOITATION
            ))
        
        return tasks
    
    def _phase_for_category(self, category: ToolCategory) -> KillChainPhase:
        """Map tool category to kill chain phase"""
        mapping = {
            ToolCategory.RECON: KillChainPhase.RECONNAISSANCE,
            ToolCategory.SCANNING: KillChainPhase.WEAPONIZATION,
            ToolCategory.EXPLOITATION: KillChainPhase.EXPLOITATION,
            ToolCategory.POST_EXPLOIT: KillChainPhase.ACTIONS,
            ToolCategory.ENUMERATION: KillChainPhase.RECONNAISSANCE,
            ToolCategory.BRUTE_FORCE: KillChainPhase.EXPLOITATION,
            ToolCategory.FUZZING: KillChainPhase.WEAPONIZATION,
            ToolCategory.CRAWLING: KillChainPhase.RECONNAISSANCE,
            ToolCategory.BROWSER: KillChainPhase.EXPLOITATION,
            ToolCategory.ANALYSIS: KillChainPhase.RECONNAISSANCE,
        }
        return mapping.get(category, KillChainPhase.RECONNAISSANCE)
    
    def _task_exists(self, tool: str, target: str) -> bool:
        """Check if a similar task already exists in the plan"""
        if not self.current_plan:
            return False
        for task in self.current_plan.tasks:
            if task.tool == tool and task.target == target:
                return True
        return False
    
    async def execute_plan(self, plan: ExecutionPlan = None) -> Dict:
        """
        Execute the plan autonomously.
        Returns a summary of findings.
        """
        plan = plan or self.current_plan
        if not plan:
            return {"error": "No plan to execute"}
        
        if not self.execute_fn:
            return {"error": "No execution function provided"}
        
        iteration = 0
        findings_summary = {
            "confirmed_vulns": [],
            "suspected_vulns": [],
            "entities_discovered": 0,
            "tools_used": [],
            "phases_reached": set(),
            "total_iterations": 0
        }
        
        while iteration < self.max_iterations:
            iteration += 1
            
            # Get next ready tasks
            ready_tasks = plan.get_next_tasks()
            if not ready_tasks:
                # Check if plan is complete or stuck
                pending = [t for t in plan.tasks if t.state == TaskState.PENDING]
                if not pending:
                    break
                # All remaining tasks are blocked
                break
            
            # Execute highest priority task
            task = ready_tasks[0]
            task.state = TaskState.RUNNING
            task.started_at = time.time()
            
            try:
                # Execute the tool
                result = await self.execute_fn(
                    tool=task.tool,
                    action=task.action,
                    target=task.target,
                    parameters=task.parameters
                )
                
                task.state = TaskState.COMPLETED
                task.completed_at = time.time()
                task.result = result
                self.used_tools.add(task.tool)
                findings_summary["tools_used"].append(task.tool)
                findings_summary["phases_reached"].add(task.kill_chain_phase.value)
                
                # Extract entities from result
                raw_output = result.get("output", "") if isinstance(result, dict) else str(result)
                new_entities = self.kg.entity_extractor.extract(task.tool, raw_output)
                task.entities_produced = [e.id for e in new_entities]
                findings_summary["entities_discovered"] += len(new_entities)
                
                # Adapt plan based on new findings
                if new_entities:
                    self.adapt_plan(new_entities)
                
                # Check for vulnerabilities and update states
                for entity in new_entities:
                    if entity.type == EntityType.VULNERABILITY:
                        self.kg.register_vulnerability(entity.id)
                        vuln_data = self.kg.vulnerabilities.get(entity.id, {})
                        if vuln_data.get("state") == VulnState.CONFIRMED:
                            findings_summary["confirmed_vulns"].append(entity.to_dict())
                        else:
                            findings_summary["suspected_vulns"].append(entity.to_dict())
                
            except Exception as e:
                task.state = TaskState.FAILED
                task.error = str(e)
                task.completed_at = time.time()
            
            # Record in history
            self.execution_history.append({
                "iteration": iteration,
                "task": task.to_dict(),
                "timestamp": time.time()
            })
        
        findings_summary["total_iterations"] = iteration
        findings_summary["phases_reached"] = list(findings_summary["phases_reached"])
        plan.completed = True
        
        return findings_summary
    
    def get_status(self) -> Dict:
        """Get current planner status"""
        status = {
            "has_plan": self.current_plan is not None,
            "used_tools": list(self.used_tools),
            "history_length": len(self.execution_history),
            "stealth_mode": self.stealth_mode,
            "graph_stats": {
                "entities": len(self.kg.entities),
                "relations": len(self.kg.relations),
                "vulnerabilities": len(self.kg.vulnerabilities)
            }
        }
        
        if self.current_plan:
            status["plan_progress"] = self.current_plan.get_progress()
        
        return status
    
    def get_recommendations(self) -> List[Dict]:
        """Get AI-driven recommendations based on current state"""
        recommendations = []
        
        # Check for unvalidated vulns
        actionable = self.kg.get_actionable_vulns()
        for vuln in actionable[:5]:
            recommendations.append({
                "type": "validate_vulnerability",
                "vuln": vuln["name"],
                "state": vuln["state"],
                "score": vuln["score"],
                "suggested_tests": vuln["suggested_tests"],
                "priority": "high" if vuln["score"] > 30 else "medium"
            })
        
        # Check for unexplored entities
        for entity_type in [EntityType.ENDPOINT, EntityType.SERVICE, EntityType.TECHNOLOGY]:
            entities = self.kg.get_entities_by_type(entity_type)
            for entity in entities[:10]:
                entity_dict = entity.to_dict()
                suggestions = self.cg.suggest_next_tools(
                    [entity_dict], 
                    self.used_tools,
                    max_suggestions=2
                )
                if suggestions:
                    recommendations.append({
                        "type": "explore_entity",
                        "entity": entity.name,
                        "entity_type": entity_type.value,
                        "tools": suggestions,
                        "priority": "medium"
                    })
        
        return recommendations[:10]


# ============================================================================
# REASONING ENGINE (Verifier + Repair)
# ============================================================================

class ReasoningEngine:
    """
    Implements the Verify -> Repair -> Retry cycle for vulnerability validation.
    Uses a refutation-first approach: tries to DISPROVE findings before confirming.
    """
    
    def __init__(self, knowledge_graph: KnowledgeGraph):
        self.kg = knowledge_graph
        self.verification_log: List[Dict] = []
    
    def should_verify(self, vuln_id: str) -> bool:
        """Determine if a vulnerability needs verification"""
        vuln_data = self.kg.vulnerabilities.get(vuln_id)
        if not vuln_data:
            return True
        
        state = vuln_data["state"]
        if state in [VulnState.CONFIRMED, VulnState.FALSE_POSITIVE]:
            return False
        
        # If recently tested (< 5 min), skip
        if time.time() - vuln_data.get("last_tested", 0) < 300:
            return False
        
        return True
    
    def plan_verification(self, vuln_id: str) -> List[Dict]:
        """
        Plan verification steps for a vulnerability.
        Returns a list of test actions to perform.
        """
        entity = self.kg.entities.get(vuln_id)
        if not entity:
            return []
        
        vuln_data = self.kg.vulnerabilities.get(vuln_id, {})
        existing_evidence = vuln_data.get("evidence", [])
        existing_types = {e.evidence_type for e in existing_evidence}
        
        tests = []
        vuln_name = entity.name.lower()
        
        # Refutation tests - try to disprove first
        tests.append({
            "action": "refute",
            "description": f"Try to disprove {entity.name}",
            "method": "Change non-essential parameters and verify behavior differs",
            "expected": "If NOT vulnerable, behavior should remain same"
        })
        
        # Evidence collection tests
        if "sql" in vuln_name:
            if "sql_boolean_diff" not in existing_types:
                tests.append({
                    "action": "boolean_test",
                    "description": "Boolean-based blind verification",
                    "payloads": ["' AND 1=1--", "' AND 1=2--"],
                    "expected": "Different response lengths/content"
                })
            if "sql_time_diff" not in existing_types:
                tests.append({
                    "action": "time_test",
                    "description": "Time-based blind verification",
                    "payloads": ["' AND SLEEP(5)--", "'; WAITFOR DELAY '0:0:5'--"],
                    "expected": "Response delay > 5 seconds"
                })
            if "sql_data_extracted" not in existing_types:
                tests.append({
                    "action": "extraction_test",
                    "description": "Data extraction verification",
                    "method": "UNION SELECT or error-based to extract version()",
                    "expected": "Database version string in response"
                })
        
        elif "xss" in vuln_name:
            if "xss_dom_executed" not in existing_types:
                tests.append({
                    "action": "browser_verify",
                    "description": "Verify XSS executes in real browser",
                    "method": "Use Playwright to load page with payload",
                    "expected": "JavaScript alert/console output"
                })
        
        elif "idor" in vuln_name:
            if "idor_other_user_data" not in existing_types:
                tests.append({
                    "action": "multi_user_test",
                    "description": "Access other user's resources",
                    "method": "Authenticate as User A, access User B's resources",
                    "expected": "Successful access to unauthorized data"
                })
        
        return tests
    
    def evaluate_evidence(self, vuln_id: str, test_result: Dict) -> Dict:
        """
        Evaluate a test result and create appropriate evidence.
        Returns the new vulnerability state.
        """
        success = test_result.get("success", False)
        evidence_type = test_result.get("evidence_type", "generic")
        description = test_result.get("description", "")
        
        # Calculate points
        if success:
            points = EVIDENCE_SCORES.get(evidence_type, 10)
        else:
            points = EVIDENCE_SCORES.get("not_reproducible", -20) if not success else 0
        
        evidence = VulnEvidence(
            vuln_id=vuln_id,
            evidence_type=evidence_type,
            description=description,
            data=test_result,
            points=points,
            tool_used=test_result.get("tool", "manual"),
            reproducible=test_result.get("reproducible", False)
        )
        
        result = self.kg.add_evidence(vuln_id, evidence)
        
        self.verification_log.append({
            "vuln_id": vuln_id,
            "evidence": evidence_type,
            "points": points,
            "new_state": result["new_state"],
            "timestamp": time.time()
        })
        
        return result
