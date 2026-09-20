# Requirements Document: Kali MCP V2 Orchestration

## Introduction

### Purpose

This document specifies the formal requirements for Kali MCP V2, which transforms the current Kali MCP V1 from an uncoordinated collection of security scanning tools into an orchestrated, evidence-driven autonomous pentest engine. V2 adds six interdependent layers (Tool Registry, Capability Engine, Orchestrator, Baseline Engine, Evidence Graph, and Standardized Output Schema) that work together to eliminate arbitrary tool multiplication, enforce semantic evidence validation, enable dependency-aware test sequencing, and respect the Evidence Policy maturity model.

### Key Constraints from Design

1. **Evidence Policy Preservation**: All V1 Evidence Policy rules remain intact (OBSERVED → SUSPECTED → CONFIRMED → EXPLOITED maturity levels)
2. **No Status Promotion Without Proof**: Finding status cannot exceed the number of proof nodes in its Evidence Graph
3. **Baseline Mandatory**: Semantic baselines must be established before ANY payload-based testing
4. **Semantic Comparison, Not Size**: All response comparisons use Jaccard similarity (token-based), not byte count differences
5. **Negative Evidence First-Class**: Every tool execution produces explicit negative_evidence quantifying what was tested but found nothing
6. **Unified Output Schema**: All tools (existing and new) must return the standardized JSON structure

---

## Glossary

### Core Concepts

- **Tool**: A security scanner or exploitation utility (nmap, nuclei, sqlmap, hydra, etc.) registered in the Tool Registry with capabilities, parameters, and health status
- **Capability**: A specific security testing ability a tool provides (e.g., SQLi detection, password cracking, SSRF probing). Identified by type (RECON, SCAN, EXPLOIT, etc.), target technology stack, vulnerability types, and max evidence level achievable
- **Relevance Score**: A float (0.0–1.0) computed by Capability Engine based on tech stack match (0.3) + objective match (0.4) + evidence level match (0.3)
- **ExecutionPhase**: A logical group of tools that execute together (sequentially or in parallel) with explicit dependencies on prior phases. Examples: RECON_01, BASELINE_EST_01, SCAN_DEEP_02
- **ExecutionPlan**: A complete, dependency-aware sequence of ExecutionPhases, validated to form a DAG (directed acyclic graph)
- **Baseline**: A "normal" response from the target used as a reference point. Examples: homepage, 404 error, invalid parameter response. Stored with semantic signatures (DOM hash, text hash, semantic tokens)
- **Semantic Comparison**: Comparison of two responses using Jaccard similarity (0.0–1.0) on extracted tokens, with 0.75 threshold for semantic equivalence
- **Evidence Graph**: A directed acyclic graph of hypothesis nodes, signal nodes (observations), and proof nodes (direct evidence) connected by weighted edges, enabling full traceability of finding justifications
- **Finding**: A single security issue detected, containing finding_type, status (OBSERVED/SUSPECTED/CONFIRMED/EXPLOITED), confidence, evidence, affected_endpoints, proof_of_concept, and remediation
- **Proof Node**: Direct evidence of a hypothesis (e.g., unescaped XSS payload executed, SQL error with query in response, AWS metadata retrieved)
- **Signal Node**: An observable indicator that may suggest a hypothesis but is not conclusive (e.g., response time spike, unusual error message)
- **FindingStatus Enum** (from V1 Evidence Policy):
  - **NOT_TESTED**: No test performed
  - **TESTED**: Test ran, found nothing
  - **OBSERVED**: Signal detected, needs validation
  - **SUSPECTED**: Consistent with vulnerability pattern
  - **CONFIRMED**: Direct evidence present in tool output
  - **EXPLOITED**: Successful exploitation demonstrated
- **HealthStatus Enum**: HEALTHY (functioning normally) | DEGRADED (works with issues) | OFFLINE (unavailable)
- **Negative Evidence**: Explicit quantification of what was tested but found no vulnerabilities (tests_performed, tests_with_no_findings, coverage_percentage, blocked_tests)
- **Execution Ledger**: Chronological log of all actions taken (tool_started, payload_sent, finding_discovered) with timestamps and related finding IDs, enabling full audit trail
- **Proof of Concept (PoC)**: Concrete request-response pair demonstrating a finding; includes URL, method, request headers/body, response status/body, and proof_markers (specific strings in response confirming vulnerability)

### Systems and Components

- **Tool_Registry**: Centralized catalog of all registered tools with capabilities, health status, and parameters
- **Capability_Engine**: Maps target characteristics (tech stack, objective) to applicable tools; ranks by relevance
- **Orchestrator**: Generates and executes dependency-aware ExecutionPlans; respects Evidence Policy
- **Baseline_Engine**: Establishes semantic baselines and compares responses using Jaccard similarity
- **Evidence_Graph**: Tracks hypothesis/signal/proof relationships; justifies finding status with explicit proofs
- **Standardized_Output**: Unified JSON schema returned by all tools (wraps existing tool output)

---

## Requirements

### Category 1: Tool Registry

#### Requirement REQ-TR-01: Tool Registration and Unique Identification

**User Story**: As an orchestrator, I want to register security tools with unique identifiers so that I can reference and query them reliably.

**Acceptance Criteria**:

1. WHEN a Tool is registered, THE Tool_Registry SHALL store it with a globally unique UUID
2. WHEN a duplicate tool ID is registered, THE Tool_Registry SHALL reject it and return an error
3. THE Tool_Registry SHALL store for each Tool: id, name, category, capabilities, required_params, optional_params, timeout_seconds, health_status, version
4. THE Tool_Registry SHALL support storage of at least 50 concurrent tools without performance degradation
5. THE Tool_Registry SHALL provide a query method that returns a Tool by its UUID in constant time

**Acceptance Tests**:

- Test 1: Register nuclei with UUID "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx", verify stored with same UUID, retrieve by UUID returns nuclei
- Test 2: Attempt to register second tool with same UUID, verify error returned
- Test 3: Register 50 distinct tools (nmap, nuclei, hydra, sqlmap, ssrf_hunter, etc.), verify all retrievable
- Test 4: Query registry.get_tool_by_id() 1000 times, verify < 1ms per query (constant time)

**Priority**: CRITICAL

**Dependencies**: None (foundational layer)

---

#### Requirement REQ-TR-02: Tool Capabilities Definition and Storage

**User Story**: As a Capability Engine, I want to query what each tool can do so that I can match tools to objectives.

**Acceptance Criteria**:

1. WHEN a Tool is registered, THE Tool_Registry SHALL store at least one Capability per Tool
2. EACH Capability SHALL define: type (RECON, SCAN, EXPLOIT, CRACK, POST_EXPLOIT), technology_stack (list of target languages), vulnerability_types (list), max_evidence_level (FindingStatus)
3. EACH Capability SHALL define: estimated_duration_seconds, estimated_requests, requires_capabilities (list of dependency UUIDs)
4. THE Tool_Registry SHALL allow querying Tools by Capability type (e.g., all RECON tools)
5. THE Tool_Registry SHALL allow querying Tools by technology_stack (e.g., all tools targeting Java, Node.js)

**Acceptance Tests**:

- Test 1: Register nuclei with capabilities [SCAN, RECON], verify both retrievable via get_tools_by_capability_type()
- Test 2: Register nmap targeting network recon, query_tools_by_tech_stack("network"), verify nmap returned
- Test 3: Register hydra with max_evidence_level = CONFIRMED, query_tools_with_evidence_level_at_least(CONFIRMED), verify hydra included
- Test 4: Query all tools targeting Java/Node.js, verify correct subset returned

**Priority**: CRITICAL

**Dependencies**: REQ-TR-01

---

#### Requirement REQ-TR-03: Tool Health Status Tracking

**User Story**: As an orchestrator, I want to know which tools are healthy before scheduling them so that I don't execute offline tools.

**Acceptance Criteria**:

1. WHEN a Tool is registered, THE Tool_Registry SHALL schedule an initial health check
2. WHEN health_check() is called, THE Tool_Registry SHALL verify tool binary exists and run a diagnostic command
3. IF diagnostic command exits with code 0, THE Tool health_status SHALL be set to HEALTHY
4. IF diagnostic command exits with non-zero code, THE Tool health_status SHALL be set to DEGRADED or OFFLINE
5. THE Tool failure_count SHALL increment on each failed health check; reset to 0 on success
6. WHEN a Tool has health_status = OFFLINE, THEN the Orchestrator SHALL NOT execute it (skip in phases)

**Acceptance Tests**:

- Test 1: Register nmap (installed), run health_check(), verify status = HEALTHY
- Test 2: Register fake-tool-xyz (not installed), run health_check(), verify status = OFFLINE
- Test 3: Register tool with failing diagnostic, run health_check(), verify failure_count incremented
- Test 4: After OFFLINE tool detected, execute a phase containing it, verify tool skipped, other tools in phase run

**Priority**: HIGH

**Dependencies**: REQ-TR-01, REQ-TR-02

---

#### Requirement REQ-TR-04: Tool Parameters and Constraints

**User Story**: As an orchestrator, I want to know what parameters each tool accepts so that I can invoke it correctly.

**Acceptance Criteria**:

1. EACH Tool SHALL define required_params (must be provided) and optional_params (can be omitted)
2. EACH Parameter SHALL have: name, type (STRING, INTEGER, BOOLEAN, ENUM, FILE_PATH), description, default_value, valid_values (for ENUM)
3. EACH Tool SHALL define: timeout_seconds (max execution time), rate_limit_delay_ms, max_concurrent_instances
4. THE Tool_Registry SHALL validate parameters before tool invocation (type checking, enum validation, regex matching for strings)
5. IF a required parameter is missing, THE Orchestrator SHALL return an error and NOT execute the tool

**Acceptance Tests**:

- Test 1: Define nuclei with required_params=[target_url], optional_params=[depth, timeout], register successfully
- Test 2: Attempt to execute nuclei without target_url, verify error "Required parameter missing: target_url"
- Test 3: Define hydra with depth ENUM=[stealth, light, deep, aggressive], attempt depth="invalid", verify validation error
- Test 4: Define parameter with timeout_seconds=300, execute tool, verify killed if exceeds 300s

**Priority**: HIGH

**Dependencies**: REQ-TR-01, REQ-TR-02

---

### Category 2: Capability Engine

#### Requirement REQ-CE-01: Target Technology Stack Detection

**User Story**: As a Capability Engine, I want to detect the target's technology stack so that I can select relevant tools.

**Acceptance Criteria**:

1. WHEN Capability_Engine.plan_scan() is called, IT SHALL run a target-type detection phase
2. THE detection SHALL identify: target_type (WEB_APP, API, NETWORK, CLOUD, CONTAINER, SAAS, HARDWARE)
3. IF target_type = WEB_APP, THE detection SHALL identify programming languages (Java, Node.js, Python, PHP, ASP.NET, Go, Rust)
4. IF target_type = WEB_APP, THE detection SHALL identify frameworks (Spring, Express, Django, Laravel, etc.)
5. THE detected_tech_stack SHALL be passed to Capability_Engine.get_applicable_tools() for relevance scoring

**Acceptance Tests**:

- Test 1: Target URL "http://example.com" detects HTML, HTTP headers, identify as WEB_APP
- Test 2: Target URL returns "X-Powered-By: Express" header, identify Node.js in tech_stack
- Test 3: Target returns Python stack traces, identify Python in tech_stack
- Test 4: Detected tech_stack (Java, Spring) passed to get_applicable_tools(), verify Java-targeting tools ranked higher

**Priority**: HIGH

**Dependencies**: REQ-TR-01, REQ-TR-02

---

#### Requirement REQ-CE-02: Tool Relevance Scoring

**User Story**: As an orchestrator, I want tools ranked by relevance so that I execute the most applicable ones first.

**Acceptance Criteria**:

1. WHEN Capability_Engine.get_applicable_tools() is called with CapabilityQuery, IT SHALL compute relevance_score for each matching tool
2. relevance_score = (tech_stack_match * 0.3) + (objective_match * 0.4) + (evidence_level_match * 0.3)
3. tech_stack_match = count(detected_techs intersecting tool_techs) / count(detected_techs)
4. objective_match = 1.0 if capability.type matches query.objective, else 0.0
5. evidence_level_match = 1.0 if capability.max_evidence_level >= query.preferred_evidence_level, else 0.0
6. ONLY tools with relevance_score > 0.2 SHALL be returned
7. Results SHALL be sorted by relevance_score descending

**Acceptance Tests**:

- Test 1: Query for SQLi detection on PHP target, sqlmap (targets PHP, SCAN type, max_level=CONFIRMED) scores > 0.2, nuclei (generic, SCAN type) scores lower; verify sqlmap ranked first
- Test 2: Query with preferred_evidence_level=EXPLOITED, return only tools with max_evidence_level >= EXPLOITED
- Test 3: Query with 3 detected techs (Java, Spring, Tomcat), tool targeting (Java, Spring) scores 2/3 tech match; tool targeting (Python, Django) scores 0; verify correct scoring
- Test 4: Query NETWORK_RECON on WEB_APP target, verify only RECON-capable tools returned (no EXPLOIT tools)

**Priority**: CRITICAL

**Dependencies**: REQ-TR-01, REQ-TR-02, REQ-TR-04, REQ-CE-01

---

#### Requirement REQ-CE-03: Capability Dependency Resolution

**User Story**: As an orchestrator, I want to resolve tool dependencies so that I run prerequisite tools before dependent ones.

**Acceptance Criteria**:

1. WHEN a Capability requires other capabilities (requires_capabilities list), THE Capability_Engine SHALL resolve transitive dependencies
2. THE resolution SHALL form a valid DAG (no circular dependencies)
3. IF a circular dependency is detected, THE Capability_Engine SHALL return an error with the cycle path
4. EACH dependency SHALL be mapped to a Tool that provides it
5. The dependency chain SHALL be returned in topological order (prerequisites first)

**Acceptance Tests**:

- Test 1: Tool A requires Capability X (provided by Tool B), Tool B has no requirements; resolve dependencies, verify order [B, A]
- Test 2: Tool A requires X, Tool B requires Y from A, Tool C provides X; detect no cycle, verify valid DAG
- Test 3: Tool A requires B's output, Tool B requires A's output; detect cycle, return error "Circular dependency detected: A → B → A"
- Test 4: Deep chain: A requires B requires C requires D; resolve, verify order [D, C, B, A]

**Priority**: HIGH

**Dependencies**: REQ-TR-02

---

#### Requirement REQ-CE-04: Health Status Filtering

**User Story**: As an orchestrator, I want to filter out unhealthy tools so that I don't schedule offline tools.

**Acceptance Criteria**:

1. WHEN Capability_Engine.get_applicable_tools() is called, IT SHALL exclude all tools with health_status = OFFLINE
2. WHEN a tool has health_status = DEGRADED, IT SHALL be included but logged as low-priority
3. WHEN a tool has health_status = HEALTHY, IT SHALL be included and prioritized
4. THE Tool_Registry SHALL be consulted for health_status before returning results

**Acceptance Tests**:

- Test 1: 3 applicable tools: nuclei (HEALTHY), hydra (DEGRADED), nmap (OFFLINE); get_applicable_tools() returns [nuclei, hydra], not nmap
- Test 2: All applicable tools are OFFLINE, get_applicable_tools() returns empty list
- Test 3: nuclei transitions from HEALTHY to OFFLINE mid-scan; verification phase skips nuclei

**Priority**: HIGH

**Dependencies**: REQ-TR-03, REQ-CE-02

---

### Category 3: Orchestrator

#### Requirement REQ-ORCH-01: Execution Plan Generation

**User Story**: As an orchestrator, I want to generate ordered execution plans so that tests run in the correct sequence (RECON → BASELINE → SCAN → EXPLOIT).

**Acceptance Criteria**:

1. WHEN Orchestrator.plan_scan(target, depth, objective) is called, IT SHALL create an ExecutionPlan with ordered ExecutionPhases
2. THE ExecutionPlan SHALL contain Phase 0: DETECT_TARGET_TYPE
3. THE ExecutionPlan SHALL contain Phase 1: RECON (when depth >= LIGHT)
4. THE ExecutionPlan SHALL contain Phase 2: BASELINE_ESTABLISHMENT (critical, before all payload testing)
5. THE ExecutionPlan SHALL contain Phase 3+: FINGERPRINTING, SHALLOW_SCAN, DEEP_SCAN, EXPLOIT_VERIFICATION (based on depth and objective)
6. THE ExecutionPlan SHALL be validated to form a valid DAG
7. THE ExecutionPlan SHALL store: target, target_type, depth, phases, total_estimated_duration, total_estimated_requests

**Acceptance Tests**:

- Test 1: plan_scan("http://example.com", "deep", VULNERABILITY_ASSESSMENT), verify phases [DETECT, RECON, BASELINE, FINGERPRINT, DEEP_SCAN] present in order
- Test 2: plan_scan(..., "stealth", RECON), verify only [DETECT, RECON, BASELINE] (no scanning)
- Test 3: plan_scan(..., "aggressive", EXPLOIT_VERIFICATION), verify [DETECT, RECON, BASELINE, FINGERPRINT, DEEP_SCAN, EXPLOIT_VERIFY] present
- Test 4: Generate plan, call topological_sort(), verify no cycles and correct ordering

**Priority**: CRITICAL

**Dependencies**: REQ-TR-01, REQ-CE-01, REQ-CE-02, REQ-CE-03

---

#### Requirement REQ-ORCH-02: Baseline Phase Precedence

**User Story**: As an orchestrator, I want baseline establishment to occur before payload testing so that I have reference responses to compare against.

**Acceptance Criteria**:

1. WHEN an ExecutionPlan is created, THE BASELINE_ESTABLISHMENT phase SHALL have sequence_index earlier than all payload-based phases (SHALLOW_SCAN, DEEP_SCAN, EXPLOIT_VERIFICATION)
2. WHEN validating the ExecutionPlan, THE Orchestrator SHALL verify: index(baseline_phase) < index(first_payload_phase)
3. IF this constraint is violated, THE plan_scan() SHALL return an error "Baseline phase must precede payload testing"
4. ALL payload-phase dependencies SHALL list baseline_phase in depends_on_phases

**Acceptance Tests**:

- Test 1: Generate plan for DEEP_SCAN objective; baseline phase has sequence_index=2, scan phase has sequence_index > 2; verify constraint satisfied
- Test 2: Manually construct invalid plan with scan_phase before baseline_phase; call validate_plan(), verify error
- Test 3: Execute plan; baseline phase runs first, produces 3 baselines; subsequent phases receive baseline_output in inputs_from_phases

**Priority**: CRITICAL

**Dependencies**: REQ-ORCH-01, REQ-BE-01

---

#### Requirement REQ-ORCH-03: Phase Dependencies and DAG Validation

**User Story**: As an orchestrator, I want to ensure phases execute in dependency order so that test results are valid.

**Acceptance Criteria**:

1. EACH ExecutionPhase SHALL define depends_on_phases: list of phase IDs that must complete first
2. THE Orchestrator SHALL build a directed graph of phase dependencies
3. WHEN executing the plan, THE Orchestrator SHALL perform topological sort to determine execution order
4. IF a circular dependency is detected during topological sort, THE execute_plan() SHALL return an error with cycle details
5. THE Orchestrator SHALL NOT execute a phase until all its dependencies are satisfied
6. IF a dependent phase's input is empty (predecessor didn't produce expected output), THE Orchestrator SHALL log a warning and skip the dependent phase

**Acceptance Tests**:

- Test 1: 3 phases: RECON → BASELINE (depends_on [RECON]) → SCAN (depends_on [BASELINE]); execute, verify order: RECON, BASELINE, SCAN
- Test 2: Manually construct plan with SCAN depends_on [RECON, FINGERPRINT], FINGERPRINT depends_on [SCAN]; call execute_plan(), verify cycle detection error
- Test 3: BASELINE phase depends_on [RECON], RECON produces no output; execute, BASELINE logs warning "Input from RECON is empty", skips BASELINE
- Test 4: Large plan (8 phases, 20 dependencies); topological sort completes in < 10ms

**Priority**: CRITICAL

**Dependencies**: REQ-ORCH-01

---

#### Requirement REQ-ORCH-04: Parallel and Sequential Phase Execution

**User Story**: As an orchestrator, I want to control whether tools within a phase run in parallel so that I respect tool constraints and rate limits.

**Acceptance Criteria**:

1. EACH ExecutionPhase SHALL define parallel: Boolean (true = concurrent, false = sequential)
2. IF parallel = true, THEN tools in the phase SHALL execute concurrently with max_concurrent_instances limit per tool
3. IF parallel = false, THEN tools execute one-at-a-time in order
4. THE phase max_concurrent_instances limit SHALL be respected (e.g., max 3 simultaneous Nuclei instances)
5. IF a tool completes faster, THE Orchestrator SHALL immediately start the next tool (no idle waiting)

**Acceptance Tests**:

- Test 1: RECON phase with parallel=true, 4 tools, max_concurrent=2; verify max 2 tools run simultaneously, 4 complete eventually
- Test 2: BASELINE phase with parallel=false, 3 requests; verify sequential execution, 2nd request starts only after 1st response received
- Test 3: Phase with 5 tools, max_concurrent=8 (unlimited); verify all 5 start immediately
- Test 4: Mid-phase tool failure in parallel phase; verify other tools continue (unless stop_on_failure=true)

**Priority**: HIGH

**Dependencies**: REQ-ORCH-01, REQ-ORCH-03

---

#### Requirement REQ-ORCH-05: Tool Execution and Error Handling

**User Story**: As an orchestrator, I want to handle tool failures gracefully so that one tool's crash doesn't stop the entire scan.

**Acceptance Criteria**:

1. WHEN a tool execution times out (exceeds timeout_seconds), THE tool execution SHALL be terminated
2. WHEN a tool execution fails (non-zero exit code), THE phase execution SHALL check stop_on_failure flag
3. IF stop_on_failure = true, THE phase execution SHALL halt and subsequent phases skipped
4. IF stop_on_failure = false, THE phase execution SHALL log the error and continue with next tool
5. THE execution result SHALL include error_message and exit_code for failed tools
6. THE execution result SHALL include negative_evidence for failed tools (tests that were planned but not run)

**Acceptance Tests**:

- Test 1: Tool times out after 120s when timeout_seconds=120; execution halted, logged as TIMEOUT
- Test 2: Nuclei fails with exit code 1; SCAN phase has stop_on_failure=false; EXPLOIT phase proceeds with available findings
- Test 3: BASELINE phase fails (stop_on_failure=true); execute_plan() returns early, SCAN phases not executed
- Test 4: Tool execution fails; negative_evidence shows planned_tests minus completed_tests

**Priority**: HIGH

**Dependencies**: REQ-ORCH-01, REQ-ORCH-04

---

#### Requirement REQ-ORCH-06: Orchestrator Health Check Before Execution

**User Story**: As an orchestrator, I want to verify tools are healthy before scheduling them so that I don't queue offline tools.

**Acceptance Criteria**:

1. WHEN Orchestrator.execute_plan() is called, THE first step SHALL verify health_status of all tools to be executed
2. FOR each tool in plan.phases[*].tools_to_execute, THE Orchestrator SHALL check tool_registry[tool.id].health_status
3. IF any tool has health_status = OFFLINE, THE tool SHALL be skipped (not queued)
4. IF any tool has health_status = DEGRADED, THE tool SHALL be executed but logged as low-priority
5. IF all tools in a phase are OFFLINE, THE phase SHALL be marked SKIPPED with reason "All tools offline"

**Acceptance Tests**:

- Test 1: Execute plan with nuclei (HEALTHY) and nmap (OFFLINE); nuclei executes, nmap skipped
- Test 2: All 3 tools in SCAN phase are OFFLINE; phase marked SKIPPED
- Test 3: RECON phase has 2 DEGRADED tools; both execute with warnings logged

**Priority**: HIGH

**Dependencies**: REQ-TR-03, REQ-ORCH-01, REQ-ORCH-05

---

### Category 4: Baseline Engine

#### Requirement REQ-BE-01: Baseline Establishment

**User Story**: As a baseline engine, I want to establish normal response patterns so that I can detect anomalies during payload testing.

**Acceptance Criteria**:

1. WHEN Orchestrator enters BASELINE_ESTABLISHMENT phase, THE Baseline_Engine SHALL establish exactly 3 baselines: HOMEPAGE, NOT_FOUND_404, INVALID_PARAM
2. BASELINE HOMEPAGE: GET / (root path), store response_body, response_status_code, response_headers
3. BASELINE NOT_FOUND_404: GET /{random_uuid} (nonexistent path), store response (expect 404)
4. BASELINE INVALID_PARAM: GET {target}?{random_param}={random_value}, store response
5. FOR each baseline, THE Baseline_Engine SHALL compute: response_size_bytes, dom_hash (if HTML), text_hash, semantic_tokens
6. THE Baseline_Engine SHALL measure response_time_ms for each request
7. IF any baseline request times out (> 10 seconds), THE baseline establishment SHALL FAIL and return error
8. THE BaselineSet returned SHALL include: baselines dict, target, established_timestamp, average_response_time_ms

**Acceptance Tests**:

- Test 1: Establish baselines for http://example.com; verify 3 baselines with different responses stored
- Test 2: Baseline HOMEPAGE returns status 200, 12KB HTML; stored with size_bytes=12288, dom_hash computed, tokens extracted
- Test 3: Baseline NOT_FOUND_404 returns status 404, 2KB error page; NOT_FOUND_404 baseline stored with 404 status
- Test 4: Request times out; baseline establishment fails, ExecutionPlan aborted
- Test 5: Average response time across 3 requests computed and stored

**Priority**: CRITICAL

**Dependencies**: REQ-ORCH-01, REQ-ORCH-02

---

#### Requirement REQ-BE-02: Semantic Token Extraction and Hashing

**User Story**: As a baseline engine, I want to extract semantic signatures so that I can compare responses beyond size.

**Acceptance Criteria**:

1. WHEN a baseline response is received, THE Baseline_Engine SHALL extract semantic_tokens: unique words, identifiers, numbers, special patterns from response_body
2. THE Baseline_Engine SHALL compute dom_hash (if HTML): SHA256 hash of parsed DOM tree structure (ignoring whitespace, comments)
3. THE Baseline_Engine SHALL compute text_hash (if HTML): SHA256 hash of all extracted text content
4. THE semantic_tokens SHALL be stored as a Set (unique strings)
5. FOR HTML responses, BOTH dom_hash and text_hash SHALL be computed; FOR non-HTML (JSON, plain text), only text_hash

**Acceptance Tests**:

- Test 1: HTML response "<div>Hello World</div>"; semantic_tokens includes ["Hello", "World"]; dom_hash computed
- Test 2: Two HTML responses with same content but different whitespace/formatting; dom_hash identical, text_hash identical
- Test 3: JSON response {"id": 123, "name": "Alice"}; semantic_tokens includes ["id", "123", "name", "Alice"]
- Test 4: Extract tokens from 10MB response in < 100ms

**Priority**: HIGH

**Dependencies**: REQ-BE-01

---

#### Requirement REQ-BE-03: Jaccard Similarity Computation

**User Story**: As a baseline engine, I want to measure semantic similarity using token-based metrics so that I don't confuse size differences with semantic changes.

**Acceptance Criteria**:

1. WHEN comparing a test_response against a baseline_response, THE Baseline_Engine SHALL compute Jaccard similarity
2. jaccard_similarity = |intersection(test_tokens, baseline_tokens)| / |union(test_tokens, baseline_tokens)|
3. jaccard_similarity range: [0.0, 1.0] where 1.0 = identical, 0.0 = no overlap
4. THE comparison SHALL also compute: size_ratio = min(test_size, baseline_size) / max(test_size, baseline_size)
5. combined_score = (jaccard_similarity * 0.6) + (size_ratio * 0.4)
6. THE comparison SHALL be implemented efficiently for responses up to 10MB

**Acceptance Tests**:

- Test 1: test_response = baseline_response; jaccard = 1.0, size_ratio = 1.0, combined = 1.0
- Test 2: test_response has 100 tokens, baseline has 100 tokens, 80 overlap; jaccard = 80/120 = 0.667
- Test 3: test_response 500 bytes, baseline 1000 bytes, 90 tokens overlap of 100 total; jaccard = 0.9, size_ratio = 0.5, combined = 0.74
- Test 4: Compare 10MB responses; computation completes in < 50ms

**Priority**: CRITICAL

**Dependencies**: REQ-BE-02

---

#### Requirement REQ-BE-04: Semantic Comparison Threshold and Classification

**User Story**: As a baseline engine, I want to classify responses as "semantically equivalent" or "different" so that I can filter false positives.

**Acceptance Criteria**:

1. WHEN a test response is compared to a baseline, IF combined_score >= 0.75, THEN is_semantic_match = true
2. IF combined_score < 0.75, THEN is_semantic_match = false (response is genuinely different)
3. THE threshold (0.75) SHALL be configurable globally but default to 0.75
4. THE comparison result SHALL include: similarity_score, jaccard_similarity, is_semantic_match, semantic_difference (description)
5. IF is_semantic_match = false, THE semantic_difference SHALL describe what changed (e.g., "120 new tokens added, 45 removed")

**Acceptance Tests**:

- Test 1: combined_score = 0.80; is_semantic_match = true
- Test 2: combined_score = 0.70; is_semantic_match = false
- Test 3: combined_score = 0.75 (boundary); is_semantic_match = true (>= threshold)
- Test 4: Response with major content change scores 0.40; is_semantic_match = false; semantic_difference explains specific token changes

**Priority**: CRITICAL

**Dependencies**: REQ-BE-03

---

#### Requirement REQ-BE-05: Baseline Reflexivity

**User Story**: As a baseline engine, I want to guarantee that a response compared against itself yields perfect similarity so that I can validate the comparison algorithm.

**Acceptance Criteria**:

1. WHEN a response R is compared against baseline B where R = B, THEN similarity_score SHALL be exactly 1.0
2. WHEN a response R is compared against baseline B where R = B, THEN is_semantic_match SHALL be true
3. This property SHALL hold for all response sizes (0 bytes to 10 MB)
4. This property SHALL hold for all response types (HTML, JSON, plain text, binary)

**Acceptance Tests**:

- Test 1: response = baseline = "<html>...</html>"; compare_semantic() returns similarity=1.0
- Test 2: response = baseline = {"key": "value"}; compare_semantic() returns similarity=1.0
- Test 3: For 50 random responses of sizes 100B to 5MB, each compared to itself, all return similarity=1.0

**Priority**: HIGH

**Dependencies**: REQ-BE-03, REQ-BE-04

---

### Category 5: Evidence Graph

#### Requirement REQ-EG-01: Hypothesis Node Creation

**User Story**: As an evidence graph, I want to track the main claim so that I can justify findings with proof chains.

**Acceptance Criteria**:

1. WHEN EvidenceGraph.build() is called with a StandardFinding, THE root_hypothesis node SHALL be created with: hypothesis (main claim), hypothesis_class (finding_type), node_id (UUID), created_timestamp
2. THE root_hypothesis.hypothesis SHALL be "{finding_type} vulnerability present" (e.g., "SSRF vulnerability present")
3. THE root_hypothesis.node_type SHALL be HYPOTHESIS
4. THE root_hypothesis.parent_hypotheses SHALL be empty (root has no parents)
5. THE root_hypothesis.supporting_signals SHALL be populated as signal nodes are added

**Acceptance Tests**:

- Test 1: Create graph for finding_type="SSRF"; root_hypothesis.hypothesis = "SSRF vulnerability present"
- Test 2: root_hypothesis.node_id is unique UUID; retrieve node by ID returns it
- Test 3: root_hypothesis.node_type = HYPOTHESIS; verify enum value

**Priority**: HIGH

**Dependencies**: REQ-TR-01

---

#### Requirement REQ-EG-02: Signal Node Creation and Weighting

**User Story**: As an evidence graph, I want to track observable signals so that I can see what indicators led to a finding.

**Acceptance Criteria**:

1. WHEN a signal is added to the Evidence Graph, A signal_node SHALL be created with: signal_type, signal_source (tool name), signal_value (actual observation), signal_confidence (0.0–1.0)
2. THE signal_node.node_type SHALL be SIGNAL
3. AN edge SHALL be created from signal_node to root_hypothesis with relationship_type="supports" and weight=signal.confidence
4. THE signal_node SHALL be added to graph.unconfirmed_signals initially
5. IF a proof node is later added that correlates with the signal, THE signal SHALL be moved from unconfirmed_signals to confirmed

**Acceptance Tests**:

- Test 1: Add signal with type="response_size_anomaly", source="nuclei", value=500, confidence=0.4; verify signal_node created with these attributes
- Test 2: Signal with confidence=0.7; edge weight = 0.7
- Test 3: Add signal to graph; verify added to unconfirmed_signals; add correlating proof; verify signal removed from unconfirmed
- Test 4: 10 signals added with varying confidence; all edges have correct weights

**Priority**: HIGH

**Dependencies**: REQ-EG-01

---

#### Requirement REQ-EG-03: Proof Node Creation and Direct Evidence

**User Story**: As an evidence graph, I want to track direct evidence so that I can promote findings from OBSERVED to CONFIRMED.

**Acceptance Criteria**:

1. WHEN a proof item is present in StandardFinding.evidence, A proof_node SHALL be created with: proof_type (key from evidence dict), proof_data (value), proof_timestamp, node_type=PROOF
2. AN edge SHALL be created from proof_node to root_hypothesis with relationship_type="proves" and weight=1.0 (proof is highest confidence)
3. THE proof_node SHALL be added to graph.confirmed_proofs
4. IF multiple proofs exist for same finding, EACH proof creates its own proof_node with separate edges

**Acceptance Tests**:

- Test 1: Evidence has {"unescaped_xss_payload": {"payload": "alert(1)", "response": "alert(1) in HTML"}}; proof_node created with proof_type="unescaped_xss_payload"
- Test 2: 3 proofs in evidence dict; 3 proof_nodes created, all connected to root_hypothesis
- Test 3: Edge from proof_node to root_hypothesis has weight=1.0

**Priority**: CRITICAL

**Dependencies**: REQ-EG-01

---

#### Requirement REQ-EG-04: Evidence Status Derivation

**User Story**: As an evidence graph, I want to determine finding status based on proof presence so that I enforce Evidence Policy.

**Acceptance Criteria**:

1. WHEN EvidenceGraph is built, evidence_status SHALL be computed as:
   - IF confirmed_proofs.length > 0: status = CONFIRMED
   - ELSE IF unconfirmed_signals.length > 0: status = OBSERVED
   - ELSE: status = NOT_TESTED
2. THE confidence_score SHALL be computed as: confirmed_proofs.length / (confirmed_proofs.length + unconfirmed_signals.length) IF denominator > 0
3. IF no proofs and no signals: confidence_score = 0.0
4. IF proofs and signals: confidence_score weighted by proof count (proofs carry 100% weight, signals carry 0%)

**Acceptance Tests**:

- Test 1: Build graph with 2 proofs, 0 signals; status = CONFIRMED, confidence = 1.0
- Test 2: Build graph with 0 proofs, 3 signals; status = OBSERVED, confidence = 0.0
- Test 3: Build graph with 1 proof, 2 signals; status = CONFIRMED, confidence = 1/3 = 0.33
- Test 4: Build graph with 0 proofs, 0 signals; status = NOT_TESTED, confidence = 0.0

**Priority**: CRITICAL

**Dependencies**: REQ-EG-01, REQ-EG-02, REQ-EG-03

---

#### Requirement REQ-EG-05: Evidence Graph Immutability and Audit Trail

**User Story**: As an evidence graph, I want to prevent modification after creation so that findings have immutable justifications.

**Acceptance Criteria**:

1. AFTER an Evidence Graph is created (EvidenceGraph.build() completes), THE graph SHALL be marked immutable
2. IF an attempt is made to modify an immutable graph (add_signal, add_proof, modify_node), THE operation SHALL return an error
3. INSTEAD of modifying existing graph, A new Evidence Graph SHALL be created for updated findings
4. THE graph SHALL include created_timestamp and last_updated_timestamp for audit trail
5. THE created_timestamp SHALL never change; last_updated_timestamp tracks when graph was last read/queried (not modified)

**Acceptance Tests**:

- Test 1: Build graph G1; add_signal() attempted; returns error "Graph is immutable"
- Test 2: Update finding with new proof; create new graph G2; G1 unchanged
- Test 3: G1.created_timestamp set at creation, never changes; G1.last_updated_timestamp updates when graph is queried
- Test 4: Immutable graph prevents accidental modification during concurrent access

**Priority**: MEDIUM

**Dependencies**: REQ-EG-01, REQ-EG-02, REQ-EG-03

---

#### Requirement REQ-EG-06: Evidence Graph Justification String

**User Story**: As a report generator, I want human-readable proof chains so that findings explain themselves.

**Acceptance Criteria**:

1. WHEN a finding is reported, A justification string SHALL be generated from the Evidence Graph
2. THE justification string SHALL include:
   - Status line: "Status: CONFIRMED" or "Status: OBSERVED"
   - Proof summary (if proofs exist): List all proof_nodes with proof_type and proof_data summary
   - Signal summary (if signals exist): List all signal_nodes with signal_type and signal_source
   - Discovery path: "Found by: Phase SCAN_DEEP_01 → Tool nuclei → Tool protocol_scanner"
   - Confidence: "Confidence: 85%"
3. THE justification string SHALL be human-readable, 100–500 characters typically

**Acceptance Tests**:

- Test 1: Graph with CONFIRMED status, 2 proofs, 0 signals; justification includes "Status: CONFIRMED", "Evidence: 2 proofs", list of proof types
- Test 2: Graph with OBSERVED status, 0 proofs, 3 signals; justification includes "Status: OBSERVED", "Signals: 3", list of signal sources
- Test 3: Justification for SSRF finding with metadata markers proof: "Status: CONFIRMED. Evidence: 1 proof. Proof: aws_metadata_retrieved (instance-id=i-1234). Confidence: 100%"

**Priority**: MEDIUM

**Dependencies**: REQ-EG-04

---

### Category 6: Standardized Output Schema

#### Requirement REQ-OS-01: Unified Tool Output Schema

**User Story**: As a report generator, I want all tools to return the same JSON structure so that I don't write 10 different parsers.

**Acceptance Criteria**:

1. ALL tool invocations SHALL return JSON conforming to StandardizedToolOutput schema
2. THE schema SHALL include top-level keys: execution, assessment, findings, negative_evidence, execution_ledger, limitations, next_action
3. execution: SHALL contain tool_id, execution_id (UUID), target, start_time, end_time, duration_seconds, status (completed|failed|timeout|interrupted), exit_code
4. assessment: SHALL contain target_type, detected_tech_stack, scan_depth, scope (in_scope, out_of_scope)
5. findings: SHALL be array of Finding objects
6. negative_evidence: SHALL quantify tests_performed, tests_with_no_findings, coverage_percentage
7. limitations: SHALL list reasons tests could not run (RATE_LIMITING, WAF_PROTECTION, AUTHENTICATION, TIMEOUT, etc.)

**Acceptance Tests**:

- Test 1: Execute nuclei through orchestrator; output validated against schema; all required fields present
- Test 2: Execute hydra; output includes execution (with start_time, end_time), assessment, findings array, negative_evidence
- Test 3: Tool timeout; output includes status="timeout", exit_code != 0, limitations field explains timeout
- Test 4: Tool succeeds with no findings; output includes findings=[], negative_evidence.tests_with_no_findings > 0

**Priority**: CRITICAL

**Dependencies**: REQ-TR-01, REQ-BE-01, REQ-EG-01

---

#### Requirement REQ-OS-02: Finding Object Schema

**User Story**: As a vulnerability analyst, I want standardized finding details so that I can analyze them programmatically.

**Acceptance Criteria**:

1. EACH Finding object SHALL contain:
   - finding_id (UUID), finding_type (string: SSRF, SSTI, IDOR, SQLi, XSS, etc.)
   - title (string), description (string)
   - severity (critical|high|medium|low|info)
   - evidence_status (NOT_TESTED|TESTED|OBSERVED|SUSPECTED|CONFIRMED|EXPLOITED)
   - confidence (0.0–1.0)
   - affected_endpoints: array of {url, parameter, method, attack_vector}
   - proof_of_concept: {url, request{method, headers, body}, response{status_code, body, proof_markers}}
   - remediation: {recommendation, effort, priority}
   - cve_references, cwe_references, owasp_references: arrays
   - limitations: array of strings
2. proof_of_concept.proof_markers SHALL contain exact strings from response proving vulnerability

**Acceptance Tests**:

- Test 1: XSS finding includes title="DOM-based XSS in search parameter", affected_endpoints=[{url: "/search", parameter: "q", method: "GET"}], proof_of_concept with unescaped payload in response
- Test 2: SQLi finding includes cwe_references=["CWE-89"], cve_references=["CVE-2023-1234"]
- Test 3: SSRF finding with proof_markers=["ami-12345", "instance-id=i-6789"]; if neither marker in response, proof_of_concept is empty
- Test 4: Finding with confidence=0.95, severity="high", evidence_status="CONFIRMED"

**Priority**: CRITICAL

**Dependencies**: REQ-OS-01, REQ-EG-01

---

#### Requirement REQ-OS-03: Proof of Concept Requirement

**User Story**: As a penetration tester, I want concrete PoCs so that I can reproduce findings manually.

**Acceptance Criteria**:

1. WHEN evidence_status = EXPLOITED, proof_of_concept SHALL be populated with concrete request-response pair
2. proof_of_concept.request SHALL include: exact URL, method (GET/POST/etc.), all headers, request body (if present)
3. proof_of_concept.response SHALL include: status_code, complete response_body
4. proof_of_concept.proof_markers SHALL list specific strings in response body that confirm vulnerability (e.g., error message, injected payload execution)
5. WHEN evidence_status = CONFIRMED but not EXPLOITED, proof_of_concept SHALL be populated with evidence URL/request, but response_body may be sanitized
6. WHEN evidence_status < CONFIRMED, proof_of_concept SHALL be empty/null

**Acceptance Tests**:

- Test 1: EXPLOITED XSS finding includes request with payload, response with alert(1) unescaped, proof_markers=["alert(1)"]
- Test 2: EXPLOITED SQLi finding includes SQL error in response, proof_markers=["MYSQL syntax error", "Query:", ...
- Test 3: CONFIRMED finding without PoC execution includes request URL but proof_markers empty
- Test 4: OBSERVED finding has proof_of_concept=null

**Priority**: HIGH

**Dependencies**: REQ-OS-02, REQ-EG-03

---

#### Requirement REQ-OS-04: Negative Evidence Quantification

**User Story**: As an analyst, I want to know what was tested but found no vulnerabilities so that I understand coverage.

**Acceptance Criteria**:

1. EVERY tool output SHALL include negative_evidence object
2. negative_evidence SHALL contain:
   - tests_performed: count of all tests executed
   - tests_with_no_findings: count of tests that returned no vulnerabilities
   - test_categories_checked: array of vulnerability types tested (SQLi, XSS, IDOR, SSRF, etc.)
   - rate_limited_tests: count of tests blocked by rate limiting
   - waf_blocked_tests: count of tests blocked by WAF
   - timeout_tests: count of tests that exceeded timeout
   - coverage_percentage: (tests_performed - blocked_tests) / total_planned * 100
3. IF tool execution failed completely: tests_performed=0, coverage_percentage=0
4. IF tool found no vulnerabilities: tests_performed > 0, tests_with_no_findings = tests_performed, coverage_percentage > 0

**Acceptance Tests**:

- Test 1: Nuclei runs 100 tests, finds 2 vulnerabilities; negative_evidence.tests_performed=100, tests_with_no_findings=98, coverage=100%
- Test 2: Hydra attempts 50 password tests, 10 blocked by rate limiting; tests_performed=50, rate_limited_tests=10, coverage_percentage=80%
- Test 3: Tool timeout after 5 seconds; tests_performed=5, timeout_tests=5, coverage_percentage varies based on plan
- Test 4: Tool execution fails before running tests; tests_performed=0, tests_with_no_findings=0, coverage_percentage=0

**Priority**: CRITICAL

**Dependencies**: REQ-OS-01

---

#### Requirement REQ-OS-05: Execution Ledger for Audit Trail

**User Story**: As a security auditor, I want a complete audit trail so that I can trace how findings were discovered.

**Acceptance Criteria**:

1. EVERY execution SHALL record an execution_ledger with timestamped entries
2. EACH ledger entry SHALL include: timestamp, action (tool_started|payload_sent|response_received|finding_discovered), phase_id, tool_id, details (dict), related_finding_id (optional)
3. THE ledger SHALL preserve execution order and timing of all events
4. WHEN a finding is discovered, a ledger entry SHALL record: finding_type, finding_id, which phase, which tool
5. THE ledger SHALL enable replay: given execution_id, one can reconstruct exact sequence of events

**Acceptance Tests**:

- Test 1: Execute SCAN phase; ledger includes entries: [tool_nuclei_started, payload_sent (nuclei), response_received, finding_discovered (id=uuid1)]
- Test 2: Ledger timestamps are ISO-8601, sortable, and reflect actual execution order
- Test 3: Ledger enables querying: "Find all findings discovered by nuclei" or "Show timeline for target http://x.com"
- Test 4: 1000 events logged; ledger < 1MB, querying by time range completes in < 10ms

**Priority**: MEDIUM

**Dependencies**: REQ-OS-01

---

#### Requirement REQ-OS-06: Limitations and Why-It-Matters

**User Story**: As an analyst, I want to understand why certain tests couldn't run so that I know the scan limitations.

**Acceptance Criteria**:

1. EVERY tool output SHALL include limitations array
2. EACH limitation SHALL have: category (RATE_LIMITING|WAF_PROTECTION|AUTHENTICATION|TIMEOUT|MISSING_PERMISSION|UNKNOWN), description, impact, recommendation
3. IF rate limiting blocked tests: "Could not test X SQLi payloads due to 429 Too Many Requests responses. Impact: SQLi detection confidence reduced. Recommendation: Retry with --rate-limit-delay=1000"
4. IF WAF detected: "Web Application Firewall detected (ModSecurity). Impact: Payload-based XSS detection may be blocked. Recommendation: Use WAF bypass techniques or manual testing"
5. IF authentication required but credentials missing: "Target requires authentication. Impact: Authenticated endpoints not tested. Recommendation: Provide credentials"
6. Limitations SHALL NOT suppress findings; they SHALL explain constraints on evidence collection

**Acceptance Tests**:

- Test 1: Nuclei detects WAF, logs limitation with category=WAF_PROTECTION, describes type (ModSecurity, CloudFlare, etc.), recommends bypass
- Test 2: Tool gets 429 response on 40/100 payloads, logs limitation: "40 requests rate-limited", coverage_percentage reflects this
- Test 3: Hydra requires SSH credentials, logs: "SSH authentication required but credentials not provided"
- Test 4: Finding still reported even if limitations present; limitations explain why confidence < 1.0

**Priority**: HIGH

**Dependencies**: REQ-OS-01, REQ-OS-04

---

#### Requirement REQ-OS-07: Next Action Guidance

**User Story**: As an orchestrator, I want automated suggestions for follow-up so that I know what to do next.

**Acceptance Criteria**:

1. EVERY tool output SHALL include next_action object with: type (MANUAL_TESTING|EXPLOIT_VERIFICATION|CREDENTIAL_ACQUISITION|RETRY_WITH_EVASION|COMPLETED), reason, suggested_tool (optional)
2. IF findings_count > 0 and evidence_status < EXPLOITED: next_action.type = EXPLOIT_VERIFICATION
3. IF findings_count = 0 and WAF_detected: next_action.type = RETRY_WITH_EVASION, suggested_tool = "ssrf_hunter" (if SSRF likely)
4. IF findings_count = 0 and auth_required: next_action.type = CREDENTIAL_ACQUISITION, reason = "Target requires authentication"
5. IF findings_count > 0 and evidence_status = EXPLOITED: next_action.type = COMPLETED

**Acceptance Tests**:

- Test 1: Nuclei finds SQLi with status=SUSPECTED; next_action.type=EXPLOIT_VERIFICATION, suggested_tool="sqlmap"
- Test 2: Hydra finds no weak credentials; next_action.type=CREDENTIAL_ACQUISITION, reason="No weak passwords found. Manual review recommended"
- Test 3: Scan complete with 3 CONFIRMED findings; next_action.type=COMPLETED
- Test 4: Scan blocked by WAF; next_action.type=RETRY_WITH_EVASION, suggested_tool="smart_fuzz_engine"

**Priority**: MEDIUM

**Dependencies**: REQ-OS-02

---

### Category 7: Evidence Policy Integration

#### Requirement REQ-POLICY-01: No Status Promotion Without Proof

**User Story**: As an evidence enforcer, I want to prevent findings from being claimed CONFIRMED without proof so that reports are accurate.

**Acceptance Criteria**:

1. WHEN a finding's status is determined, THE Orchestrator SHALL check evidence_graph.confirmed_proofs.length
2. IF confirmed_proofs.length = 0, THEN finding status SHALL NOT be CONFIRMED (max status = OBSERVED)
3. IF confirmed_proofs.length > 0, THEN finding status MAY be CONFIRMED
4. IF finding status would exceed evidence_graph.evidence_status, THE Orchestrator SHALL reduce it to evidence_graph.evidence_status
5. NO finding shall be reported as EXPLOITED unless proof_of_concept is populated with concrete request-response

**Acceptance Tests**:

- Test 1: Signal detected (confidence=0.9) but no proof; finding status capped at OBSERVED, not CONFIRMED
- Test 2: Proof node added (e.g., unescaped_xss_payload); finding status promoted from OBSERVED to CONFIRMED
- Test 3: Tool claims EXPLOITED but no PoC response; Orchestrator reduces to CONFIRMED if proof present, else OBSERVED
- Test 4: Multiple signals (high confidence) but no proofs; status = OBSERVED despite high confidence

**Priority**: CRITICAL

**Dependencies**: REQ-EG-01, REQ-EG-03, REQ-EG-04

---

#### Requirement REQ-POLICY-02: Baseline Required Before Payload Testing

**User Story**: As an evidence enforcer, I want baselines established before payload testing so that response comparisons are valid.

**Acceptance Criteria**:

1. WHEN Orchestrator.execute_plan() begins, THE baseline_establishment phase SHALL run first
2. NO tool that injects payloads (SQLi tester, XSS fuzzer, SSRF prober) SHALL execute until baseline_establishment completes
3. ALL responses from payload-injecting tools SHALL be compared against baselines using semantic_comparison()
4. IF baseline_establishment fails (e.g., timeout), THE entire scan SHALL be aborted; no payload testing proceeds

**Acceptance Tests**:

- Test 1: Execute DEEP_SCAN plan; baseline phase runs first, produces 3 baselines; SCAN phase begins after baseline complete
- Test 2: Attempt to manually execute SQLi testing phase before baseline; Orchestrator returns error "Baseline required before payload testing"
- Test 3: Baseline fails to establish (target timeout); execute_plan() aborts with error, scan phase not queued
- Test 4: All SCAN phase responses compared against baselines; false positives eliminated

**Priority**: CRITICAL

**Dependencies**: REQ-BE-01, REQ-ORCH-02, REQ-POLICY-01

---

#### Requirement REQ-POLICY-03: Evidence Status Consistency

**User Story**: As an evidence enforcer, I want to ensure finding status always matches proof presence so that findings are justified.

**Acceptance Criteria**:

1. WHEN a finding is reported, THE finding.evidence_status SHALL be checked against evidence_graph.confirmed_proofs.length
2. INVARIANT: (finding.evidence_status = CONFIRMED) ⟹ (evidence_graph.confirmed_proofs.length > 0)
3. INVARIANT: (finding.evidence_status = OBSERVED) ⟹ (evidence_graph.confirmed_proofs.length = 0 AND evidence_graph.unconfirmed_signals.length > 0)
4. IF invariant is violated, THE Orchestrator SHALL raise an error "Evidence status inconsistent with proof presence"
5. This check SHALL run before any finding is included in final report

**Acceptance Tests**:

- Test 1: Finding claims CONFIRMED with 0 proofs; validation fails, error raised
- Test 2: Finding claims OBSERVED with 0 proofs and 0 signals; validation fails (OBSERVED requires signals)
- Test 3: Finding claims OBSERVED with 3 signals and 0 proofs; validation passes
- Test 4: 100 findings validated; all pass consistency check

**Priority**: CRITICAL

**Dependencies**: REQ-EG-04, REQ-OS-02, REQ-POLICY-01

---

#### Requirement REQ-POLICY-04: No Evidence Regression

**User Story**: As an evidence enforcer, I want to prevent finding status from regressing so that proof maturity only increases.

**Acceptance Criteria**:

1. WHEN a finding's status is updated, THE new status SHALL be >= previous status
2. Allowed transitions: NOT_TESTED → TESTED → OBSERVED → SUSPECTED → CONFIRMED → EXPLOITED
3. Forbidden transitions: CONFIRMED → OBSERVED, EXPLOITED → CONFIRMED, etc.
4. IF a regression would occur, THE Orchestrator SHALL log a warning and keep the previous (higher) status

**Acceptance Tests**:

- Test 1: Finding status is CONFIRMED, new evidence suggests only OBSERVED; Orchestrator keeps CONFIRMED
- Test 2: Finding status is EXPLOITED, new test contradicts it; keep EXPLOITED (original proof still valid)
- Test 3: Finding status is OBSERVED, proof found; transition to CONFIRMED allowed
- Test 4: For 50 findings, all status transitions checked; no regressions allowed

**Priority**: HIGH

**Dependencies**: REQ-EG-04, REQ-POLICY-01

---

#### Requirement REQ-POLICY-05: Signal Validation Before Confirmation

**User Story**: As an evidence enforcer, I want signals to be correlated with proofs before promoting findings so that signals alone don't cause confirmation.

**Acceptance Criteria**:

1. WHEN a signal is added to evidence_graph, IT SHALL be added to unconfirmed_signals initially
2. A signal STAYS in unconfirmed_signals until a proof_node that correlates with it is found
3. Correlation is defined as: proof_node addresses the same vulnerability type as signal_node
4. WHEN proof_node is added, the Orchestrator SHALL scan unconfirmed_signals for correlates and move them to confirmed (implicitly, by virtue of having a proof)
5. A signal alone NEVER causes finding status to become CONFIRMED

**Acceptance Tests**:

- Test 1: Signal "response_time_spike" detected; added to unconfirmed_signals; finding remains OBSERVED even if signal.confidence=0.9
- Test 2: Signal for SSRF (e.g., unusual hostname pattern) detected; proof_node added (AWS metadata marker); signal correlated to proof
- Test 3: 10 signals, 1 proof; status = CONFIRMED (proof drives it), signals are context
- Test 4: Signals alone produce OBSERVED status; only proofs promote to CONFIRMED

**Priority**: HIGH

**Dependencies**: REQ-EG-02, REQ-EG-03, REQ-POLICY-01

---

### Category 8: Cross-Layer Integration and Constraints

#### Requirement REQ-INT-01: Tool Registry to Capability Engine Integration

**User Story**: As an orchestrator, I want capability queries to use Tool Registry data so that tool selection is dynamic.

**Acceptance Criteria**:

1. WHEN Capability_Engine.get_applicable_tools() is called, IT SHALL query Tool_Registry for all registered tools
2. EACH tool's capabilities, health_status, and technology_stack SHALL be retrieved from registry
3. IF a tool is re-registered with updated capabilities, capability_engine queries SHALL use new data
4. IF a tool's health_status changes, subsequent queries SHALL respect new status (OFFLINE tools excluded)

**Acceptance Tests**:

- Test 1: nuclei registered with SCAN capability, query returns nuclei; nuclei re-registered with SCAN + FINGERPRINT, query returns both
- Test 2: nmap health changes to OFFLINE; capability queries exclude nmap
- Test 3: 50 tools registered; querying specific capability retrieves only tools with that capability

**Priority**: HIGH

**Dependencies**: REQ-TR-01, REQ-TR-02, REQ-CE-02

---

#### Requirement REQ-INT-02: Capability Engine to Orchestrator Integration

**User Story**: As an orchestrator, I want capability queries to inform execution plan generation so that plans include relevant tools.

**Acceptance Criteria**:

1. WHEN Orchestrator.plan_scan() is called, IT SHALL invoke Capability_Engine.get_applicable_tools() for each phase objective
2. THE returned tools (ranked by relevance_score) SHALL populate ExecutionPhase.tools_to_execute
3. IF no tools are available for a phase objective, THE ExecutionPhase SHALL be skipped with reason "No applicable tools found"
4. THE dependency chain from capability resolution SHALL be reflected in ExecutionPhase.depends_on_phases

**Acceptance Tests**:

- Test 1: plan_scan(..., objective=SCAN_DEEP), Capability_Engine returns [nuclei, hydra, sqlmap] ranked; SCAN phase includes all three
- Test 2: plan_scan(..., objective=EXPLOIT_VERIFY), no tools available; EXPLOIT_VERIFY phase skipped with log message
- Test 3: Tool A requires output from Tool B; ExecutionPhase for A lists B's phase in depends_on_phases

**Priority**: HIGH

**Dependencies**: REQ-CE-02, REQ-ORCH-01

---

#### Requirement REQ-INT-03: Orchestrator to Baseline Engine Integration

**User Story**: As an orchestrator, I want baseline results to be available to all scanning phases so that all comparisons use the same baselines.

**Acceptance Criteria**:

1. WHEN Orchestrator.execute_plan() enters BASELINE_ESTABLISHMENT phase, THE BaselineSet output SHALL be stored in execution context
2. WHEN subsequent SCAN phases execute, THEY SHALL receive BaselineSet via ExecutionPhase.inputs_from_phases
3. EACH tool in SCAN phases SHALL have access to baselines for semantic_comparison()
4. IF baseline establishment fails, ALL downstream SCAN phases SHALL be skipped with error logged

**Acceptance Tests**:

- Test 1: BASELINE phase produces BaselineSet, stored in context with phase_id="BASELINE_EST_01"; SCAN phase receives it as input
- Test 2: Nuclei tool in SCAN phase receives baselines, compares all responses, marks false positives as "semantic_match=true"
- Test 3: BASELINE fails; SCAN phase skipped; execution result shows "SCAN phase skipped due to baseline failure"

**Priority**: CRITICAL

**Dependencies**: REQ-BE-01, REQ-ORCH-02, REQ-ORCH-03

---

#### Requirement REQ-INT-04: SCAN Phases to Evidence Graph Integration

**User Story**: As an orchestrator, I want tool findings to be recorded in evidence graphs so that justifications are preserved.

**Acceptance Criteria**:

1. WHEN a tool completes execution and produces findings, EACH finding SHALL be used to create an EvidenceGraph via EvidenceGraph.build()
2. THE evidence_graph_id SHALL be stored in StandardFinding.evidence_graph_id
3. EACH finding SHALL be enriched with orchestration metadata via StandardFinding.enrich_with_orchestration()
4. THE enriched finding SHALL include: evidence_graph_id, execution_ledger_id, negative_evidence, affected_endpoints, proof_of_concept

**Acceptance Tests**:

- Test 1: Nuclei finds SSRF, creates Finding; Orchestrator creates EvidenceGraph, links via evidence_graph_id
- Test 2: Finding enriched with evidence_graph_id, execution_ledger_id (phase + tool), negative_evidence (50 tested, 49 clean)
- Test 3: Report generated; finding includes justification derived from evidence_graph

**Priority**: HIGH

**Dependencies**: REQ-EG-01, REQ-OS-01, REQ-OS-02

---

#### Requirement REQ-INT-05: Resource Constraints and Concurrency Limits

**User Story**: As an orchestrator, I want to respect tool constraints so that I don't overload the system.

**Acceptance Criteria**:

1. EACH Tool in Tool_Registry SHALL define max_concurrent_instances (e.g., max 3 simultaneous Nuclei)
2. WHEN ExecutionPhase with parallel=true runs multiple instances of same tool, THE Orchestrator SHALL enforce max_concurrent_instances limit
3. WHEN ExecutionPhase limit is reached, SUBSEQUENT tool instances SHALL queue until earlier ones complete
4. THE Orchestrator SHALL not exceed global concurrent limit (e.g., max 8 simultaneous tools across all tools)

**Acceptance Tests**:

- Test 1: Nuclei has max_concurrent_instances=2, SCAN phase has 5 target URLs; Orchestrator queues: run 2, then 2 more, then 1 final
- Test 2: Global limit=8, SCAN phase has nuclei(3), hydra(3), sqlmap(3); orchestrator runs 8, queues 1
- Test 3: Tools complete; queued instances immediately start

**Priority**: MEDIUM

**Dependencies**: REQ-TR-04, REQ-ORCH-04

---

### Acceptance Criteria Summary

V2 is COMPLETE when ALL of the following are verified:

1. ✅ **Tool Registry**: 50+ tools can be registered, queried by capability/tech stack, health tracked
2. ✅ **Capability Engine**: Tools ranked by relevance (0.0–1.0) for any target; dependencies resolved
3. ✅ **Orchestrator**: DAG-ordered ExecutionPlans generated; baseline phase always before SCAN phases; all phases execute in correct order
4. ✅ **Baseline Engine**: 3 baselines established; responses compared via Jaccard similarity; threshold 0.75 works correctly
5. ✅ **Evidence Graph**: Proof chains constructed; status derived from proofs (CONFIRMED requires proof_nodes > 0)
6. ✅ **Standardized Output**: All tools return unified JSON schema; findings include PoC, affected_endpoints, remediation
7. ✅ **Evidence Policy**: No status promotion without proof; baseline mandatory; negative evidence quantified; status never regresses
8. ✅ **Integration**: All layers communicate correctly; tool findings linked to evidence graphs; execution ledger complete
9. ✅ **Correctness Properties** (automated tests):
   - No phase cycles (DAG validation)
   - Evidence status consistency (proofs ⟺ CONFIRMED)
   - Baseline before payload (phase ordering)
   - Semantic reflexivity (similarity(x, x) = 1.0)
   - Tool health check before execution (OFFLINE tools skip)
10. ✅ **Performance**: plan_scan() < 100ms, baseline < 5s, execute_plan() respects rate limits

---

## Testing Requirements

### Automated Test Coverage

- **Unit Tests**: ToolRegistry, CapabilityEngine, Orchestrator, BaselineEngine, EvidenceGraph, StandardizedOutput
- **Integration Tests**: Full end-to-end execution with mocked tools, multi-phase plans, cross-phase data flow
- **Property-Based Tests**: DAG acyclicity, evidence consistency, semantic reflexivity
- **Stress Tests**: 50+ tools, 8+ concurrent phases, 10MB response sizes

### Manual Acceptance Tests

- Penetration testers verify findings match manual verification
- Evidence graphs justify claims with proof chains
- Reports are actionable (findings explain how to reproduce)

---

## Performance and Resource Requirements

| Metric | Target |
|--------|--------|
| plan_scan() latency | < 100 ms |
| Baseline establishment | 3–5 seconds (3 requests) |
| Semantic comparison per response | < 50 ms (up to 10 MB) |
| Evidence graph construction per finding | < 50 ms |
| Max concurrent tools | 8 simultaneous |
| Max scan duration | 30 minutes (1800 seconds) |
| Max HTTP requests per scan | 5000 |
| Evidence graph memory | < 10 MB per finding |
| Execution ledger size | < 5 MB per scan |

---

## Dependency Tree

```
REQ-TR-01 (Tool Registration)
  ├─ REQ-TR-02 (Capabilities)
  │  ├─ REQ-CE-02 (Relevance Scoring)
  │  │  ├─ REQ-CE-01 (Tech Stack Detection)
  │  │  ├─ REQ-CE-04 (Health Filtering)
  │  │  │  └─ REQ-TR-03 (Health Tracking)
  │  │  └─ REQ-ORCH-01 (Plan Generation)
  │  │     ├─ REQ-ORCH-02 (Baseline Precedence)
  │  │     │  └─ REQ-BE-01 (Baseline Establishment)
  │  │     ├─ REQ-ORCH-03 (Phase Dependencies)
  │  │     └─ REQ-ORCH-06 (Health Check Before Execution)
  ├─ REQ-TR-04 (Parameters)
  └─ REQ-CE-03 (Dependency Resolution)

REQ-BE-01 (Baseline Establishment)
  ├─ REQ-BE-02 (Token Extraction)
  │  └─ REQ-BE-03 (Jaccard Similarity)
  │     └─ REQ-BE-04 (Threshold & Classification)
  │        └─ REQ-BE-05 (Reflexivity)

REQ-EG-01 (Hypothesis Node)
  ├─ REQ-EG-02 (Signal Nodes)
  ├─ REQ-EG-03 (Proof Nodes)
  └─ REQ-EG-04 (Status Derivation)
     ├─ REQ-EG-05 (Immutability)
     └─ REQ-EG-06 (Justification)

REQ-OS-01 (Unified Schema)
  ├─ REQ-OS-02 (Finding Schema)
  ├─ REQ-OS-03 (PoC Requirement)
  ├─ REQ-OS-04 (Negative Evidence)
  ├─ REQ-OS-05 (Execution Ledger)
  ├─ REQ-OS-06 (Limitations)
  └─ REQ-OS-07 (Next Action)

REQ-POLICY-01 (No Status Promotion)
  ├─ REQ-POLICY-02 (Baseline Required)
  ├─ REQ-POLICY-03 (Status Consistency)
  ├─ REQ-POLICY-04 (No Regression)
  └─ REQ-POLICY-05 (Signal Validation)

REQ-INT-01 through REQ-INT-05 (Cross-Layer Integration)
  └─ Depend on all layers above
```

---

## Glossary Summary

| Term | Definition |
|------|-----------|
| **Baseline** | "Normal" response from target; HOMEPAGE, NOT_FOUND_404, INVALID_PARAM |
| **Capability** | Security testing ability (e.g., SQLi detection); has type, tech_stack, max_evidence_level |
| **Confidence** | 0.0–1.0 score indicating evidence strength; 1.0 = proof present, 0.0 = no signals |
| **CONFIRMED** | Finding status when proof_nodes > 0 in evidence graph |
| **Execution Ledger** | Chronological record of all actions: tool_started, payload_sent, finding_discovered |
| **Evidence Graph** | DAG of hypothesis, signal, and proof nodes; enables proof chains |
| **Evidence Status** | OBSERVED / SUSPECTED / CONFIRMED / EXPLOITED (from V1 Evidence Policy) |
| **Finding** | Detected security issue; has type, status, confidence, evidence, PoC, remediation |
| **FindingStatus** | Enum: NOT_TESTED, TESTED, OBSERVED, SUSPECTED, CONFIRMED, EXPLOITED |
| **HealthStatus** | HEALTHY, DEGRADED, OFFLINE |
| **Negative Evidence** | Quantification of tests that found no vulnerabilities |
| **OBSERVED** | Finding status when signals present but no proofs |
| **Proof Node** | Direct evidence of vulnerability in evidence graph |
| **Relevance Score** | 0.0–1.0 ranking of how well a tool matches query |
| **Semantic Comparison** | Jaccard similarity of response tokens; >= 0.75 threshold = semantic match |
| **Signal Node** | Observable indicator (not conclusive) in evidence graph |
| **Standardized Output** | Unified JSON schema all tools return |
| **Tool** | Security scanner/exploit utility registered in Tool_Registry |
| **Tool Registry** | Centralized catalog of all tools with capabilities and health status |

---

**End of Requirements Document**
